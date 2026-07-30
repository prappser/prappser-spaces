package user

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

// maxDelegationTTLSec bounds how long a delegation JWS (see verifyDelegation)
// may be valid for, independent of its own exp claim - keeps a leaked or
// mis-issued delegation from staying usable indefinitely.
const maxDelegationTTLSec = 600

// delegationClaims are the claims of a delegation JWS: an existing device
// (Issuer) vouching for a new device joining the same account.
type delegationClaims struct {
	Issuer    string `json:"iss"` // signer device's public key
	JTI       string `json:"jti"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// jtiInfo/jtiStore mirrors challengeStore's shape (see user.go): a
// mutex-guarded map with an opportunistic prune-on-write sweep, sized here
// for delegation JTI replay protection instead of login challenges.
type jtiInfo struct {
	expiresAt time.Time
}

type jtiStore struct {
	mu   sync.Mutex
	data map[string]jtiInfo
}

func newJTIStore() *jtiStore {
	return &jtiStore{data: make(map[string]jtiInfo)}
}

// markUsed atomically checks-and-marks a jti as used under a single lock
// acquisition, returning false if it was already seen (replay). Mirrors
// challengeStore.consume's atomicity rationale: a separate check-then-store
// would let two concurrent replays of the same delegation both pass.
func (s *jtiStore) markUsed(jti string, expiresAt time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.data[jti]; exists {
		return false
	}
	s.data[jti] = jtiInfo{expiresAt: expiresAt}
	now := timeNowFunc()
	for key, entry := range s.data {
		if entry.expiresAt.Before(now) {
			delete(s.data, key)
		}
	}
	return true
}

// DeviceEndpoints exposes HTTP handlers for the device roster: registering a
// new device via delegation, listing an account's devices, and revoking one.
type DeviceEndpoints struct {
	userRepository UserRepository
	usedJTIs       *jtiStore
}

// NewDeviceEndpoints creates a new DeviceEndpoints.
func NewDeviceEndpoints(userRepository UserRepository) *DeviceEndpoints {
	return &DeviceEndpoints{userRepository: userRepository, usedJTIs: newJTIStore()}
}

// registerDeviceRequest is the request body for POST /users/devices.
type registerDeviceRequest struct {
	Delegation      string `json:"delegation"`
	DevicePublicKey string `json:"devicePublicKey"`
	DeviceName      string `json:"deviceName,omitempty"`
}

// registerDeviceResponse is the response body for POST /users/devices.
type registerDeviceResponse struct {
	UserPublicKey   string `json:"userPublicKey"`
	Username        string `json:"username"`
	Role            string `json:"role"`
	DevicePublicKey string `json:"devicePublicKey"`
	CreatedAt       int64  `json:"createdAt"`
}

// RegisterDevice handles POST /users/devices. It is UNauthenticated - the
// delegation JWS (signed by an existing, unrevoked device of the account) is
// the credential proving the new device belongs to the same account.
func (de *DeviceEndpoints) RegisterDevice(ctx *fasthttp.RequestCtx) {
	var req registerDeviceRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		log.Error().Err(err).Msg("[DEVICE] Failed to parse register device request body")
		ctx.Error("invalid request body", fasthttp.StatusBadRequest)
		return
	}

	if req.Delegation == "" || req.DevicePublicKey == "" {
		ctx.Error("delegation and devicePublicKey are required", fasthttp.StatusBadRequest)
		return
	}

	signerDevice, err := de.verifyDelegation(req.Delegation)
	if err != nil {
		log.Debug().Err(err).Msg("[DEVICE] Delegation verification failed")
		ctx.Error("invalid delegation", fasthttp.StatusUnauthorized)
		return
	}

	newDeviceKeyBytes, err := base64.StdEncoding.DecodeString(req.DevicePublicKey)
	if err != nil || len(newDeviceKeyBytes) != ed25519.PublicKeySize {
		ctx.Error("devicePublicKey must be 32 std-base64-encoded bytes", fasthttp.StatusBadRequest)
		return
	}

	existing, err := de.userRepository.GetDevice(req.DevicePublicKey)
	if err != nil {
		log.Error().Err(err).Msg("[DEVICE] Failed to look up device")
		ctx.Error("internal server error", fasthttp.StatusInternalServerError)
		return
	}

	statusCode := fasthttp.StatusCreated
	now := time.Now().Unix()
	createdAt := now

	if existing != nil {
		if existing.RevokedAt != nil {
			ctx.Error("device revoked", fasthttp.StatusConflict)
			return
		}
		if existing.UserPublicKey != signerDevice.UserPublicKey {
			ctx.Error("device public key already registered under a different account", fasthttp.StatusConflict)
			return
		}
		// Idempotent retry: same account, still live.
		statusCode = fasthttp.StatusOK
		createdAt = existing.CreatedAt
	}

	var deviceName *string
	if req.DeviceName != "" {
		deviceName = &req.DeviceName
	}
	if err := de.userRepository.EnsureDevice(req.DevicePublicKey, signerDevice.UserPublicKey, deviceName, now); err != nil {
		log.Error().Err(err).Msg("[DEVICE] Failed to ensure device")
		ctx.Error("internal server error", fasthttp.StatusInternalServerError)
		return
	}

	account, err := de.userRepository.GetUserByPublicKey(signerDevice.UserPublicKey)
	if err != nil || account == nil {
		log.Error().Err(err).Msg("[DEVICE] Failed to fetch account for registered device")
		ctx.Error("internal server error", fasthttp.StatusInternalServerError)
		return
	}

	log.Debug().Str("devicePublicKey", req.DevicePublicKey).Msg("[DEVICE] Device registered")
	ctx.SetStatusCode(statusCode)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(registerDeviceResponse{
		UserPublicKey:   account.PublicKey,
		Username:        account.Username,
		Role:            account.Role,
		DevicePublicKey: req.DevicePublicKey,
		CreatedAt:       createdAt,
	})
}

// verifyDelegation validates a delegation JWS and returns the signer's
// device row. Verify order: parse claims -> signer device exists and is
// unrevoked -> signature verifies against the signer's own key (requiring
// EdDSA) -> exp is in the future and the token's total lifetime is within
// maxDelegationTTLSec -> jti has not been replayed.
func (de *DeviceEndpoints) verifyDelegation(signedJWT string) (*Device, error) {
	token, _, err := jwt.NewParser().ParseUnverified(signedJWT, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse delegation: %w", err)
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid delegation claims format")
	}

	var claims delegationClaims
	if iss, ok := mapClaims["iss"].(string); ok {
		claims.Issuer = iss
	}
	if jti, ok := mapClaims["jti"].(string); ok {
		claims.JTI = jti
	}
	if iat, ok := mapClaims["iat"].(float64); ok {
		claims.IssuedAt = int64(iat)
	}
	if exp, ok := mapClaims["exp"].(float64); ok {
		claims.ExpiresAt = int64(exp)
	}

	if claims.Issuer == "" || claims.JTI == "" {
		return nil, fmt.Errorf("missing iss or jti claim")
	}

	signerDevice, err := de.userRepository.GetDevice(claims.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to look up signer device: %w", err)
	}
	if signerDevice == nil || signerDevice.RevokedAt != nil {
		return nil, fmt.Errorf("signer device not found or revoked")
	}

	signerKeyBytes, err := base64.StdEncoding.DecodeString(claims.Issuer)
	if err != nil || len(signerKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid signer public key")
	}
	signerPublicKey := ed25519.PublicKey(signerKeyBytes)

	verifiedToken, err := jwt.Parse(signedJWT, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return signerPublicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("delegation signature verification failed: %w", err)
	}
	if !verifiedToken.Valid {
		return nil, fmt.Errorf("delegation signature verification failed")
	}

	now := timeNowFunc()
	if claims.ExpiresAt == 0 || time.Unix(claims.ExpiresAt, 0).Before(now) {
		return nil, fmt.Errorf("delegation expired")
	}
	if claims.ExpiresAt-claims.IssuedAt > maxDelegationTTLSec {
		return nil, fmt.Errorf("delegation ttl exceeds maximum")
	}

	if !de.usedJTIs.markUsed(claims.JTI, time.Unix(claims.ExpiresAt, 0)) {
		return nil, fmt.Errorf("delegation already used")
	}

	return signerDevice, nil
}

// deviceResponse is one entry in the GET /users/devices response.
type deviceResponse struct {
	DevicePublicKey string  `json:"devicePublicKey"`
	DeviceName      *string `json:"deviceName,omitempty"`
	CreatedAt       int64   `json:"createdAt"`
	LastSeenAt      *int64  `json:"lastSeenAt,omitempty"`
	IsCurrent       bool    `json:"isCurrent"`
}

// ListDevices handles GET /users/devices. Requires auth; returns the
// authenticated account's non-revoked devices.
func (de *DeviceEndpoints) ListDevices(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("[DEVICE] Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	devices, err := de.userRepository.ListDevices(authenticatedUser.PublicKey)
	if err != nil {
		log.Error().Err(err).Msg("[DEVICE] Failed to list devices")
		ctx.Error("internal server error", fasthttp.StatusInternalServerError)
		return
	}

	resp := make([]deviceResponse, 0, len(devices))
	for _, d := range devices {
		resp = append(resp, deviceResponse{
			DevicePublicKey: d.DevicePublicKey,
			DeviceName:      d.DeviceName,
			CreatedAt:       d.CreatedAt,
			LastSeenAt:      d.LastSeenAt,
			IsCurrent:       d.DevicePublicKey == authenticatedUser.DevicePublicKey,
		})
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(resp)
}

// RevokeDevice handles DELETE /users/devices?devicePublicKey=.... Requires
// auth; the ownership guard mirrors push_endpoints.go's DeleteSubscription.
func (de *DeviceEndpoints) RevokeDevice(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("[DEVICE] Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	targetDevicePublicKey := string(ctx.QueryArgs().Peek("devicePublicKey"))
	if targetDevicePublicKey == "" {
		ctx.Error("devicePublicKey is required", fasthttp.StatusBadRequest)
		return
	}

	if targetDevicePublicKey == authenticatedUser.DevicePublicKey {
		log.Debug().Msg("[DEVICE] Rejected self-revocation attempt")
		ctx.Error("cannot revoke the device currently in use", fasthttp.StatusForbidden)
		return
	}

	target, err := de.userRepository.GetDevice(targetDevicePublicKey)
	if err != nil {
		log.Error().Err(err).Msg("[DEVICE] Failed to look up device for revocation")
		ctx.Error("internal server error", fasthttp.StatusInternalServerError)
		return
	}
	if target == nil || target.UserPublicKey != authenticatedUser.PublicKey {
		ctx.Error("device not found", fasthttp.StatusNotFound)
		return
	}

	if err := de.userRepository.RevokeDevice(targetDevicePublicKey, time.Now().Unix()); err != nil {
		log.Error().Err(err).Msg("[DEVICE] Failed to revoke device")
		ctx.Error("internal server error", fasthttp.StatusInternalServerError)
		return
	}

	log.Debug().Str("devicePublicKey", targetDevicePublicKey).Msg("[DEVICE] Device revoked")
	ctx.SetStatusCode(fasthttp.StatusNoContent)
}
