package user

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

// maxDeviceNameRunes caps a device's display name - long enough for any
// realistic device label, short enough to keep it out of abuse territory.
const maxDeviceNameRunes = 64

// NormalizeDeviceName trims a user-supplied device name and validates its
// shape. It is the single shared validator for every write path that stores
// a device name (RegisterDevice, RenameDevice, OwnerRegister, invitation
// Join) so "empty" and "too long" mean the same thing everywhere. ok is
// false for an empty (post-trim) or over-length name; callers on lenient
// paths (Join, OwnerRegister) treat that as "no name" rather than an error,
// while RegisterDevice and RenameDevice reject it with 400.
func NormalizeDeviceName(raw string) (name string, ok bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || len([]rune(trimmed)) > maxDeviceNameRunes {
		return "", false
	}
	return trimmed, true
}

// maxDelegationTTLSec bounds how long a delegation JWS (see verifyDelegation)
// may be valid for, independent of its own exp claim - keeps a leaked or
// mis-issued delegation from staying usable indefinitely.
const maxDelegationTTLSec = 600

// delegationClaims are the claims of a delegation JWS: an existing device
// (Issuer) vouching for a new device joining the same account. Audience (aud)
// is required (grill F4): it binds the delegation to the specific space, so
// a delegation minted for one space cannot be replayed against another.
// DevicePublicKey (dpk) is OPTIONAL: the QR/paste device-link flow mints its
// delegation in generateLink BEFORE the scanning device has generated a
// keypair, so the enrolling device's public key isn't known yet at mint
// time. When dpk IS present (e.g. escrow-restore delegations, minted after
// the enrolling device's key is known), it must match the enrolling device
// exactly - see verifyDelegation.
type delegationClaims struct {
	Issuer          string `json:"iss"` // signer device's public key
	JTI             string `json:"jti"`
	IssuedAt        int64  `json:"iat"`
	ExpiresAt       int64  `json:"exp"`
	DevicePublicKey string `json:"dpk"` // the enrolling device's public key
	Audience        string `json:"aud"` // the target space's public key
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
// new device via delegation or password credentials, listing an account's
// devices, and revoking one.
type DeviceEndpoints struct {
	userRepository UserRepository
	usedJTIs       *jtiStore
	// verifierKey is the HKDF-derived key used to verify password
	// credentials on the password enrollment path (see resolveEnrollCredential
	// and password.go's verifyAuthSecret). Shared with PasswordEndpoints,
	// both derived once from the space keypair in main.go.
	verifierKey []byte
	// spacePublicKey is this space's own base64-encoded Ed25519 public key -
	// a delegation JWS's aud claim must equal it (see delegationClaims).
	spacePublicKey string
}

// NewDeviceEndpoints creates a new DeviceEndpoints. spacePublicKey is this
// space's own base64-encoded Ed25519 public key (see main.go's
// spacePublicKeyString), used to validate delegation JWS aud claims.
func NewDeviceEndpoints(userRepository UserRepository, verifierKey []byte, spacePublicKey string) *DeviceEndpoints {
	return &DeviceEndpoints{userRepository: userRepository, usedJTIs: newJTIStore(), verifierKey: verifierKey, spacePublicKey: spacePublicKey}
}

// registerDeviceRequest is the request body for POST /users/devices.
// Exactly one credential kind must be present: Delegation, or
// Username+AuthSecret (see resolveEnrollCredential).
type registerDeviceRequest struct {
	Delegation      string `json:"delegation,omitempty"`
	Username        string `json:"username,omitempty"`
	AuthSecret      string `json:"authSecret,omitempty"`
	DevicePublicKey string `json:"devicePublicKey"`
	DeviceName      string `json:"deviceName,omitempty"`
}

// registerDeviceResponse is the response body for POST /users/devices.
// AccountKeyBlob and UserState are only ever populated on the password
// enrollment path (see RegisterDevice) - the delegation path's response is
// byte-identical to before escrow existed, since a delegating device already
// has the account key locally and re-sending escrow over it would be a
// pointless extra exposure of the blobs.
type registerDeviceResponse struct {
	UserPublicKey   string `json:"userPublicKey"`
	Username        string `json:"username"`
	Role            string `json:"role"`
	DevicePublicKey string `json:"devicePublicKey"`
	CreatedAt       int64  `json:"createdAt"`
	AccountKeyBlob  string `json:"accountKeyBlob,omitempty"`
	UserState       string `json:"userState,omitempty"`
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

	if req.DevicePublicKey == "" {
		ctx.Error("devicePublicKey is required", fasthttp.StatusBadRequest)
		return
	}

	accountPublicKey, viaPassword, statusCode, err := de.resolveEnrollCredential(&req)
	if err != nil {
		ctx.Error(err.Error(), statusCode)
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

	responseStatusCode := fasthttp.StatusCreated
	now := time.Now().Unix()
	createdAt := now

	if existing != nil {
		if existing.RevokedAt != nil {
			ctx.Error("device revoked", fasthttp.StatusConflict)
			return
		}
		if existing.UserPublicKey != accountPublicKey {
			ctx.Error("device public key already registered under a different account", fasthttp.StatusConflict)
			return
		}
		// Idempotent retry: same account, still live.
		responseStatusCode = fasthttp.StatusOK
		createdAt = existing.CreatedAt
	}

	var deviceName *string
	if req.DeviceName != "" {
		normalized, ok := NormalizeDeviceName(req.DeviceName)
		if !ok {
			ctx.Error("deviceName is invalid", fasthttp.StatusBadRequest)
			return
		}
		deviceName = &normalized
	}
	if err := de.userRepository.EnsureDevice(req.DevicePublicKey, accountPublicKey, deviceName, now); err != nil {
		log.Error().Err(err).Msg("[DEVICE] Failed to ensure device")
		ctx.Error("internal server error", fasthttp.StatusInternalServerError)
		return
	}

	account, err := de.userRepository.GetUserByPublicKey(accountPublicKey)
	if err != nil || account == nil {
		log.Error().Err(err).Msg("[DEVICE] Failed to fetch account for registered device")
		ctx.Error("internal server error", fasthttp.StatusInternalServerError)
		return
	}

	resp := registerDeviceResponse{
		UserPublicKey:   account.PublicKey,
		Username:        account.Username,
		Role:            account.Role,
		DevicePublicKey: req.DevicePublicKey,
		CreatedAt:       createdAt,
	}

	// Escrow is only ever returned on the password path (see
	// registerDeviceResponse's doc comment).
	if viaPassword {
		accountKeyBlob, userState, escrowErr := de.userRepository.GetEscrow(accountPublicKey)
		if escrowErr != nil {
			log.Error().Err(escrowErr).Msg("[DEVICE] Failed to get escrow")
			ctx.Error("internal server error", fasthttp.StatusInternalServerError)
			return
		}
		resp.AccountKeyBlob = accountKeyBlob
		resp.UserState = userState
	}

	log.Debug().Str("devicePublicKey", req.DevicePublicKey).Msg("[DEVICE] Device registered")
	ctx.SetStatusCode(responseStatusCode)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(resp)
}

// resolveEnrollCredential resolves the account public key a device
// registration should attach to, from exactly one of two credential kinds:
// a delegation JWS (an existing device vouching for the new one), or a
// username+authSecret password credential. viaPassword is true only for
// the username+authSecret branch (see registerDeviceResponse's doc
// comment for why RegisterDevice cares). statusCode and err.Error() are
// only meaningful when err is non-nil, and are exactly what RegisterDevice
// should respond with.
func (de *DeviceEndpoints) resolveEnrollCredential(req *registerDeviceRequest) (accountPublicKey string, viaPassword bool, statusCode int, err error) {
	delegationPresent := req.Delegation != ""
	usernamePresent := req.Username != ""
	authSecretPresent := req.AuthSecret != ""
	passwordPresent := usernamePresent || authSecretPresent

	if delegationPresent && passwordPresent {
		return "", false, fasthttp.StatusBadRequest, fmt.Errorf("provide either delegation or username+authSecret, not both")
	}
	if !delegationPresent && !passwordPresent {
		return "", false, fasthttp.StatusBadRequest, fmt.Errorf("delegation or username+authSecret is required")
	}
	if passwordPresent && (!usernamePresent || !authSecretPresent) {
		return "", false, fasthttp.StatusBadRequest, fmt.Errorf("username and authSecret are both required")
	}

	if delegationPresent {
		signerDevice, verifyErr := de.verifyDelegation(req.Delegation, req.DevicePublicKey)
		if verifyErr != nil {
			log.Debug().Err(verifyErr).Msg("[DEVICE] Delegation verification failed")
			return "", false, fasthttp.StatusUnauthorized, fmt.Errorf("invalid delegation")
		}
		return signerDevice.UserPublicKey, false, 0, nil
	}

	username, normErr := NormalizeUsername(req.Username)
	if normErr != nil {
		return "", false, fasthttp.StatusBadRequest, fmt.Errorf("username is invalid")
	}

	userPublicKey, verifier, lookupErr := de.userRepository.GetPasswordCredential(username)
	if lookupErr != nil {
		log.Error().Err(lookupErr).Msg("[DEVICE] Failed to look up password credential")
		return "", false, fasthttp.StatusInternalServerError, fmt.Errorf("internal server error")
	}
	// Miss, empty verifier, or mismatch all collapse to the same generic
	// error - the body must be byte-identical for an unknown username and
	// a wrong password (see password_endpoints.go's GetSalt for the same
	// anti-enumeration rationale).
	if userPublicKey == "" || verifier == "" || !verifyAuthSecret(de.verifierKey, verifier, req.AuthSecret) {
		log.Debug().Msg("[DEVICE] Password credential check failed")
		return "", false, fasthttp.StatusUnauthorized, fmt.Errorf("invalid credentials")
	}

	return userPublicKey, true, 0, nil
}

// verifyDelegation validates a delegation JWS and returns the signer's
// device row. devicePublicKey is the enrolling device's public key from the
// enclosing registerDeviceRequest - IF the delegation carries a dpk claim, it
// must match devicePublicKey exactly; a delegation with no dpk claim skips
// that check (see delegationClaims for why dpk is optional). aud is always
// required and must match this space. Verify order: parse claims -> signer
// device exists and is unrevoked -> signature verifies against the signer's
// own key (requiring EdDSA) -> dpk (if present) matches the enrolling device
// and aud matches this space -> exp is in the future and the token's total
// lifetime is within maxDelegationTTLSec -> jti has not been replayed.
func (de *DeviceEndpoints) verifyDelegation(signedJWT string, devicePublicKey string) (*Device, error) {
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
	if dpk, ok := mapClaims["dpk"].(string); ok {
		claims.DevicePublicKey = dpk
	}
	if aud, ok := mapClaims["aud"].(string); ok {
		claims.Audience = aud
	}

	if claims.Issuer == "" || claims.JTI == "" || claims.Audience == "" {
		return nil, fmt.Errorf("missing iss, jti, or aud claim")
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

	// dpk is optional (see delegationClaims) - only checked when present.
	if claims.DevicePublicKey != "" && claims.DevicePublicKey != devicePublicKey {
		return nil, fmt.Errorf("delegation dpk does not match enrolling device")
	}
	if claims.Audience != de.spacePublicKey {
		return nil, fmt.Errorf("delegation aud does not match this space")
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

// renameDeviceRequest is the request body for PATCH /users/devices.
type renameDeviceRequest struct {
	DevicePublicKey string `json:"devicePublicKey"`
	DeviceName      string `json:"deviceName"`
}

// RenameDevice handles PATCH /users/devices. Requires auth; the ownership
// guard mirrors RevokeDevice's, except renaming the CURRENT device is
// allowed (unlike revoke, which refuses to cut off the device in use).
func (de *DeviceEndpoints) RenameDevice(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("[DEVICE] Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	var req renameDeviceRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		log.Error().Err(err).Msg("[DEVICE] Failed to parse rename device request body")
		ctx.Error("invalid request body", fasthttp.StatusBadRequest)
		return
	}

	if req.DevicePublicKey == "" {
		ctx.Error("devicePublicKey is required", fasthttp.StatusBadRequest)
		return
	}
	deviceName, ok := NormalizeDeviceName(req.DeviceName)
	if !ok {
		ctx.Error("deviceName is invalid", fasthttp.StatusBadRequest)
		return
	}

	target, err := de.userRepository.GetDevice(req.DevicePublicKey)
	if err != nil {
		log.Error().Err(err).Msg("[DEVICE] Failed to look up device for rename")
		ctx.Error("internal server error", fasthttp.StatusInternalServerError)
		return
	}
	if target == nil || target.RevokedAt != nil || target.UserPublicKey != authenticatedUser.PublicKey {
		ctx.Error("device not found", fasthttp.StatusNotFound)
		return
	}

	if err := de.userRepository.RenameDevice(req.DevicePublicKey, deviceName); err != nil {
		log.Error().Err(err).Msg("[DEVICE] Failed to rename device")
		ctx.Error("internal server error", fasthttp.StatusInternalServerError)
		return
	}

	log.Debug().Str("devicePublicKey", req.DevicePublicKey).Msg("[DEVICE] Device renamed")
	ctx.SetStatusCode(fasthttp.StatusNoContent)
}
