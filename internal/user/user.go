package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prappser/prappser-spaces/internal/user/owner"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

const (
	headerAuthorization = "Authorization"
	headerBearer        = "Bearer"

	RoleOwner = "owner"
	RoleUser  = "user"
	RoleGuest = "guest"
)

type User struct {
	PublicKey       string  `json:"publicKey"`
	Username        string  `json:"username"`
	Role            string  `json:"role"`
	SpaceID         string  `json:"spaceId,omitempty"`
	CreatedAt       int64   `json:"createdAt"`
	AvatarStorageID *string `json:"avatarStorageId,omitempty"`
	// DevicePublicKey identifies which of the account's devices authenticated
	// the current request. Populated by UserService.ValidateJWT from the JWT's
	// devicePublicKey claim (or the account key for legacy tokens - device #1's
	// key equals the account key). Not part of the wire representation: it is
	// request-scoped identity, not account data.
	DevicePublicKey string `json:"-"`
}

// Device is one entry in a user's device roster (see device_repository.go).
// A user has one row per device that has ever authenticated; RevokedAt marks
// a device as no longer usable without deleting its history.
type Device struct {
	DevicePublicKey string  `json:"devicePublicKey"`
	UserPublicKey   string  `json:"userPublicKey"`
	DeviceName      *string `json:"deviceName,omitempty"`
	CreatedAt       int64   `json:"createdAt"`
	LastSeenAt      *int64  `json:"lastSeenAt,omitempty"`
	RevokedAt       *int64  `json:"revokedAt,omitempty"`
}

type UserRepository interface {
	CreateUser(user *User) error
	GetUserByPublicKey(publicKey string) (*User, error)
	GetUserByUsername(username string) (*User, error)
	UpdateUserRole(publicKey string, role string) error
	UpdateAvatarStorageID(publicKey string, avatarStorageID *string) error
	UpdateUsername(publicKey, username string) error
	// EnsureDevice registers a device for an account if it doesn't already exist (no-op otherwise).
	EnsureDevice(devicePublicKey, userPublicKey string, deviceName *string, createdAt int64) error
	// GetDevice returns nil, nil when no device with that key exists.
	GetDevice(devicePublicKey string) (*Device, error)
	// ListDevices returns the non-revoked devices for an account.
	ListDevices(userPublicKey string) ([]*Device, error)
	// RevokeDevice soft-revokes a device and deletes its push subscriptions.
	RevokeDevice(devicePublicKey string, ts int64) error
	TouchDeviceLastSeen(devicePublicKey string, ts int64) error
}

// SpaceCreator creates a default space for new owners.
type SpaceCreator interface {
	CreateSpace(name string, userPublicKey *string) error
}

type UserEndpoints struct {
	userRepository UserRepository
	config         Config
	privateKey     ed25519.PrivateKey
	publicKey      ed25519.PublicKey
	userService    *UserService
	spaceCreator   SpaceCreator
	// challenges holds the pending-login challenge storage for verification.
	// UserEndpoints methods use value receivers, so this must be a pointer
	// field - a plain sync.Mutex field would be copied per call and its lock
	// would never actually protect the shared map.
	challenges *challengeStore
}

type Config struct {
	MasterPassword          string
	RegistrationTokenTTLSec int32
	JWTExpirationHours      int
	ChallengeTTLSec         int
}

// JWS claims for user authentication
type userAuthJWSClaims struct {
	PublicKey string `json:"publicKey"` // User's public key (unique identifier)
	Challenge string `json:"challenge"` // Prevents replay attacks
	IssuedAt  int64  `json:"iat"`       // For TTL validation
}

type JWTClaims struct {
	UserPublicKey string `json:"userPublicKey"`
	// DevicePublicKey is the device that authenticated, distinct from
	// UserPublicKey (the account). Empty on tokens minted before the device
	// roster existed - ValidateJWT falls back to UserPublicKey for those.
	DevicePublicKey string `json:"devicePublicKey"`
	Username        string `json:"username"`
	Role            string `json:"role"`
	SpaceID         string `json:"spaceId"`
	jwt.RegisteredClaims
}

type ChallengeResponse struct {
	Challenge      string `json:"challenge"`
	ExpiresAt      int64  `json:"expiresAt"`
	SpacePublicKey string `json:"spacePublicKey"`
}

type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"`
}

type challengeInfo struct {
	challenge string
	expiresAt time.Time
}

// challengeStore is a mutex-guarded map of in-flight login challenges, keyed
// by user public key. It must always be held behind a pointer (see the
// comment on UserEndpoints.challenges).
type challengeStore struct {
	mu   sync.Mutex
	data map[string]challengeInfo
}

func newChallengeStore() *challengeStore {
	return &challengeStore{data: make(map[string]challengeInfo)}
}

func (s *challengeStore) store(publicKey string, info challengeInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[publicKey] = info
	// ponytail: opportunistic O(n) sweep on every store keeps the map from
	// growing unbounded without a background goroutine; fine at this scale,
	// switch to a ticking janitor if the challenge volume ever makes this sweep matter.
	now := timeNowFunc()
	for key, entry := range s.data {
		if entry.expiresAt.Before(now) {
			delete(s.data, key)
		}
	}
}

func (s *challengeStore) get(publicKey string) (challengeInfo, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.data[publicKey]
	return info, ok
}

func (s *challengeStore) delete(publicKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, publicKey)
}

// consume atomically retrieves and removes a challenge under a single lock
// acquisition, so a challenge can be redeemed exactly once even if two
// requests race to verify the same signed JWS concurrently - a separate
// get() then delete() (two lock acquisitions) would let both see the
// challenge as present and both succeed. exists reports whether a challenge
// was found at all; expired reports whether it had already passed its TTL
// (only meaningful when exists is true). Either way the entry is gone after
// this call.
func (s *challengeStore) consume(publicKey string) (info challengeInfo, exists bool, expired bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, exists = s.data[publicKey]
	if !exists {
		return challengeInfo{}, false, false
	}
	delete(s.data, publicKey)
	return info, true, info.expiresAt.Before(timeNowFunc())
}

var timeNowFunc = time.Now

func NewEndpoints(userRepository UserRepository, config Config, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey, userService *UserService, spaceCreator SpaceCreator) *UserEndpoints {
	return &UserEndpoints{
		userRepository: userRepository,
		config:         config,
		privateKey:     privateKey,
		publicKey:      publicKey,
		userService:    userService,
		spaceCreator:   spaceCreator,
		challenges:     newChallengeStore(),
	}
}

// OwnerRegister handles owner registration with JWE/JWS (existing flow)
func (ue UserEndpoints) OwnerRegister(ctx *fasthttp.RequestCtx) {
	authHeader := ctx.Request.Header.Peek(headerAuthorization)
	if authHeader == nil {
		log.Error().Msg("Missing authorization header")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	jwe, err := owner.ExtractJWEFromAuthorizationHeader(string(authHeader))
	if err != nil {
		log.Error().Err(err).Msg("Invalid authorization header")
		ctx.Error("Invalid authorization header", fasthttp.StatusBadRequest)
		return
	}

	registerJWEClaims, err := owner.DecryptJWE(jwe, ue.config.MasterPassword)
	if err != nil {
		log.Error().Err(err).Msg("Failed to decrypt JWE")
		ctx.Error("Failed to decrypt JWE", fasthttp.StatusUnauthorized)
		return
	}

	registerJWSClaims, err := owner.VerifyJWS(registerJWEClaims.JWS, ue.config.RegistrationTokenTTLSec)
	if err != nil {
		log.Error().Err(err).Msg("Failed to verify JWS")
		ctx.Error("Failed to verify JWS", fasthttp.StatusUnauthorized)
		return
	}

	// Validate that public key is not empty
	if registerJWSClaims.PublicKey == "" {
		log.Error().Msg("Public key is empty")
		ctx.Error("Public key cannot be empty", fasthttp.StatusBadRequest)
		return
	}

	// Check if user already exists
	existingUser, err := ue.userRepository.GetUserByPublicKey(registerJWSClaims.PublicKey)
	if err == nil && existingUser != nil {
		// If user exists but is not an owner, upgrade them to owner
		if existingUser.Role != RoleOwner {
			log.Debug().
				Str("publicKey", existingUser.PublicKey).
				Str("oldRole", existingUser.Role).
				Msg("Upgrading user to owner role")

			err := ue.userRepository.UpdateUserRole(existingUser.PublicKey, RoleOwner)
			if err != nil {
				log.Error().Err(err).Msg("Failed to upgrade user to owner")
				ctx.Error("Failed to upgrade user to owner", fasthttp.StatusInternalServerError)
				return
			}

			// Backfill device #1 for accounts created before the device roster
			// existed (ON CONFLICT DO NOTHING makes this a no-op otherwise).
			if err := ue.userRepository.EnsureDevice(existingUser.PublicKey, existingUser.PublicKey, nil, time.Now().Unix()); err != nil {
				log.Error().Err(err).Msg("Failed to ensure device for upgraded owner")
				ctx.Error("Failed to upgrade user to owner", fasthttp.StatusInternalServerError)
				return
			}

			// Auto-create default space for newly upgraded owner
			if ue.spaceCreator != nil {
				if err := ue.spaceCreator.CreateSpace(existingUser.Username+"'s space", &existingUser.PublicKey); err != nil {
					log.Error().Err(err).Msg("Failed to create default space for upgraded owner")
					// Non-fatal: owner is upgraded, space can be created later
				} else {
					log.Info().Str("publicKey", existingUser.PublicKey[:min(50, len(existingUser.PublicKey))]+"...").Msg("Default space created for upgraded owner")
				}
			}
		}

		ctx.SetStatusCode(fasthttp.StatusCreated)
		ctx.SetContentType("application/json")
		response := map[string]string{"message": "Owner registered successfully", "publicKey": existingUser.PublicKey}
		json.NewEncoder(ctx).Encode(response)
		return
	}

	newUser := &User{
		PublicKey: registerJWSClaims.PublicKey,
		Username:  registerJWSClaims.Username,
		Role:      RoleOwner,
		CreatedAt: time.Now().Unix(),
	}

	err = ue.userRepository.CreateUser(newUser)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create owner")
		ctx.Error("Failed to create owner", fasthttp.StatusInternalServerError)
		return
	}

	// Device #1 for a brand-new owner: this owner's account key IS device #1's key.
	if err := ue.userRepository.EnsureDevice(newUser.PublicKey, newUser.PublicKey, nil, newUser.CreatedAt); err != nil {
		log.Error().Err(err).Msg("Failed to ensure device for new owner")
		ctx.Error("Failed to create owner", fasthttp.StatusInternalServerError)
		return
	}

	// Auto-create default space for new owner
	if ue.spaceCreator != nil {
		if err := ue.spaceCreator.CreateSpace(newUser.Username+"'s space", &newUser.PublicKey); err != nil {
			log.Error().Err(err).Msg("Failed to create default space for new owner")
			// Non-fatal: owner is created, space can be created later
		} else {
			log.Info().Str("publicKey", newUser.PublicKey[:min(50, len(newUser.PublicKey))]+"...").Msg("Default space created for new owner")
		}
	}

	ctx.SetStatusCode(fasthttp.StatusCreated)
	ctx.SetContentType("application/json")
	response := map[string]string{"message": "Owner registered successfully", "publicKey": registerJWSClaims.PublicKey}
	json.NewEncoder(ctx).Encode(response)
}

// GetChallenge generates a challenge for user login
func (ue UserEndpoints) GetChallenge(ctx *fasthttp.RequestCtx) {
	publicKey := ctx.QueryArgs().Peek("publicKey")
	if publicKey == nil {
		log.Error().Msg("[CHALLENGE] Missing publicKey parameter")
		ctx.Error("Missing publicKey parameter", fasthttp.StatusBadRequest)
		return
	}

	publicKeyStr := string(publicKey)
	log.Debug().Str("publicKey", publicKeyStr).Int("publicKeyLen", len(publicKeyStr)).Msg("[CHALLENGE] Challenge requested for device (full key)")

	// publicKey identifies a DEVICE key (see device_repository.go), not
	// necessarily the account key - pre-device-roster clients pass the
	// account key directly, which still resolves because device #1's key
	// equals the account key (backfilled by migration 000018).
	device, err := ue.userRepository.GetDevice(publicKeyStr)
	if err != nil {
		log.Error().Err(err).Str("publicKey", publicKeyStr[:min(50, len(publicKeyStr))]+"...").Msg("[CHALLENGE] Failed to get device")
		ctx.Error("Internal server error", fasthttp.StatusInternalServerError)
		return
	}
	if device == nil || device.RevokedAt != nil {
		log.Debug().Str("publicKey", publicKeyStr[:min(50, len(publicKeyStr))]+"...").Msg("[CHALLENGE] Device not found or revoked")
		ctx.Error("Device not found", fasthttp.StatusNotFound)
		return
	}

	// Generate random challenge
	challenge, err := generateChallenge()
	if err != nil {
		log.Error().Err(err).Msg("[CHALLENGE] Failed to generate challenge")
		ctx.Error("Internal server error", fasthttp.StatusInternalServerError)
		return
	}

	expiresAt := time.Now().Add(time.Duration(ue.config.ChallengeTTLSec) * time.Second)

	ue.challenges.store(publicKeyStr, challengeInfo{
		challenge: challenge,
		expiresAt: expiresAt,
	})

	log.Debug().Str("publicKey", publicKeyStr[:min(50, len(publicKeyStr))]+"...").Time("expiresAt", expiresAt).Msg("[CHALLENGE] Challenge generated and stored")

	// Convert space's Ed25519 public key to base64
	spacePublicKeyString := base64.StdEncoding.EncodeToString(ue.publicKey)

	response := ChallengeResponse{
		Challenge:      challenge,
		ExpiresAt:      expiresAt.Unix(),
		SpacePublicKey: spacePublicKeyString,
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(response)
}

// UserAuth handles user authentication with challenge verification
func (ue UserEndpoints) UserAuth(ctx *fasthttp.RequestCtx) {
	log.Debug().Msg("[AUTH] Starting user authentication")

	authHeader := ctx.Request.Header.Peek(headerAuthorization)
	if authHeader == nil {
		log.Error().Msg("[AUTH] Missing authorization header")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	jws, err := extractJWSFromAuthorizationHeader(string(authHeader))
	if err != nil {
		log.Error().Err(err).Msg("[AUTH] Invalid authorization header")
		ctx.Error("Invalid authorization header", fasthttp.StatusBadRequest)
		return
	}

	log.Debug().Msg("[AUTH] Verifying JWS signature")
	claims, device, err := ue.verifyUserAuthJWS(jws, ue.config.ChallengeTTLSec)
	if err != nil {
		log.Error().Err(err).Msg("[AUTH] Failed to verify JWS")
		ctx.Error("Failed to verify JWS", fasthttp.StatusBadRequest)
		return
	}

	publicKeyPrefix := claims.PublicKey[:min(50, len(claims.PublicKey))] + "..."
	log.Debug().Str("publicKey", publicKeyPrefix).Msg("[AUTH] JWS verified, fetching account")

	// Fetch the account owning the verified device (claims.PublicKey is the
	// DEVICE key; device.UserPublicKey is the account key).
	user, err := ue.userRepository.GetUserByPublicKey(device.UserPublicKey)
	if err != nil {
		log.Error().Err(err).Str("publicKey", publicKeyPrefix).Msg("[AUTH] Failed to get user")
		ctx.Error("Internal server error", fasthttp.StatusInternalServerError)
		return
	}
	if user == nil {
		log.Error().Str("publicKey", publicKeyPrefix).Msg("[AUTH] User not found")
		ctx.Error("User not found", fasthttp.StatusNotFound)
		return
	}

	log.Debug().Str("username", user.Username).Str("role", user.Role).Msg("[AUTH] User found, generating JWT")

	// Generate JWT token
	token, expiresAt, err := ue.userService.GenerateJWT(user, device.DevicePublicKey)
	if err != nil {
		log.Error().Err(err).Msg("[AUTH] Failed to generate JWT")
		ctx.Error("Internal server error", fasthttp.StatusInternalServerError)
		return
	}

	if err := ue.userRepository.TouchDeviceLastSeen(device.DevicePublicKey, time.Now().Unix()); err != nil {
		log.Warn().Err(err).Str("publicKey", publicKeyPrefix).Msg("[AUTH] Failed to touch device last seen")
	}

	// Challenge is already consumed (deleted) by verifyUserAuthJWS's atomic
	// consume() call above - no separate cleanup needed here.

	log.Debug().Str("username", user.Username).Msg("[AUTH] Authentication successful")

	response := LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt,
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(response)
}

// VerifyJWT middleware for protecting routes
func (ue UserEndpoints) VerifyJWT(ctx *fasthttp.RequestCtx) (*User, error) {
	return ue.userService.ValidateJWTFromRequest(ctx)
}

// Helper functions
func extractJWSFromAuthorizationHeader(authHeader string) (string, error) {
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", fmt.Errorf("invalid Authorization header format")
	}
	return parts[1], nil
}

func (ue UserEndpoints) verifyUserAuthJWS(signedJWT string, ttlSec int) (*userAuthJWSClaims, *Device, error) {
	log.Debug().Msg("[VERIFY] Parsing JWT")

	// Parse JWT without verification first to get claims
	token, _, err := jwt.NewParser().ParseUnverified(signedJWT, jwt.MapClaims{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, fmt.Errorf("invalid JWT claims format")
	}

	var claims userAuthJWSClaims
	// claims.PublicKey identifies a DEVICE key (see device_repository.go);
	// pre-device-roster clients pass the account key directly, which still
	// resolves because device #1's key equals the account key.
	if pk, ok := mapClaims["publicKey"].(string); ok {
		claims.PublicKey = pk
	}
	if ch, ok := mapClaims["challenge"].(string); ok {
		claims.Challenge = ch
	}
	if iat, ok := mapClaims["iat"].(float64); ok {
		claims.IssuedAt = int64(iat)
	}

	publicKeyPrefix := claims.PublicKey[:min(50, len(claims.PublicKey))] + "..."
	log.Debug().Str("publicKey", publicKeyPrefix).Msg("[VERIFY] JWT claims extracted")

	// Check if the JWT is expired
	var timeNow = timeNowFunc()
	var issuedAtTime = time.Unix(claims.IssuedAt, 0)
	if issuedAtTime.Add(time.Duration(ttlSec) * time.Second).Before(timeNow) {
		log.Debug().Str("publicKey", publicKeyPrefix).Msg("[VERIFY] JWT has expired")
		return nil, nil, fmt.Errorf("JWT has expired")
	}

	log.Debug().Str("publicKey", publicKeyPrefix).Msg("[VERIFY] Looking up device in database")
	// 1. Get the device by its public key
	device, err := ue.userRepository.GetDevice(claims.PublicKey)
	if err != nil {
		log.Debug().Str("publicKey", publicKeyPrefix).Msg("[VERIFY] Failed to get device from database")
		return nil, nil, fmt.Errorf("device not found: %w", err)
	}
	if device == nil {
		log.Debug().Str("publicKey", publicKeyPrefix).Msg("[VERIFY] Device not found in database")
		return nil, nil, fmt.Errorf("device not found")
	}
	if device.RevokedAt != nil {
		log.Debug().Str("publicKey", publicKeyPrefix).Msg("[VERIFY] Device has been revoked")
		return nil, nil, fmt.Errorf("device revoked")
	}

	log.Debug().Str("publicKey", publicKeyPrefix).Msg("[VERIFY] Device found, validating public key")

	// 2. Parse the device's Ed25519 public key from base64
	publicKeyBytes, err := base64.StdEncoding.DecodeString(claims.PublicKey)
	if err != nil {
		log.Error().Err(err).Str("publicKey", publicKeyPrefix).Msg("[VERIFY] Failed to decode public key base64")
		return nil, nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	if len(publicKeyBytes) != ed25519.PublicKeySize {
		log.Error().Int("size", len(publicKeyBytes)).Msg("[VERIFY] Invalid Ed25519 public key size")
		return nil, nil, fmt.Errorf("invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(publicKeyBytes))
	}

	ed25519PublicKey := ed25519.PublicKey(publicKeyBytes)

	log.Debug().Str("publicKey", publicKeyPrefix).Msg("[VERIFY] Public key parsed, verifying JWT signature")

	// 3. Verify the JWT signature using the device's Ed25519 public key
	verifiedToken, err := jwt.Parse(signedJWT, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return ed25519PublicKey, nil
	})

	if err != nil {
		log.Error().Err(err).Str("publicKey", publicKeyPrefix).Msg("[VERIFY] JWT signature verification failed")
		return nil, nil, fmt.Errorf("failed to verify JWT signature: %w", err)
	}

	if !verifiedToken.Valid {
		log.Error().Str("publicKey", publicKeyPrefix).Msg("[VERIFY] JWT is not valid")
		return nil, nil, fmt.Errorf("JWT signature verification failed")
	}

	log.Debug().Str("publicKey", publicKeyPrefix).Msg("[VERIFY] JWT signature verified, checking challenge")

	// 4. Verify that the challenge matches what was issued (keyed by publicKey).
	// consume() retrieves and deletes it in one lock acquisition, so the
	// challenge is redeemed exactly once - two concurrent replays of the same
	// signed JWS can't both see it as present and both mint a JWT.
	storedChallenge, exists, expired := ue.challenges.consume(claims.PublicKey)
	if !exists {
		log.Error().Str("publicKey", publicKeyPrefix).Msg("[VERIFY] No challenge found for device")
		return nil, nil, fmt.Errorf("no challenge found for device")
	}

	if storedChallenge.challenge != claims.Challenge {
		log.Error().Str("publicKey", publicKeyPrefix).Msg("[VERIFY] Challenge mismatch")
		return nil, nil, fmt.Errorf("challenge mismatch")
	}

	// Check if challenge has expired
	if expired {
		log.Error().Str("publicKey", publicKeyPrefix).Msg("[VERIFY] Challenge has expired")
		return nil, nil, fmt.Errorf("challenge has expired")
	}

	log.Debug().Str("publicKey", publicKeyPrefix).Msg("[VERIFY] All verifications passed successfully")
	return &claims, device, nil
}

func generateChallenge() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GetProfile returns the authenticated user's profile
func (ue UserEndpoints) GetProfile(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("[PROFILE] Unauthorized")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(authenticatedUser)
}

// GetSpacePublicKey returns the space's Ed25519 public key for JWT verification
func (ue UserEndpoints) GetSpacePublicKey(ctx *fasthttp.RequestCtx) {
	response := map[string]string{
		"publicKey": base64.StdEncoding.EncodeToString(ue.publicKey),
		"algorithm": "ed25519",
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(response)
}
