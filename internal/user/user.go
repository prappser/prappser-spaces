package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
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
	// Issuer is the public key that vouched for this account TO THIS SPACE.
	// Equals PublicKey when the account registered/joined here directly;
	// equals the issuing space's key when it arrived via a cross-space
	// assertion (#111). NEVER empty: CreateUser defaults it to PublicKey.
	Issuer string `json:"issuer"`
	// DevicePublicKey identifies which of the account's devices authenticated
	// the current request. Populated by UserService.ValidateJWT from the JWT's
	// devicePublicKey claim (or the account key for legacy tokens - device #1's
	// key equals the account key). Not part of the wire representation: it is
	// request-scoped identity, not account data.
	DevicePublicKey string `json:"-"`
	// HasPassword reports whether this account has password-login credentials
	// set. Populated only by GetProfile (looked up on demand, not stored on
	// the account record) - omitempty so every other endpoint that serializes
	// a User keeps emitting byte-identical payloads.
	HasPassword bool `json:"hasPassword,omitempty"`
	// UserStateBlob is the account's escrowed user-state blob (see GetEscrow),
	// exposed so the account-key device can union it with local state after
	// another device's PasswordEndpoints.UpdateUserState call refreshes it
	// (#137). Populated only by GetProfile, and only when the caller IS the
	// account-key device (DevicePublicKey == PublicKey, same guard
	// UpdateUserState uses) - secondary devices never consume this blob, so
	// GetProfile skips the GetEscrow round-trip for them entirely. omitempty
	// for the same byte-identical-payload reason as HasPassword above.
	UserStateBlob string `json:"userStateBlob,omitempty"`
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
	UpdateUserRole(publicKey string, role string) error
	UpdateAvatarStorageID(publicKey string, avatarStorageID *string) error
	// UpdateUsername renames an account's username - the same value doubles
	// as its password-login handle. Returns ErrUsernameTaken when the new
	// username collides (case-insensitively) with a DIFFERENT
	// password-enabled account's username (see user_repository.go's partial
	// unique index) - non-password accounts may freely share a username.
	UpdateUsername(publicKey, username string) error
	// UpdateUserIssuer re-pins issuer from self (issuer == public_key) to a
	// vouching space's key, used only by the cross-space assertion re-pin
	// (#111 D5). The SQL guard (WHERE issuer = public_key) enforces the
	// one-way self->vouched upgrade: it is a no-op, returning nil, when the
	// account is already vouched or doesn't exist - callers treat a no-op as
	// fine.
	UpdateUserIssuer(publicKey, issuer string) error
	// SetUserIssuer unconditionally overwrites issuer for an account, used
	// only by the account-key-signed rebind endpoint (#116 Phase 5, see
	// AssertionEndpoints.RebindIssuer). Unlike UpdateUserIssuer, there is no
	// guard: any transition is allowed, including vouched->self, because the
	// account key itself is root authority over its own provenance-only
	// issuer field.
	SetUserIssuer(publicKey, issuer string) error
	// EnsureDevice registers a device for an account if it doesn't already exist (no-op otherwise).
	EnsureDevice(devicePublicKey, userPublicKey string, deviceName *string, createdAt int64) error
	// GetDevice returns nil, nil when no device with that key exists.
	GetDevice(devicePublicKey string) (*Device, error)
	// ListDevices returns the non-revoked devices for an account.
	ListDevices(userPublicKey string) ([]*Device, error)
	// RevokeDevice soft-revokes a device and deletes its push subscriptions.
	RevokeDevice(devicePublicKey string, ts int64) error
	// RenameDevice updates a device's display name. Ownership is checked by
	// the caller (device_endpoints.go), not this method.
	RenameDevice(devicePublicKey, deviceName string) error
	TouchDeviceLastSeen(devicePublicKey string, ts int64) error
	// SetPasswordCredentials sets the password-login verifier, handle, and
	// escrowed account-key/user-state blobs for an account in a single write
	// (see user_repository.go's doc comment for why they move together, and
	// why handle is COALESCEd rather than overwritten). Returns
	// ErrUsernameTaken if another account already holds that username as its
	// password-login handle (case-insensitive). An empty accountKeyBlob or
	// userState clears that column.
	SetPasswordCredentials(publicKey, passwordVerifier, handle, accountKeyBlob, userState string) error
	// GetPasswordCredential returns "", "", nil when no PASSWORD-ENABLED
	// account holds this username (absence is a valid state, not an error).
	GetPasswordCredential(username string) (userPublicKey, verifier string, err error)
	// GetPasswordHandle returns "" when no password-enabled account holds
	// this username (absence is a valid state, not an error) - the caller
	// falls back to lower(username) itself as the HMAC input in that case
	// (see password_endpoints.go's GetSalt).
	GetPasswordHandle(username string) (handle string, err error)
	// GetEscrow returns the account's escrowed account-key and user-state
	// blobs, "", "", nil when unset or no such account (absence is a valid
	// state, not an error). accountKeyBlob is deliberately NOT exposed via
	// User/GetUserByPublicKey; userState IS, but only via GetProfile's
	// on-demand lookup (see the User struct's UserStateBlob doc comment) -
	// GetUserByPublicKey itself never populates it.
	GetEscrow(publicKey string) (accountKeyBlob, userState string, err error)
	// UpdateUserState overwrites the account's escrowed user-state blob so
	// the account-key device can refresh it after a local merge (#137,
	// PasswordEndpoints.UpdateUserState). An empty userState clears the
	// column, mirroring SetPasswordCredentials's per-column NULLIF contract.
	UpdateUserState(publicKey, userState string) error
	// ClaimOwner creates the owner account, its first device, and its
	// password-login credentials, then records the claim in a single
	// transaction (see owner_claim_endpoints.go's Claim, the one-shot
	// unauthenticated endpoint this backs). Returns ErrSpaceAlreadyClaimed if
	// the space was already claimed - the space_owner_claim table's primary
	// key (migration 000024) is the REAL protection against two concurrent
	// claims both succeeding, not any check a caller runs beforehand (see
	// ClaimOwner's doc comment for why). Returns ErrUsernameTaken if another
	// password-enabled account already holds username.
	ClaimOwner(publicKey, username, passwordVerifier, handle, accountKeyBlob, userState string, deviceName *string, createdAt int64) error
	// HasClaim reports whether this space has already been claimed. Used by
	// the claim endpoint as a cheap pre-check before spending Argon2id
	// CPU/memory on an already-claimed space (see owner_claim_endpoints.go's
	// Claim) - it is an optimization, not the concurrency guard (see
	// ClaimOwner's doc comment). Reads the space_owner_claim table rather
	// than users.role: migration 000024 backfills a claim row whenever an
	// owner already exists, so the two are equivalent on legacy data, but
	// only the claim table is authoritative for spaces claimed since #114.
	HasClaim() (bool, error)
}

// ErrUsernameTaken is returned by SetPasswordCredentials and UpdateUsername
// when the requested username is already used for password login on this
// space (by a different, password-enabled account).
var ErrUsernameTaken = errors.New("username already used for password login")

// ErrSpaceAlreadyClaimed is returned by ClaimOwner when an owner account
// already exists for this space - the one-shot owner-claim endpoint refuses
// a second claim.
var ErrSpaceAlreadyClaimed = errors.New("space already claimed")

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
	MasterPassword     string
	JWTExpirationHours int
	ChallengeTTLSec    int
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

	// Copy so the shared authenticatedUser pointer (held by other request
	// middleware) is never mutated by this handler.
	profile := *authenticatedUser
	credPublicKey, _, err := ue.userRepository.GetPasswordCredential(authenticatedUser.Username)
	if err != nil {
		log.Debug().Err(err).Str("username", authenticatedUser.Username).Msg("[PROFILE] Failed to look up password credential")
	} else {
		// Compare to the caller's OWN public key rather than just checking
		// credPublicKey != "": a different, password-enabled account can hold
		// this same username (see UpdateUsername's doc comment on username
		// sharing), which would otherwise register as a false positive.
		profile.HasPassword = credPublicKey == authenticatedUser.PublicKey
	}

	// Only the account-key device ever consumes userStateBlob (secondary
	// devices discard it) - same guard as UpdateUserState - so gate the
	// lookup to skip the extra DB round-trip on every other device's poll.
	if authenticatedUser.DevicePublicKey == authenticatedUser.PublicKey {
		_, userState, err := ue.userRepository.GetEscrow(authenticatedUser.PublicKey)
		if err != nil {
			log.Debug().Err(err).Str("publicKey", authenticatedUser.PublicKey).Msg("[PROFILE] Failed to look up escrow")
		} else {
			profile.UserStateBlob = userState
		}
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(profile)
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
