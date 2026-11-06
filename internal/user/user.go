package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
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

	NotifyModeAll  = "all"
	NotifyModeChat = "chat"
)

type User struct {
	PublicKey       string  `json:"publicKey"`
	Username        string  `json:"username"`
	Role            string  `json:"role"`
	SpaceID         string  `json:"spaceId,omitempty"`
	CreatedAt       int64   `json:"createdAt"`
	AvatarStorageID *string `json:"avatarStorageId,omitempty"`
	Locale          string  `json:"locale"`
	NotifyMode      string  `json:"notifyMode"`
	BindingIat      int64   `json:"-"`
	BindingSub      string  `json:"-"`
	StoredBinding   string  `json:"-"`
	IdentityBinding string  `json:"identityBinding,omitempty"`
	// DevicePublicKey identifies which of the account's devices authenticated
	// the current request. Populated by UserService.ValidateJWT from the JWT's
	// devicePublicKey claim (or the account key for legacy tokens - device #1's
	// key equals the account key). Not part of the wire representation: it is
	// request-scoped identity, not account data.
	DevicePublicKey string `json:"-"`
	Agent           bool   `json:"-"`
	// HasPassword reports whether this account has password-login credentials
	// set. Populated only by GetProfile (looked up on demand, not stored on
	// the account record) - omitempty so every other endpoint that serializes
	// a User keeps emitting byte-identical payloads.
	HasPassword bool `json:"hasPassword,omitempty"`
	// UserStateBlob is the account's escrowed user-state blob (see GetEscrow),
	// exposed so a device can union it with local state after another
	// device's PasswordEndpoints.UpdateUserState call refreshes it (#137).
	// Populated by GetProfile for every device unconditionally: the blob is
	// sealed client-side under a key derived from the account seed, so a
	// device without that seed just receives ciphertext it can't open -
	// gating the lookup to the account-key device was a DB round-trip
	// optimization, never a security boundary. omitempty for the same
	// byte-identical-payload reason as HasPassword above.
	UserStateBlob string `json:"userStateBlob,omitempty"`
	// HasEscrow reports whether this space holds an escrowed account-key
	// blob for the account (accountKeyBlob != "" from GetEscrow). Derived
	// fresh on every GetProfile call, never stored on the account record.
	// Deliberately a boolean, not the blob itself: exposing accountKeyBlob
	// here would let any authenticated device pull it and crack it offline
	// without proving the password.
	HasEscrow bool `json:"hasEscrow,omitempty"`
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
	Kind            string  `json:"kind"`
}

const (
	DeviceKindHuman = "human"
	DeviceKindAgent = "agent"

	accessTokenTyp = "at+jwt"
)

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
	UpdateLocale(publicKey, locale string) error
	UpdateNotifyMode(publicKey, mode string) error
	AcceptBinding(publicKey, binding string, iat int64, sub, ownKey string) (storedBinding, storedSub string, updated bool, err error)
	// EnsureDevice registers a device for an account if it doesn't already exist (no-op otherwise).
	EnsureDevice(devicePublicKey, userPublicKey string, deviceName *string, createdAt int64) error
	ReviveDevice(devicePublicKey, userPublicKey string, revokedBefore int64) (bool, error)
	// GetDevice returns nil, nil when no device with that key exists.
	GetDevice(devicePublicKey string) (*Device, error)
	// ListDevices returns the devices for an account; revoked ones only when includeRevoked is set.
	ListDevices(userPublicKey string, includeRevoked bool) ([]*Device, error)
	// RevokeDevice soft-revokes a device and deletes its push subscriptions.
	RevokeDevice(devicePublicKey string, ts int64) error
	// RenameDevice updates a device's display name. Ownership is checked by
	// the caller (device_endpoints.go), not this method.
	RenameDevice(devicePublicKey, deviceName string) error
	TouchDeviceLastSeen(devicePublicKey string, ts int64) error
	// SetPasswordCredentials sets the password-login verifier, handle, and
	// escrowed account-key/user-state blobs for an account in a single write
	// (see user_repository.go's doc comment for why they move together, and
	// why a handle is frozen while a verifier is live and re-pointed once it is NULL). Returns
	// ErrUsernameTaken if another account already holds that username as its
	// password-login handle (case-insensitive). An empty accountKeyBlob or
	// userState clears that column.
	SetPasswordCredentials(publicKey, passwordVerifier, handle, accountKeyBlob, userState, ownKey string) error
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
	// UpdateUserState overwrites the account's escrowed user-state blob so a
	// device can refresh it after a local merge (#137,
	// PasswordEndpoints.UpdateUserState). An empty userState clears the
	// column, mirroring SetPasswordCredentials's per-column NULLIF contract.
	UpdateUserState(publicKey, userState string) error
	// ClearEscrow nulls account_key_blob, user_state_blob, AND
	// password_verifier for an account on this space (DELETE
	// /users/me/escrow, see PasswordEndpoints.ClearEscrow) - used when the
	// account is moving its escrow elsewhere, or reclaiming its key.
	// password_handle is deliberately left alone; idempotent, an
	ClearEscrow(publicKey, ownKey string) error
	// ClaimOwner creates the owner account, its first device, and its
	// password-login credentials, then records the claim in a single
	// transaction (see owner_claim_endpoints.go's Claim, the one-shot
	// unauthenticated endpoint this backs). Returns ErrSpaceAlreadyClaimed if
	// the space was already claimed - the space_owner_claim table's primary
	// key (migration 000024) is the REAL protection against two concurrent
	// claims both succeeding, not any check a caller runs beforehand (see
	// ClaimOwner's doc comment for why). Returns ErrUsernameTaken if another
	// password-enabled account already holds username. Returns
	// ErrDeviceKeyTaken if devicePublicKey is already registered on this
	// space (device_public_key is globally unique - migration 000018) -
	// the claim is rejected outright rather than silently reusing the
	// existing device row. passwordVerifier and handle may both be empty
	// (claiming without a password); devicePublicKey is device #1's key,
	// which no longer has to equal the account key.
	ClaimOwner(publicKey, username, passwordVerifier, handle, accountKeyBlob, userState, devicePublicKey string, deviceName *string, createdAt int64) error
	// HasClaim reports whether this space has already been claimed. Used by
	// the claim endpoint as a cheap pre-check before spending Argon2id
	// CPU/memory on an already-claimed space (see owner_claim_endpoints.go's
	// Claim) - it is an optimization, not the concurrency guard (see
	// ClaimOwner's doc comment). Reads the space_owner_claim table rather
	// than users.role: migration 000024 backfills a claim row whenever an
	// owner already exists, so the two are equivalent on legacy data, but
	// only the claim table is authoritative for spaces claimed since #114.
	HasClaim() (bool, error)
	// RegisterUser creates a 'user'-role account with password credentials,
	// escrow, and its first device in one transaction (POST /users/register).
	// Returns ErrUsernameTaken, ErrAccountExists, or ErrDeviceKeyTaken on the
	// matching unique violation. userState may be empty.
	RegisterUser(publicKey, username, passwordVerifier, handle, accountKeyBlob, userState, devicePublicKey string, deviceName *string, createdAt int64) error
	// CountUsers counts every account on the space, owner and guests included.
	CountUsers() (int, error)
}

// ErrUsernameTaken is returned by SetPasswordCredentials and UpdateUsername
// when the requested username is already used for password login on this
// space (by a different, password-enabled account).
var ErrUsernameTaken = errors.New("username already used for password login")

var ErrIdentitySpaceEscrow = errors.New("escrow cannot be cleared on the identity space")

// ErrSpaceAlreadyClaimed is returned by ClaimOwner when an owner account
// already exists for this space - the one-shot owner-claim endpoint refuses
// a second claim.
var ErrSpaceAlreadyClaimed = errors.New("space already claimed")

// ErrDeviceKeyTaken is returned by ClaimOwner when the claim's
// devicePublicKey is already registered as a device on this space.
var ErrDeviceKeyTaken = errors.New("device key already registered on this space")

// ErrAccountExists is returned by RegisterUser when the account public key
// already has a users row.
var ErrAccountExists = errors.New("account already exists")

// ErrAudienceMismatch is returned by verifyUserAuthJWS when the login JWS was
// signed for a different space than this one (login-phishing replay).
var ErrAudienceMismatch = errors.New("login audience does not match this space")

var errMalformedLogin = errors.New("malformed login")

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
	Bindings   *Bindings
}

type Config struct {
	JWTExpirationHours int
	ChallengeTTLSec    int
	// ExternalURL (EXTERNAL_URL, already resolved) is the URL device logins
	// are bound to via the JWS aud claim; empty falls back to the request Host.
	ExternalURL string
	// TrustProxyHeaders lets X-Forwarded-Proto pick the scheme of the
	// request-derived URL.
	TrustProxyHeaders bool
}

// JWS claims for user authentication
type userAuthJWSClaims struct {
	PublicKey string `json:"publicKey"` // User's public key (unique identifier)
	Challenge string `json:"challenge"` // Prevents replay attacks
	IssuedAt  int64  `json:"iat"`       // For TTL validation
	Audience  string `json:"aud"`       // Space URL the login is bound to; empty when absent
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
	BindingVersion  int64  `json:"bv,omitempty"`
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
	publicKey string
	expiresAt time.Time
}

const maxChallenges = 10000

type challengeStore struct {
	mu   sync.Mutex
	data map[string]challengeInfo
	max  int
}

func newChallengeStore() *challengeStore {
	return &challengeStore{data: make(map[string]challengeInfo), max: maxChallenges}
}

func (s *challengeStore) store(challenge string, info challengeInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.data) >= s.max {
		now := timeNowFunc()
		for key, entry := range s.data {
			if entry.expiresAt.Before(now) {
				delete(s.data, key)
			}
		}
		if len(s.data) >= s.max {
			for key := range s.data {
				delete(s.data, key)
				break
			}
		}
	}
	s.data[challenge] = info
}

func (s *challengeStore) consume(challenge, publicKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.data[challenge]
	if !ok {
		return errors.New("no such challenge")
	}
	delete(s.data, challenge)
	if info.publicKey != publicKey {
		return errors.New("challenge issued to another key")
	}
	if info.expiresAt.Before(timeNowFunc()) {
		return errors.New("challenge has expired")
	}
	return nil
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
		Bindings:       NewBindings(userRepository, base64.StdEncoding.EncodeToString(publicKey)),
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

	if !isPublicKey(publicKeyStr) {
		log.Debug().Msg("[CHALLENGE] Malformed publicKey")
		ctx.Error("publicKey must be 32 std-base64-encoded bytes", fasthttp.StatusBadRequest)
		return
	}

	// Generate random challenge
	challenge, err := generateChallenge()
	if err != nil {
		log.Error().Err(err).Msg("[CHALLENGE] Failed to generate challenge")
		ctx.Error("Internal server error", fasthttp.StatusInternalServerError)
		return
	}

	expiresAt := timeNowFunc().Add(time.Duration(ue.config.ChallengeTTLSec) * time.Second)

	ue.challenges.store(challenge, challengeInfo{
		publicKey: publicKeyStr,
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

type userAuthRequest struct {
	Assertion string `json:"assertion"`
	Binding   string `json:"binding"`
}

func refuseAuth(ctx *fasthttp.RequestCtx, body any) {
	if body == nil {
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}
	writeJSON(ctx, fasthttp.StatusUnauthorized, body)
}

func (ue UserEndpoints) UserAuth(ctx *fasthttp.RequestCtx) {
	log.Debug().Msg("[AUTH] Starting user authentication")

	var req userAuthRequest
	if body := strings.TrimSpace(string(ctx.PostBody())); body != "" {
		if err := json.Unmarshal([]byte(body), &req); err != nil {
			log.Error().Err(err).Msg("[AUTH] Malformed request body")
			ctx.Error("invalid request body", fasthttp.StatusBadRequest)
			return
		}
	}
	if (req.Assertion == "") != (req.Binding == "") {
		log.Error().Msg("[AUTH] Assertion and binding must be sent together")
		ctx.Error("assertion and binding must be sent together", fasthttp.StatusBadRequest)
		return
	}

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

	claims, err := ue.verifyUserAuthJWS(jws, ue.config.ChallengeTTLSec, ue.expectedSpaceURL(ctx))
	if err != nil {
		log.Error().Err(err).Msg("[AUTH] Failed to verify JWS")
		if errors.Is(err, errMalformedLogin) {
			ctx.Error("Failed to verify JWS", fasthttp.StatusBadRequest)
		} else {
			ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		}
		return
	}
	deviceKey := claims.PublicKey
	publicKeyPrefix := deviceKey[:min(50, len(deviceKey))] + "..."
	now := timeNowFunc()

	var user *User
	if req.Binding != "" {
		user = ue.bindingLogin(ctx, deviceKey, req, now)
	} else {
		user = ue.rosterLogin(ctx, deviceKey)
	}
	if user == nil {
		return
	}

	token, expiresAt, err := ue.userService.GenerateJWT(user, deviceKey)
	if err != nil {
		log.Error().Err(err).Msg("[AUTH] Failed to generate JWT")
		ctx.Error("Internal server error", fasthttp.StatusInternalServerError)
		return
	}

	if err := ue.userRepository.TouchDeviceLastSeen(deviceKey, time.Now().Unix()); err != nil {
		log.Warn().Err(err).Str("publicKey", publicKeyPrefix).Msg("[AUTH] Failed to touch device last seen")
	}

	log.Debug().Str("username", user.Username).Msg("[AUTH] Authentication successful")
	writeJSON(ctx, fasthttp.StatusOK, LoginResponse{Token: token, ExpiresAt: expiresAt})
}

func (ue UserEndpoints) bindingLogin(ctx *fasthttp.RequestCtx, deviceKey string, req userAuthRequest, now time.Time) *User {
	iss := bindingIssuer(req.Binding)
	acct, err := ue.userRepository.GetUserByPublicKey(iss)
	if err != nil {
		log.Error().Err(err).Msg("[AUTH] Failed to get account")
		ctx.Error("Internal server error", fasthttp.StatusInternalServerError)
		return nil
	}
	if acct == nil {
		log.Error().Msg("[AUTH] Binding names an unknown account")
		refuseAuth(ctx, nil)
		return nil
	}
	adm, err := ue.Bindings.VerifyAdmission(iss, deviceKey, req.Binding, req.Assertion, now)
	if err != nil {
		log.Error().Err(err).Msg("[AUTH] Binding admission refused")
		refuseAuth(ctx, nil)
		return nil
	}
	err = ue.Bindings.Admit(iss, deviceKey, req.Binding, adm, nil, now)
	var required *BindingRequiredError
	switch {
	case errors.As(err, &required):
		log.Error().Msg("[AUTH] Presented binding is not the stored one")
		refuseAuth(ctx, bindingResponse{Code: "binding_required", Binding: required.Binding})
		return nil
	case errors.Is(err, ErrDeviceRowConflict):
		log.Error().Msg("[AUTH] Device row conflicts with this admission")
		refuseAuth(ctx, nil)
		return nil
	case err != nil:
		log.Error().Err(err).Msg("[AUTH] Failed to admit device")
		ctx.Error("Internal server error", fasthttp.StatusInternalServerError)
		return nil
	}
	acct.BindingIat = max(acct.BindingIat, adm.claims.IssuedAt)
	return acct
}

func (ue UserEndpoints) rosterLogin(ctx *fasthttp.RequestCtx, deviceKey string) *User {
	d, err := ue.userRepository.GetDevice(deviceKey)
	if err != nil {
		log.Error().Err(err).Msg("[AUTH] Failed to get device")
		ctx.Error("Internal server error", fasthttp.StatusInternalServerError)
		return nil
	}
	if d == nil {
		log.Error().Msg("[AUTH] Device not found")
		refuseAuth(ctx, nil)
		return nil
	}
	acct, err := ue.userRepository.GetUserByPublicKey(d.UserPublicKey)
	if err != nil {
		log.Error().Err(err).Msg("[AUTH] Failed to get account")
		ctx.Error("Internal server error", fasthttp.StatusInternalServerError)
		return nil
	}
	if acct == nil {
		log.Error().Msg("[AUTH] Account not found")
		refuseAuth(ctx, nil)
		return nil
	}
	allowed, err := ue.Bindings.RosterAllowed(acct, d)
	if err != nil {
		log.Error().Err(err).Msg("[AUTH] Failed to check roster login")
		ctx.Error("Internal server error", fasthttp.StatusInternalServerError)
		return nil
	}
	if !allowed {
		log.Error().Msg("[AUTH] Roster login refused")
		if acct.BindingIat > 0 {
			refuseAuth(ctx, bindingResponse{Code: "binding_required", Binding: acct.StoredBinding})
		} else {
			refuseAuth(ctx, nil)
		}
		return nil
	}
	return acct
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

// normalizeSpaceURL reduces a space URL to scheme://host[:port]: lowercase,
// default port dropped, path/query/fragment ignored.
func normalizeSpaceURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid space URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Hostname() == "" || u.User != nil {
		return "", fmt.Errorf("invalid space URL: need http(s) scheme and host, no userinfo")
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host, nil
}

// expectedSpaceURL is the normalized URL a login JWS must carry as aud, or ""
// when it cannot be determined. It reads Host, never X-Forwarded-Host: a
// client can send that header and Cloudflare passes it through, which would let
// an attacker space name itself as the audience.
func (ue UserEndpoints) expectedSpaceURL(ctx *fasthttp.RequestCtx) string {
	raw := ue.config.ExternalURL
	if raw == "" {
		scheme := "http"
		if ctx.IsTLS() {
			scheme = "https"
		}
		if ue.config.TrustProxyHeaders {
			if proto := strings.TrimSpace(strings.Split(string(ctx.Request.Header.Peek("X-Forwarded-Proto")), ",")[0]); proto != "" {
				scheme = proto
			}
		}
		raw = scheme + "://" + string(ctx.Host())
	}
	normalized, err := normalizeSpaceURL(raw)
	if err != nil {
		log.Warn().Err(err).Msg("[AUTH] Cannot determine this space's URL")
		return ""
	}
	return normalized
}

func (ue UserEndpoints) verifyUserAuthJWS(signedJWT string, ttlSec int, expectedAud string) (*userAuthJWSClaims, error) {
	token, _, err := jwt.NewParser().ParseUnverified(signedJWT, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errMalformedLogin, err)
	}
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: invalid claims format", errMalformedLogin)
	}

	var claims userAuthJWSClaims
	claims.PublicKey, _ = mapClaims["publicKey"].(string)
	claims.Challenge, _ = mapClaims["challenge"].(string)
	if iat, ok := mapClaims["iat"].(float64); ok {
		claims.IssuedAt = int64(iat)
	}
	rawAud, hasAud := mapClaims["aud"]

	if !isPublicKey(claims.PublicKey) {
		return nil, fmt.Errorf("%w: bad publicKey", errMalformedLogin)
	}
	publicKeyPrefix := claims.PublicKey[:min(50, len(claims.PublicKey))] + "..."

	if time.Unix(claims.IssuedAt, 0).Add(time.Duration(ttlSec) * time.Second).Before(timeNowFunc()) {
		return nil, fmt.Errorf("JWT has expired")
	}

	publicKeyBytes, _ := base64.StdEncoding.DecodeString(claims.PublicKey)
	verifiedToken, err := jwt.Parse(signedJWT, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return ed25519.PublicKey(publicKeyBytes), nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify JWT signature: %w", err)
	}
	if !verifiedToken.Valid {
		return nil, errors.New("JWT signature verification failed")
	}

	if err := ue.challenges.consume(claims.Challenge, claims.PublicKey); err != nil {
		return nil, err
	}

	if hasAud {
		aud, _ := rawAud.(string)
		normalized, err := normalizeSpaceURL(aud)
		if err != nil || expectedAud == "" || normalized != expectedAud {
			log.Error().Str("publicKey", publicKeyPrefix).Str("expectedAud", expectedAud).Str("presentedAud", aud).Msg("[VERIFY] Audience mismatch")
			return nil, ErrAudienceMismatch
		}
		claims.Audience = normalized
	} else {
		log.Info().Str("publicKey", publicKeyPrefix).Msg("[AUTH] Login JWS has no aud, accepting for old clients")
	}

	return &claims, nil
}

func isPublicKey(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == ed25519.PublicKeySize
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

	// Runs unconditionally for every device now - see UserStateBlob's doc
	// comment for why the old account-key-device gate was never a security
	// boundary.
	accountKeyBlob, userState, err := ue.userRepository.GetEscrow(authenticatedUser.PublicKey)
	if err != nil {
		log.Debug().Err(err).Str("publicKey", authenticatedUser.PublicKey).Msg("[PROFILE] Failed to look up escrow")
	} else {
		profile.UserStateBlob = userState
		profile.HasEscrow = accountKeyBlob != ""
	}
	profile.IdentityBinding = authenticatedUser.StoredBinding

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
