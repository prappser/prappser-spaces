package user

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

// deviceTouchThrottle caps last-seen writes to once per interval per device.
// JWT TTL is 24h, so touching on every authenticated request would hit the
// DB constantly for a timestamp whose granularity nobody needs that fine.
const deviceTouchThrottle = 5 * time.Minute

// SpaceLookup is a minimal interface to avoid circular dependency with space package.
type SpaceLookup interface {
	GetByUserPublicKey(publicKey string) (*SpaceInfo, error)
}

// SpaceInfo carries the space fields needed for JWT claims.
type SpaceInfo struct {
	ID string
}

type UserService struct {
	userRepository UserRepository
	spaceLookup    SpaceLookup
	config         Config
	privateKey     ed25519.PrivateKey
	publicKey      ed25519.PublicKey
	// lastDeviceTouch throttles TouchDeviceLastSeen writes; see deviceTouchThrottle.
	lastDeviceTouch sync.Map // map[string]time.Time
}

func NewUserService(userRepository UserRepository, spaceLookup SpaceLookup, config Config, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) *UserService {
	return &UserService{
		userRepository: userRepository,
		spaceLookup:    spaceLookup,
		config:         config,
		privateKey:     privateKey,
		publicKey:      publicKey,
	}
}

func (us *UserService) ValidateJWTFromRequest(ctx *fasthttp.RequestCtx) (*User, error) {
	authHeader := ctx.Request.Header.Peek(headerAuthorization)
	if authHeader == nil {
		return nil, fmt.Errorf("missing authorization header")
	}

	tokenString, err := extractJWTFromAuthorizationHeader(string(authHeader))
	if err != nil {
		return nil, fmt.Errorf("invalid authorization header: %w", err)
	}

	return us.ValidateJWT(tokenString)
}

func (us *UserService) GenerateJWT(user *User, deviceKey string) (string, int64, error) {
	expiresAt := time.Now().Add(time.Duration(us.config.JWTExpirationHours) * time.Hour).Unix()

	var spaceID string
	if us.spaceLookup != nil {
		if spaceInfo, err := us.spaceLookup.GetByUserPublicKey(user.PublicKey); err == nil && spaceInfo != nil {
			spaceID = spaceInfo.ID
		}
	}

	claims := JWTClaims{
		UserPublicKey:   user.PublicKey,
		DevicePublicKey: deviceKey,
		Username:        user.Username,
		Role:            user.Role,
		SpaceID:         spaceID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Unix(expiresAt, 0)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenString, err := token.SignedString(us.privateKey)
	if err != nil {
		return "", 0, err
	}

	return tokenString, expiresAt, nil
}

func (us *UserService) ValidateJWT(tokenString string) (*User, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return us.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		user, err := us.userRepository.GetUserByPublicKey(claims.UserPublicKey)
		if err != nil {
			return nil, err
		}
		if user == nil {
			return nil, fmt.Errorf("user not found")
		}
		user.SpaceID = claims.SpaceID

		// Legacy tokens (minted before the device roster existed) carry no
		// devicePublicKey claim - device #1's key equals the account key, so
		// falling back to it still enforces revocation correctly for them.
		deviceKey := claims.DevicePublicKey
		if deviceKey == "" {
			deviceKey = claims.UserPublicKey
		}

		device, err := us.userRepository.GetDevice(deviceKey)
		if err != nil {
			return nil, err
		}
		if device == nil || device.RevokedAt != nil {
			return nil, fmt.Errorf("device not found or revoked")
		}

		user.DevicePublicKey = deviceKey
		us.touchDeviceLastSeenThrottled(deviceKey)

		return user, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// touchDeviceLastSeenThrottled fires a best-effort, fire-and-forget
// TouchDeviceLastSeen write, throttled to once per deviceTouchThrottle per
// device so that every authenticated request doesn't hit the DB.
// ponytail: the load-then-store below isn't atomic, so two requests landing
// in the same instant can both pass the throttle check and both fire a
// write; harmless since last-seen is monotonically increasing either way,
// not worth a per-device lock for that.
func (us *UserService) touchDeviceLastSeenThrottled(deviceKey string) {
	now := time.Now()
	if last, loaded := us.lastDeviceTouch.Load(deviceKey); loaded {
		if now.Sub(last.(time.Time)) < deviceTouchThrottle {
			return
		}
	}
	us.lastDeviceTouch.Store(deviceKey, now)

	go func() {
		if err := us.userRepository.TouchDeviceLastSeen(deviceKey, now.Unix()); err != nil {
			log.Warn().Err(err).Msg("[AUTH] Failed to touch device last seen")
		}
	}()
}

func extractJWTFromAuthorizationHeader(authHeader string) (string, error) {
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != headerBearer {
		return "", fmt.Errorf("invalid Authorization header format")
	}
	return parts[1], nil
}
