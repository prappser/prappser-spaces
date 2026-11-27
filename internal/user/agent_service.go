package user

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

var (
	ErrAgentLimit          = errors.New("agent limit reached")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
)

const (
	agentAccessTokenTTL     = time.Hour
	agentRefreshTokenTTL    = 90 * 24 * time.Hour
	maxLiveAgentsPerAccount = 5
	refreshGraceWindow      = 30 * time.Second
)

type AgentTokens struct {
	DevicePublicKey      string
	AccessToken          string
	AccessTokenExpiresAt int64
	RefreshToken         string
}

type AgentService struct {
	repo           *agentRepository
	userRepository UserRepository
	privateKey     ed25519.PrivateKey
	publicKey      ed25519.PublicKey
	issuer         string
	audience       string
	Disconnect     func(account, device string)
}

func NewAgentService(db *sql.DB, userRepository UserRepository, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey, externalURL string) *AgentService {
	externalURL = strings.TrimRight(externalURL, "/")
	return &AgentService{
		repo:           newAgentRepository(db),
		userRepository: userRepository,
		privateKey:     privateKey,
		publicKey:      publicKey,
		issuer:         externalURL,
		audience:       externalURL + "/mcp",
	}
}

func newRefreshToken() (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, hashRefreshToken(token), nil
}

// derivedRefreshToken makes the token a rotation issues a pure function of the
// presented token's hash and the server key, so a retry inside the grace window
// can be answered with the same token without storing it.
func (as *AgentService) derivedRefreshToken(oldHash string) string {
	kdf := hmac.New(sha256.New, as.privateKey.Seed())
	kdf.Write([]byte("refresh-token-derivation"))
	mac := hmac.New(sha256.New, kdf.Sum(nil))
	mac.Write([]byte("prappser-refresh-v1" + oldHash))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func hashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (as *AgentService) CanAddAgent(userPublicKey string) (bool, error) {
	n, err := as.repo.countLiveAgents(userPublicKey, time.Now().Unix())
	if err != nil {
		return false, err
	}
	return n < maxLiveAgentsPerAccount, nil
}

func (as *AgentService) CanAddAgentForClient(userPublicKey, clientID string) (bool, error) {
	n, err := as.repo.countLiveAgentsExcludingClient(userPublicKey, clientID, time.Now().Unix())
	if err != nil {
		return false, err
	}
	return n < maxLiveAgentsPerAccount, nil
}

func (as *AgentService) IssueTokens(userPublicKey, name string) (*AgentTokens, error) {
	return as.IssueTokensForClient(userPublicKey, name, "", "")
}

func (as *AgentService) IssueTokensForClient(userPublicKey, name, clientID, clientHost string) (*AgentTokens, error) {
	now := time.Now()
	n, err := as.repo.countLiveAgentsExcludingClient(userPublicKey, clientID, now.Unix())
	if err != nil {
		return nil, err
	}
	// ponytail: soft cap, count-then-insert like register_endpoints.go; parallel issues can overshoot by one
	if n >= maxLiveAgentsPerAccount {
		return nil, ErrAgentLimit
	}

	// "_" is not base64, so challenge auth can never accept this key as a human device.
	deviceKey := "agent_" + rand.Text()
	var namePtr *string
	if name != "" {
		namePtr = &name
	}
	refresh, hash, err := newRefreshToken()
	if err != nil {
		return nil, err
	}
	access, exp, err := as.mintAccessToken(deviceKey)
	if err != nil {
		return nil, err
	}
	if err := as.repo.createAgent(deviceKey, userPublicKey, namePtr, optional(clientID), optional(clientHost), hash, now.Unix(), now.Add(agentRefreshTokenTTL).Unix()); err != nil {
		return nil, err
	}
	log.Info().Msg("[AGENT] Agent device created")

	if clientID != "" {
		stale, err := as.repo.liveAgentsForClient(userPublicKey, clientID, now.Unix())
		if err != nil {
			log.Error().Err(err).Msg("[AGENT] Failed to list stale agents")
		}
		// ponytail: two overlapping issues for one client can each revoke the other's new device, leaving no live token, so the user must re-authorize; accepted soft race, advisory lock on (user, client_id) if it ever matters
		for _, d := range stale {
			if d == deviceKey {
				continue
			}
			if err := as.userRepository.RevokeDevice(d, now.Unix()); err != nil {
				log.Error().Err(err).Msg("[AGENT] Failed to revoke stale agent")
				continue
			}
			if as.Disconnect != nil {
				as.Disconnect(userPublicKey, d)
			}
		}
	}
	return &AgentTokens{DevicePublicKey: deviceKey, AccessToken: access, AccessTokenExpiresAt: exp, RefreshToken: refresh}, nil
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (as *AgentService) Refresh(refreshToken string) (*AgentTokens, error) {
	oldHash := hashRefreshToken(refreshToken)
	newToken := as.derivedRefreshToken(oldHash)
	now := time.Now()
	device, err := as.repo.rotateRefreshToken(oldHash, hashRefreshToken(newToken), now.Unix(), now.Add(agentRefreshTokenTTL).Unix())
	if err != nil {
		return nil, err
	}
	if device == "" {
		prev, err := as.repo.deviceForPrevHash(oldHash)
		inGrace := prev != nil && prev.rotatedAt.Valid && now.Unix()-prev.rotatedAt.Int64 <= int64(refreshGraceWindow/time.Second)
		switch {
		case err != nil:
			log.Error().Err(err).Msg("[AGENT] Refresh token reuse lookup failed")
		case prev == nil:
		case inGrace && prev.currentHash == hashRefreshToken(newToken):
			device = prev.device
			log.Warn().Str("device", prev.device).Msg("[AGENT] Refresh token retried within grace window")
		case inGrace:
			// The derivation key changed since the rotation, so this is a retry we cannot answer, not proof of theft.
		default:
			if err := as.RevokeAgent(prev.account, prev.device); err != nil {
				log.Error().Err(err).Msg("[AGENT] Failed to revoke device after token reuse")
			} else {
				log.Warn().Msg("[AGENT] Refresh token reuse, device revoked")
			}
		}
		if device == "" {
			return nil, ErrInvalidRefreshToken
		}
	}

	access, exp, err := as.mintAccessToken(device)
	if err != nil {
		return nil, err
	}
	return &AgentTokens{DevicePublicKey: device, AccessToken: access, AccessTokenExpiresAt: exp, RefreshToken: newToken}, nil
}

// RevokeAgent disconnects even when the revoke fails, so a live socket never outlasts a revoke attempt.
func (as *AgentService) RevokeAgent(account, device string) error {
	err := as.userRepository.RevokeDevice(device, time.Now().Unix())
	if as.Disconnect != nil {
		as.Disconnect(account, device)
	}
	return err
}

func (as *AgentService) DeviceActive(device string) (bool, error) {
	d, err := as.userRepository.GetDevice(device)
	if err != nil {
		return false, err
	}
	return d != nil && d.RevokedAt == nil, nil
}

func (as *AgentService) mintAccessToken(deviceKey string) (string, int64, error) {
	now := time.Now()
	exp := now.Add(agentAccessTokenTTL)
	claims := jwt.RegisteredClaims{
		Issuer:    as.issuer,
		Subject:   deviceKey,
		Audience:  jwt.ClaimStrings{as.audience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(exp),
		ID:        rand.Text(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["typ"] = accessTokenTyp
	signed, err := token.SignedString(as.privateKey)
	if err != nil {
		return "", 0, fmt.Errorf("failed to sign access token: %w", err)
	}
	return signed, exp.Unix(), nil
}

func (as *AgentService) ValidateAccessToken(tokenString string) (*User, error) {
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(*jwt.Token) (interface{}, error) {
		return as.publicKey, nil
	},
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithAudience(as.audience),
		jwt.WithIssuer(as.issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}
	if typ, _ := token.Header["typ"].(string); typ != accessTokenTyp {
		return nil, fmt.Errorf("not an access token")
	}

	device, err := as.userRepository.GetDevice(claims.Subject)
	if err != nil {
		return nil, err
	}
	if device == nil || device.RevokedAt != nil || device.Kind != DeviceKindAgent {
		return nil, fmt.Errorf("agent device not valid")
	}
	user, err := as.userRepository.GetUserByPublicKey(device.UserPublicKey)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}
	user.DevicePublicKey = device.DevicePublicKey
	user.Agent = true
	user.TokenExpiresAt = claims.ExpiresAt.Unix()
	return user, nil
}
