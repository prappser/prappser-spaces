package user

import (
	"crypto/ed25519"
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

func hashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (as *AgentService) IssueTokens(userPublicKey, name string) (*AgentTokens, error) {
	now := time.Now()
	n, err := as.repo.countLiveAgents(userPublicKey, now.Unix())
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
	if err := as.repo.createAgent(deviceKey, userPublicKey, namePtr, hash, now.Unix(), now.Add(agentRefreshTokenTTL).Unix()); err != nil {
		return nil, err
	}
	log.Info().Msg("[AGENT] Agent device created")
	return &AgentTokens{DevicePublicKey: deviceKey, AccessToken: access, AccessTokenExpiresAt: exp, RefreshToken: refresh}, nil
}

func (as *AgentService) Refresh(refreshToken string) (*AgentTokens, error) {
	oldHash := hashRefreshToken(refreshToken)
	newToken, newHash, err := newRefreshToken()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	device, err := as.repo.rotateRefreshToken(oldHash, newHash, now.Unix(), now.Add(agentRefreshTokenTTL).Unix())
	if err != nil {
		return nil, err
	}
	if device == "" {
		reused, err := as.repo.deviceForPrevHash(oldHash)
		if err != nil {
			return nil, err
		}
		if reused != "" {
			if err := as.userRepository.RevokeDevice(reused, now.Unix()); err != nil {
				return nil, fmt.Errorf("failed to revoke device after token reuse: %w", err)
			}
			log.Warn().Msg("[AGENT] Refresh token reuse, device revoked")
		}
		return nil, ErrInvalidRefreshToken
	}

	access, exp, err := as.mintAccessToken(device)
	if err != nil {
		return nil, err
	}
	return &AgentTokens{DevicePublicKey: device, AccessToken: access, AccessTokenExpiresAt: exp, RefreshToken: newToken}, nil
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
	return user, nil
}
