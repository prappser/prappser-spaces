package space

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type SpaceService struct {
	repo       SpaceRepository
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func NewSpaceService(repo SpaceRepository, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) *SpaceService {
	return &SpaceService{repo: repo, privateKey: privateKey, publicKey: publicKey}
}

func (s *SpaceService) CreateSpace(name string, userPublicKey *string) (*Space, error) {
	if name == "" {
		return nil, fmt.Errorf("space name cannot be empty")
	}

	now := time.Now().Unix()
	space := &Space{
		ID:            uuid.New().String(),
		Name:          name,
		UserPublicKey: userPublicKey,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := s.repo.Create(space); err != nil {
		return nil, fmt.Errorf("failed to create space: %w", err)
	}

	return space, nil
}

func (s *SpaceService) ListSpaces() ([]*Space, error) {
	return s.repo.List()
}

func (s *SpaceService) DeleteSpace(id string) error {
	return s.repo.Delete(id)
}

func (s *SpaceService) GetMySpace(userPublicKey string) (*Space, error) {
	return s.repo.GetByUserPublicKey(userPublicKey)
}

// ClaimInviteResponse is the response for generating a claim invite token.
type ClaimInviteResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expiresAt"`
}

// GenerateClaimInvite creates a time-limited JWT token for claiming a space.
func (s *SpaceService) GenerateClaimInvite(spaceID string) (*ClaimInviteResponse, error) {
	space, err := s.repo.GetByID(spaceID)
	if err != nil {
		return nil, fmt.Errorf("failed to look up space: %w", err)
	}
	if space == nil {
		return nil, fmt.Errorf("space not found")
	}

	expiresAt := time.Now().Add(48 * time.Hour).Unix()

	claims := jwt.MapClaims{
		"spaceId": spaceID,
		"type":    "space_claim",
		"iat":     time.Now().Unix(),
		"exp":     expiresAt,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign claim token: %w", err)
	}

	return &ClaimInviteResponse{
		Token:     tokenString,
		ExpiresAt: expiresAt,
	}, nil
}

// ValidateClaimToken validates a space claim JWT and returns the space ID.
func (s *SpaceService) ValidateClaimToken(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})
	if err != nil {
		return "", fmt.Errorf("invalid claim token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", fmt.Errorf("invalid token claims")
	}

	claimType, _ := claims["type"].(string)
	if claimType != "space_claim" {
		return "", fmt.Errorf("invalid token type")
	}

	spaceID, ok := claims["spaceId"].(string)
	if !ok || spaceID == "" {
		return "", fmt.Errorf("missing spaceId in claim token")
	}

	return spaceID, nil
}

// ClaimSpace assigns a space to a user identified by userPublicKey.
func (s *SpaceService) ClaimSpace(spaceID string, userPublicKey string) (*Space, error) {
	space, err := s.repo.GetByID(spaceID)
	if err != nil {
		return nil, fmt.Errorf("failed to look up space: %w", err)
	}
	if space == nil {
		return nil, fmt.Errorf("space not found")
	}

	if space.UserPublicKey != nil && *space.UserPublicKey != userPublicKey {
		return nil, fmt.Errorf("space already claimed by another user")
	}

	space.UserPublicKey = &userPublicKey
	space.UpdatedAt = time.Now().Unix()
	if err := s.repo.Update(space); err != nil {
		return nil, fmt.Errorf("failed to claim space: %w", err)
	}

	return space, nil
}
