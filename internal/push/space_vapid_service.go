package push

import (
	"context"
	"fmt"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/rs/zerolog/log"
)

// SpaceVapidService manages the singleton VAPID keypair for the space.
// Keys are loaded (or generated) once at startup via Initialize and then
// served from memory for every push delivery.
type SpaceVapidService struct {
	repo       PushRepository
	publicKey  string
	privateKey string
}

// NewSpaceVapidService creates a SpaceVapidService backed by the given repository.
func NewSpaceVapidService(repo PushRepository) *SpaceVapidService {
	return &SpaceVapidService{repo: repo}
}

// Initialize loads the existing space VAPID keypair from the database.
// If no row exists, a new keypair is generated and persisted.
// Must be called once at startup before any push deliveries.
func (s *SpaceVapidService) Initialize(ctx context.Context) error {
	existing, err := s.repo.GetSpaceVapid()
	if err != nil {
		return fmt.Errorf("failed to load space vapid: %w", err)
	}

	if existing != nil {
		s.publicKey = existing.VapidPublicKey
		s.privateKey = existing.VapidPrivateKey
		log.Info().Msg("Space VAPID keys loaded from database")
		return nil
	}

	log.Info().Msg("No space VAPID keys found, generating new keypair...")

	privKey, pubKey, err := webpush.GenerateVAPIDKeys()
	if err != nil {
		return fmt.Errorf("failed to generate VAPID keys: %w", err)
	}

	now := time.Now().Unix()
	v := &SpaceVapid{
		VapidPublicKey:  pubKey,
		VapidPrivateKey: privKey,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	if err := s.repo.UpsertSpaceVapid(v); err != nil {
		return fmt.Errorf("failed to persist space vapid: %w", err)
	}

	// Re-read after upsert so concurrent startups converge on the winner in DB.
	persisted, err := s.repo.GetSpaceVapid()
	if err != nil {
		return fmt.Errorf("failed to reload space vapid after upsert: %w", err)
	}
	if persisted == nil {
		return fmt.Errorf("space vapid row missing after upsert")
	}

	s.publicKey = persisted.VapidPublicKey
	s.privateKey = persisted.VapidPrivateKey
	log.Info().Msg("New space VAPID keypair generated and stored")
	return nil
}

// PublicKey returns the cached VAPID public key.
func (s *SpaceVapidService) PublicKey() string {
	return s.publicKey
}

// PrivateKey returns the cached VAPID private key.
func (s *SpaceVapidService) PrivateKey() string {
	return s.privateKey
}
