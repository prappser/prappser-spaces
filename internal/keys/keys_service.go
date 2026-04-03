package keys

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/rs/zerolog/log"
)

type KeyService struct {
	repo           *KeyRepository
	masterPassword string
	privateKey     ed25519.PrivateKey
	publicKey      ed25519.PublicKey
}

func NewKeyService(repo *KeyRepository, masterPassword string) *KeyService {
	return &KeyService{
		repo:           repo,
		masterPassword: masterPassword,
	}
}

func (s *KeyService) Initialize(ctx context.Context) error {
	enc, err := s.repo.GetSpaceKey(ctx)
	if err != nil {
		return fmt.Errorf("failed to load space key: %w", err)
	}

	if enc == nil {
		log.Info().Msg("No space keys found, generating new Ed25519 keypair...")

		priv, pub, err := GenerateEd25519KeyPair()
		if err != nil {
			return fmt.Errorf("failed to generate keypair: %w", err)
		}

		enc, err = EncryptPrivateKey(priv, s.masterPassword)
		if err != nil {
			return fmt.Errorf("failed to encrypt private key: %w", err)
		}

		if err := s.repo.SaveSpaceKey(ctx, enc); err != nil {
			return fmt.Errorf("failed to save space key: %w", err)
		}

		s.privateKey = priv
		s.publicKey = pub
		log.Info().Msg("New Ed25519 keypair generated and stored")
		return nil
	}

	log.Info().Msg("Loading existing space keys from database...")

	priv, err := DecryptPrivateKey(enc, s.masterPassword)
	if err != nil {
		return fmt.Errorf("failed to decrypt space key (wrong MASTER_PASSWORD?): %w", err)
	}

	s.privateKey = priv
	s.publicKey = enc.PublicKey
	log.Info().Msg("Space keys loaded successfully")
	return nil
}

func (s *KeyService) PrivateKey() ed25519.PrivateKey {
	return s.privateKey
}

func (s *KeyService) PublicKey() ed25519.PublicKey {
	return s.publicKey
}
