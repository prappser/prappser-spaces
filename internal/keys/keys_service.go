package keys

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// lastSeenTouchThrottle caps last_seen_at writes to once per interval, so
// every served request (see KeyEndpoints.TouchLastSeen, wired in
// internal/http.go) doesn't hit the DB. Mirrors UserService's
// deviceTouchThrottle (user_service.go).
const lastSeenTouchThrottle = 5 * time.Minute

// keyRepository is the subset of *KeyRepository's methods KeyService needs.
// *KeyRepository satisfies this implicitly, so production callers pass it
// unchanged; tests substitute a stub without a database (see TouchLastSeen
// tests in keys_service_test.go).
type keyRepository interface {
	GetSpaceKey(ctx context.Context) (*EncryptedKey, error)
	SaveSpaceKey(ctx context.Context, enc *EncryptedKey) error
	TouchLastSeen(ctx context.Context, ts int64) error
}

type KeyService struct {
	repo             keyRepository
	masterPassword   string
	importBlob       string
	importPassphrase string
	privateKey       ed25519.PrivateKey
	publicKey        ed25519.PublicKey

	// touchThrottle overrides lastSeenTouchThrottle in tests; always
	// lastSeenTouchThrottle in production (set by NewKeyService).
	touchThrottle time.Duration

	// lastSeenMu guards lastSeenAt and lastTouchWriteAt below; see
	// TouchLastSeen.
	lastSeenMu       sync.Mutex
	lastSeenAt       int64
	lastTouchWriteAt time.Time
}

// NewKeyService creates a new KeyService. importBlob/importPassphrase are
// SPACE_IDENTITY_IMPORT / SPACE_IDENTITY_IMPORT_PASSPHRASE (see
// internal/config.go) - both empty is the normal, non-migration case; see
// Initialize for how they're used.
func NewKeyService(repo *KeyRepository, masterPassword, importBlob, importPassphrase string) *KeyService {
	return &KeyService{
		repo:             repo,
		masterPassword:   masterPassword,
		importBlob:       importBlob,
		importPassphrase: importPassphrase,
		touchThrottle:    lastSeenTouchThrottle,
	}
}

// Initialize loads or creates this space's identity keypair. Order matters:
//  1. No existing row, no import configured -> generate a fresh keypair
//     (original, pre-#115 behavior).
//  2. Existing row, decrypts under masterPassword -> use it as-is; this
//     short-circuits before the import branch below, which is what makes
//     leaving SPACE_IDENTITY_IMPORT* set across restarts an idempotent
//     no-op once the row has been re-encrypted under the current
//     masterPassword.
//  3. Existing row, decrypt fails, import configured -> this is a hosting
//     move: decode+decrypt the import blob, require its public key to
//     match the existing row's (a mismatch means wrong database or wrong
//     blob - fail startup loudly rather than silently swap identities),
//     then re-encrypt under masterPassword and upsert.
//  4. No existing row, import configured -> same import path, minus the
//     mismatch check (nothing to compare against on a fresh DB).
//  5. Existing row, decrypt fails, no import configured -> original wrong-
//     MASTER_PASSWORD error.
func (s *KeyService) Initialize(ctx context.Context) error {
	enc, err := s.repo.GetSpaceKey(ctx)
	if err != nil {
		return fmt.Errorf("failed to load space key: %w", err)
	}

	if enc == nil && s.importBlob == "" {
		log.Info().Msg("No space keys found, generating new Ed25519 keypair...")

		priv, pub, err := GenerateEd25519KeyPair()
		if err != nil {
			return fmt.Errorf("failed to generate keypair: %w", err)
		}

		newEnc, err := EncryptPrivateKey(priv, s.masterPassword)
		if err != nil {
			return fmt.Errorf("failed to encrypt private key: %w", err)
		}

		if err := s.repo.SaveSpaceKey(ctx, newEnc); err != nil {
			return fmt.Errorf("failed to save space key: %w", err)
		}

		s.privateKey = priv
		s.publicKey = pub
		log.Info().Msg("New Ed25519 keypair generated and stored")
		return nil
	}

	if enc != nil {
		if priv, decryptErr := DecryptPrivateKey(enc, s.masterPassword); decryptErr == nil {
			log.Info().Msg("Loading existing space keys from database...")
			s.privateKey = priv
			s.publicKey = enc.PublicKey
			if enc.LastSeenAt != nil {
				s.lastSeenAt = *enc.LastSeenAt
			}
			return nil
		}
	}

	if s.importBlob == "" {
		return fmt.Errorf("failed to decrypt space key (wrong MASTER_PASSWORD?)")
	}

	return s.importIdentity(ctx, enc)
}

// importIdentity handles Initialize's hosting-move branch: decode+decrypt
// s.importBlob under s.importPassphrase, verify it matches existing (if
// any), then re-encrypt under masterPassword and persist. existing is the
// row Initialize already loaded (nil on a fresh DB).
func (s *KeyService) importIdentity(ctx context.Context, existing *EncryptedKey) error {
	blob, err := DecodeIdentityBlob(s.importBlob)
	if err != nil {
		return fmt.Errorf("failed to decode SPACE_IDENTITY_IMPORT: %w", err)
	}

	priv, err := DecryptPrivateKey(blob, s.importPassphrase)
	if err != nil {
		return fmt.Errorf("failed to decrypt SPACE_IDENTITY_IMPORT (wrong passphrase?): %w", err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	// Corruption check: blob.PublicKey is the blob's own Pub field, decoded
	// (but otherwise unused) by DecodeIdentityBlob. Re-derive the public key
	// from the just-decrypted private key and require the two to match -
	// AES-GCM alone doesn't catch a payload that was assembled inconsistently
	// (e.g. re-encrypted under the wrong key) but still decrypts cleanly.
	if !bytes.Equal(blob.PublicKey, pub) {
		return fmt.Errorf("SPACE_IDENTITY_IMPORT is corrupted: decrypted private key does not match the blob's public key")
	}

	if existing != nil && !bytes.Equal(existing.PublicKey, pub) {
		return fmt.Errorf("identity import public key mismatch: this database already holds a different space identity (wrong database or wrong import blob)")
	}

	newEnc, err := EncryptPrivateKey(priv, s.masterPassword)
	if err != nil {
		return fmt.Errorf("failed to encrypt imported private key: %w", err)
	}
	if err := s.repo.SaveSpaceKey(ctx, newEnc); err != nil {
		return fmt.Errorf("failed to save imported space key: %w", err)
	}

	s.privateKey = priv
	s.publicKey = pub
	if existing != nil && existing.LastSeenAt != nil {
		s.lastSeenAt = *existing.LastSeenAt
	}
	log.Info().Msg("[KEYS] identity imported, re-encrypted under current MASTER_PASSWORD")
	return nil
}

func (s *KeyService) PrivateKey() ed25519.PrivateKey {
	return s.privateKey
}

func (s *KeyService) PublicKey() ed25519.PublicKey {
	return s.publicKey
}

// PublicKeyBase64 returns the space identity's public key, std-base64
// encoded - used by GET /status and the export endpoint's log line.
func (s *KeyService) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(s.publicKey)
}

// ExportIdentity encrypts the space's private key under passphrase (a
// caller-chosen export passphrase, distinct from masterPassword) and
// returns it as a PRAPSPACE1... blob. No DB access - this is a pure
// re-encryption of the key already held in memory.
//
// The minExportPassphraseLen check duplicates KeyEndpoints.ExportIdentity's
// HTTP-layer check (see keys_endpoints.go) so a non-HTTP caller can't bypass
// it by calling the service directly.
func (s *KeyService) ExportIdentity(passphrase string) (string, error) {
	if len(passphrase) < minExportPassphraseLen {
		return "", fmt.Errorf("passphrase must be at least %d characters", minExportPassphraseLen)
	}

	enc, err := EncryptPrivateKey(s.privateKey, passphrase)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt identity for export: %w", err)
	}
	return EncodeIdentityBlob(enc)
}

// LastSeenAt returns the in-memory last-seen timestamp, kept fresh by
// TouchLastSeen and seeded from the DB row at Initialize.
func (s *KeyService) LastSeenAt() int64 {
	s.lastSeenMu.Lock()
	defer s.lastSeenMu.Unlock()
	return s.lastSeenAt
}

// TouchLastSeen fires a best-effort, fire-and-forget last_seen_at write,
// throttled to once per lastSeenTouchThrottle. Called on every served
// request (see KeyEndpoints.TouchLastSeen) so GET /status's lastSeenAt
// tracks whether this space instance is still alive.
// ponytail: the check-then-store below is guarded by lastSeenMu but the
// throttled DB write itself is fire-and-forget and can race a concurrent
// Initialize/import re-save; harmless since last_seen_at only ever moves
// forward and nothing reads it mid-write.
func (s *KeyService) TouchLastSeen() {
	now := time.Now()

	s.lastSeenMu.Lock()
	if !s.lastTouchWriteAt.IsZero() && now.Sub(s.lastTouchWriteAt) < s.touchThrottle {
		s.lastSeenMu.Unlock()
		return
	}
	s.lastTouchWriteAt = now
	s.lastSeenAt = now.Unix()
	s.lastSeenMu.Unlock()

	go func() {
		if err := s.repo.TouchLastSeen(context.Background(), now.Unix()); err != nil {
			log.Warn().Err(err).Msg("[KEYS] Failed to touch space identity last seen")
		}
	}()
}
