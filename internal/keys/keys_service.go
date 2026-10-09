package keys

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
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
	HasUsers(ctx context.Context) (bool, error)
	TouchLastSeen(ctx context.Context, ts int64) error
}

type KeyService struct {
	repo             keyRepository
	masterPassword   string
	importBlob       string
	importPassphrase string
	keyFilePath      string
	keyDirEphemeral  bool
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

func NewKeyService(repo *KeyRepository, masterPassword, importBlob, importPassphrase, keyFilePath string, keyDirEphemeral bool) *KeyService {
	return &KeyService{
		repo:             repo,
		masterPassword:   masterPassword,
		importBlob:       importBlob,
		importPassphrase: importPassphrase,
		keyFilePath:      keyFilePath,
		keyDirEphemeral:  keyDirEphemeral,
		touchThrottle:    lastSeenTouchThrottle,
	}
}

const missingKeyAlternatives = "restore the storage volume, or set SPACE_IDENTITY_IMPORT"

// Initialize resolves the space identity. A: key file present: load it and
// cross-check the row and import by public key only, never Argon2. B: row, no
// file: B1 MASTER_PASSWORD decrypts it, B2 import, B3 refuse. C: no row: C1
// import, C2 accounts exist so refuse, C4 generate. Never writes space_keys.
func (s *KeyService) Initialize(ctx context.Context) error {
	path := s.keyFilePath

	row, err := s.repo.GetSpaceKey(ctx)
	if err != nil {
		return fmt.Errorf("failed to load space key: %w", err)
	}
	if row != nil && row.LastSeenAt != nil {
		s.lastSeenAt = *row.LastSeenAt
	}

	filePriv, err := loadKeyFile(path)
	if err != nil {
		return err
	}
	if filePriv != nil {
		return s.useFile(filePriv, row)
	}

	if row != nil {
		return s.initFromRow(row)
	}

	if s.importBlob != "" {
		priv, err := s.decryptImport()
		if err != nil {
			return err
		}
		log.Info().Msg("[KEYS] importing identity from SPACE_IDENTITY_IMPORT")
		return s.persist(priv, nil)
	}

	hasUsers, err := s.repo.HasUsers(ctx)
	if err != nil {
		return fmt.Errorf("failed to check for existing accounts: %w", err)
	}
	if hasUsers {
		return fmt.Errorf("space key file %s missing but the space has accounts: storage volume lost or not persistent; %s", path, missingKeyAlternatives)
	}

	priv, _, err := GenerateEd25519KeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}
	log.Info().Msg("[KEYS] no space key found, generating new Ed25519 keypair")
	return s.persist(priv, nil)
}

func (s *KeyService) initFromRow(row *EncryptedKey) error {
	decryptFailed := false
	if s.masterPassword != "" {
		priv, err := DecryptPrivateKey(row, s.masterPassword)
		if err == nil {
			if !bytes.Equal(pubOf(priv), row.PublicKey) {
				return fmt.Errorf("space_keys row is corrupt: decrypted key does not match its public key")
			}
			if err := s.checkImportMatches(row.PublicKey); err != nil {
				return err
			}
			log.Info().Msg("[KEYS] migrating legacy space_keys row to key file")
			return s.persist(priv, row)
		}
		decryptFailed = true
	}

	if s.importBlob != "" {
		priv, err := s.decryptImport()
		if err != nil {
			return err
		}
		if !bytes.Equal(pubOf(priv), row.PublicKey) {
			return errImportMismatch
		}
		log.Info().Msg("[KEYS] importing identity from SPACE_IDENTITY_IMPORT")
		return s.persist(priv, row)
	}

	if !decryptFailed {
		return fmt.Errorf("space key file %s missing; set MASTER_PASSWORD once to migrate the legacy space_keys row, %s", s.keyFilePath, missingKeyAlternatives)
	}
	return fmt.Errorf("cannot decrypt the space_keys row with MASTER_PASSWORD (wrong password or corrupt row): space key file %s missing; set the correct MASTER_PASSWORD, %s", s.keyFilePath, missingKeyAlternatives)
}

var errImportMismatch = errors.New("identity import public key mismatch: this space already holds a different identity (wrong database, volume or import blob)")

func pubOf(priv ed25519.PrivateKey) ed25519.PublicKey {
	return priv.Public().(ed25519.PublicKey)
}

// checkImportMatches is a no-op without SPACE_IDENTITY_IMPORT; otherwise the
// blob's public key must equal pub.
func (s *KeyService) checkImportMatches(pub ed25519.PublicKey) error {
	if s.importBlob == "" {
		return nil
	}
	blob, err := DecodeIdentityBlob(s.importBlob)
	if err != nil {
		return fmt.Errorf("failed to decode SPACE_IDENTITY_IMPORT: %w", err)
	}
	if !bytes.Equal(blob.PublicKey, pub) {
		return errImportMismatch
	}
	return nil
}

func (s *KeyService) useFile(priv ed25519.PrivateKey, row *EncryptedKey) error {
	pub := pubOf(priv)
	if row != nil && !bytes.Equal(row.PublicKey, pub) {
		return fmt.Errorf("space key file %s does not match the space_keys row (wrong volume or database)", s.keyFilePath)
	}
	if err := s.checkImportMatches(pub); err != nil {
		return err
	}
	s.privateKey = priv
	s.publicKey = pub
	log.Info().Str("path", s.keyFilePath).Str("publicKey", s.PublicKeyBase64()).Msg("[KEYS] space key loaded from file")
	if s.masterPassword != "" {
		log.Info().Msg("[KEYS] MASTER_PASSWORD is only needed for rolling back to a pre-key-file release")
	}
	return nil
}

func (s *KeyService) persist(priv ed25519.PrivateKey, row *EncryptedKey) error {
	if s.keyDirEphemeral {
		return fmt.Errorf("refusing to write space key file %s: STORAGE_TYPE=s3 with STORAGE_PATH unset would put it on ephemeral disk; set STORAGE_PATH to a persistent volume", s.keyFilePath)
	}
	err := writeKeyFile(s.keyFilePath, priv)
	if errors.Is(err, errKeyFileExists) {
		existing, loadErr := loadKeyFile(s.keyFilePath)
		if loadErr != nil {
			return loadErr
		}
		if existing == nil {
			return fmt.Errorf("space key file %s vanished during write", s.keyFilePath)
		}
		return s.useFile(existing, row)
	}
	if err != nil {
		return err
	}

	written, err := loadKeyFile(s.keyFilePath)
	if err != nil {
		return err
	}
	if written == nil || !bytes.Equal(pubOf(written), pubOf(priv)) {
		return fmt.Errorf("space key file %s does not match the key just written", s.keyFilePath)
	}
	s.privateKey = written
	s.publicKey = pubOf(written)
	log.Info().Str("path", s.keyFilePath).Str("publicKey", s.PublicKeyBase64()).Msg("[KEYS] space key written to file")
	return nil
}

func (s *KeyService) decryptImport() (ed25519.PrivateKey, error) {
	blob, err := DecodeIdentityBlob(s.importBlob)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SPACE_IDENTITY_IMPORT: %w", err)
	}
	priv, err := DecryptPrivateKey(blob, s.importPassphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt SPACE_IDENTITY_IMPORT (wrong passphrase?): %w", err)
	}
	if !bytes.Equal(blob.PublicKey, pubOf(priv)) {
		return nil, fmt.Errorf("SPACE_IDENTITY_IMPORT is corrupted: decrypted private key does not match the blob's public key")
	}
	return priv, nil
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
