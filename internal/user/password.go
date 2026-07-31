package user

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/hkdf"
)

// ErrInvalidIdentifier is returned when a supplied identifier fails the
// shape check in NormalizeIdentifier.
var ErrInvalidIdentifier = errors.New("invalid identifier")

// ErrInvalidAuthSecret is returned when a supplied authSecret is not valid
// std-base64 of exactly 32 bytes.
var ErrInvalidAuthSecret = errors.New("invalid auth secret")

// ErrInvalidEscrowBlob is returned when a supplied escrow blob (accountKeyBlob
// or userState) is not valid std-base64, or exceeds the size cap for its kind.
var ErrInvalidEscrowBlob = errors.New("invalid escrow blob")

// maxAccountKeyBlobLen and maxUserStateBlobLen cap the base64 length of the
// two escrow blobs SetPassword accepts. accountKeyBlob wraps a fixed 32-byte
// seed (small; 512 std-base64 chars gives generous AEAD-framing headroom).
// userState wraps an arbitrary-size JSON document (space list + preferences),
// capped at 64KiB to keep a misbehaving client from writing an unbounded row.
const (
	maxAccountKeyBlobLen = 512
	maxUserStateBlobLen  = 64 * 1024
)

var identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._+@-]{2,63}$`)

// validateEscrowBlob checks that blob is valid std-base64 and does not exceed
// maxLen. An empty blob is always valid - it is the signal to CLEAR the
// corresponding escrow column (see user_repository.go's SetPasswordCredentials).
func validateEscrowBlob(blob string, maxLen int) error {
	if blob == "" {
		return nil
	}
	if len(blob) > maxLen {
		return fmt.Errorf("%w: exceeds max length %d", ErrInvalidEscrowBlob, maxLen)
	}
	if _, err := base64.StdEncoding.DecodeString(blob); err != nil {
		return fmt.Errorf("%w: not valid base64", ErrInvalidEscrowBlob)
	}
	return nil
}

// verifierScheme prefixes every stored password_verifier value, naming the
// algorithm so a future scheme change can coexist with old rows.
const verifierScheme = "hmac-sha256"

const (
	saltSecretInfo  = "prappser/salt/v1"
	verifierKeyInfo = "prappser/verifier/v1"
)

// NormalizeIdentifier trims and lowercases a user-supplied login identifier
// and validates its shape. Normalization must happen before every use of an
// identifier (salt derivation, storage, lookup) so the same human-entered
// value always resolves to the same account regardless of case or
// surrounding whitespace.
func NormalizeIdentifier(raw string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if !identifierPattern.MatchString(normalized) {
		return "", fmt.Errorf("%w: identifier must match %s", ErrInvalidIdentifier, identifierPattern.String())
	}
	return normalized, nil
}

// deterministicSalt derives a per-identifier salt as HMAC-SHA256(secret,
// normalized identifier). Deterministic on purpose: GetSalt must return the
// same salt for the same identifier on every call, with no database lookup,
// so it can answer identically for a real account and an unknown one (see
// password_endpoints.go's GetSalt).
func deterministicSalt(secret []byte, identifier string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(identifier))
	return mac.Sum(nil)
}

// hashAuthSecret computes the value stored in users.password_verifier for a
// client-derived authSecret (itself the output of a client-side Argon2id KDF
// over the user's password). authSecret must be std-base64 of exactly 32
// bytes.
//
// The verifier is a keyed HMAC, not a second round of Argon2id. authSecret
// is already the output of the client's Argon2id KDF, so it carries the
// password's entropy - hashing it again with Argon2id server-side would
// spend ~16MiB of memory per request on an endpoint (POST /users/devices'
// password path) that is unauthenticated by construction, handing an
// attacker a cheap memory-exhaustion lever. A keyed HMAC needs no per-request
// memory budget and is secure here specifically because the input already
// has full KDF-derived entropy - it would NOT be an adequate substitute for
// Argon2id if the input were a raw low-entropy password.
func hashAuthSecret(verifierKey []byte, authSecret string) (string, error) {
	secretBytes, err := base64.StdEncoding.DecodeString(authSecret)
	if err != nil || len(secretBytes) != 32 {
		return "", fmt.Errorf("%w: authSecret must be 32 std-base64-encoded bytes", ErrInvalidAuthSecret)
	}
	mac := hmac.New(sha256.New, verifierKey)
	mac.Write(secretBytes)
	return verifierScheme + "$" + base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// verifyAuthSecret recomputes the HMAC over authSecret and compares it
// against stored in constant time. It returns false (never an error) for a
// malformed stored value or a malformed authSecret, so a caller can treat
// "wrong password", "unknown identifier", and "corrupted verifier row"
// identically without a type switch. HMAC-SHA256 over the fixed-length
// 32-byte input runs in uniform time regardless of whether the MAC matches,
// so no dummy-verifier computation is needed to avoid a timing side channel
// on unknown identifiers.
func verifyAuthSecret(verifierKey []byte, stored, authSecret string) bool {
	scheme, encodedMAC, ok := strings.Cut(stored, "$")
	if !ok || scheme != verifierScheme {
		return false
	}
	storedMAC, err := base64.StdEncoding.DecodeString(encodedMAC)
	if err != nil {
		return false
	}
	secretBytes, err := base64.StdEncoding.DecodeString(authSecret)
	if err != nil || len(secretBytes) != 32 {
		return false
	}
	mac := hmac.New(sha256.New, verifierKey)
	mac.Write(secretBytes)
	return subtle.ConstantTimeCompare(storedMAC, mac.Sum(nil)) == 1
}

// DerivePasswordSecrets derives the two HMAC keys used by the password-login
// scheme (salt derivation and verifier hashing) from the space's Ed25519
// private key seed via HKDF-SHA256, using distinct info labels so the two
// keys are independent even though they share the same input seed. Exported
// for main.go, which derives these once at startup and threads them into
// PasswordEndpoints and DeviceEndpoints.
//
// Rotating the space keypair invalidates every password credential: both
// derived secrets change, so previously stored password_verifier values no
// longer verify and previously issued salts no longer match what a client
// would derive against the new salt secret. There is no migration path for
// this - a keypair rotation requires every account to re-set its password.
func DerivePasswordSecrets(seed []byte) (saltSecret, verifierKey []byte) {
	return deriveHKDFKey(seed, saltSecretInfo), deriveHKDFKey(seed, verifierKeyInfo)
}

// deriveHKDFKey expands a 32-byte HKDF-SHA256 key from seed under info. The
// expansion can only fail if the requested length exceeds HKDF-SHA256's
// maximum output (255 * 32 bytes) - unreachable for a fixed 32-byte read, so
// a failure here would indicate a broken hkdf implementation rather than bad
// input.
func deriveHKDFKey(seed []byte, info string) []byte {
	key := make([]byte, 32)
	kdf := hkdf.New(sha256.New, seed, nil, []byte(info))
	if _, err := io.ReadFull(kdf, key); err != nil {
		log.Error().Err(err).Msg("[PASSWORD] HKDF expand failed unexpectedly")
	}
	return key
}
