package keys

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/goccy/go-json"
)

// identityBlobPrefix versions the export format used by
// POST /space/identity/export and SPACE_IDENTITY_IMPORT (see
// EncodeIdentityBlob). The version tag pins the KDF/cipher parameters -
// Argon2id + AES-GCM via EncryptPrivateKey/DecryptPrivateKey - so the blob
// itself never needs to carry them; a future format change gets a new
// prefix instead of a params field inside the payload.
const identityBlobPrefix = "PRAPSPACE1."

// identityBlobPayload is the exact JSON shape inside an identity export
// blob's base64url segment. It mirrors EncryptedKey's crypto fields only -
// LastSeenAt is deliberately absent so it can never leak into an export
// (see EncodeIdentityBlob).
type identityBlobPayload struct {
	Pub   string `json:"pub"`
	CT    string `json:"ct"`
	Salt  string `json:"salt"`
	Nonce string `json:"nonce"`
}

// EncodeIdentityBlob serializes enc into the PRAPSPACE1.<base64url-nopad>
// export format. Fields are written out explicitly rather than marshaling
// enc as a whole, so LastSeenAt can never leak into the export.
func EncodeIdentityBlob(enc *EncryptedKey) (string, error) {
	payload := identityBlobPayload{
		Pub:   base64.StdEncoding.EncodeToString(enc.PublicKey),
		CT:    base64.StdEncoding.EncodeToString(enc.EncryptedPrivateKey),
		Salt:  base64.StdEncoding.EncodeToString(enc.Salt),
		Nonce: base64.StdEncoding.EncodeToString(enc.Nonce),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal identity blob payload: %w", err)
	}
	return identityBlobPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// DecodeIdentityBlob parses a blob produced by EncodeIdentityBlob, rejecting
// a wrong prefix, malformed base64/JSON, or fields that don't match the
// pinned shapes: public key 32 bytes, salt SaltSize bytes, nonce NonceSize
// bytes, ciphertext nonempty.
func DecodeIdentityBlob(blob string) (*EncryptedKey, error) {
	if !strings.HasPrefix(blob, identityBlobPrefix) {
		return nil, fmt.Errorf("invalid identity blob: unrecognized prefix")
	}

	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(blob, identityBlobPrefix))
	if err != nil {
		return nil, fmt.Errorf("invalid identity blob: bad base64: %w", err)
	}

	var payload identityBlobPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("invalid identity blob: bad JSON: %w", err)
	}

	pub, err := base64.StdEncoding.DecodeString(payload.Pub)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid identity blob: publicKey must be %d bytes", ed25519.PublicKeySize)
	}
	ct, err := base64.StdEncoding.DecodeString(payload.CT)
	if err != nil || len(ct) == 0 {
		return nil, fmt.Errorf("invalid identity blob: ciphertext must be nonempty")
	}
	salt, err := base64.StdEncoding.DecodeString(payload.Salt)
	if err != nil || len(salt) != SaltSize {
		return nil, fmt.Errorf("invalid identity blob: salt must be %d bytes", SaltSize)
	}
	nonce, err := base64.StdEncoding.DecodeString(payload.Nonce)
	if err != nil || len(nonce) != NonceSize {
		return nil, fmt.Errorf("invalid identity blob: nonce must be %d bytes", NonceSize)
	}

	return &EncryptedKey{
		PublicKey:           ed25519.PublicKey(pub),
		EncryptedPrivateKey: ct,
		Salt:                salt,
		Nonce:               nonce,
	}, nil
}
