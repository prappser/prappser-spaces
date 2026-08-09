package keys

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIdentityBlob_RoundTripsThroughEncodeAndDecode covers the happy path:
// an EncryptedKey encoded by EncodeIdentityBlob decodes back to identical
// fields, and the underlying private key still decrypts correctly.
func TestIdentityBlob_RoundTripsThroughEncodeAndDecode(t *testing.T) {
	// given
	priv, pub, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	enc, err := EncryptPrivateKey(priv, "export-passphrase-1234")
	assert.NoError(t, err)

	// when
	blob, err := EncodeIdentityBlob(enc)
	assert.NoError(t, err)
	decoded, err := DecodeIdentityBlob(blob)

	// then
	assert.NoError(t, err)
	assert.True(t, strings.HasPrefix(blob, identityBlobPrefix))
	assert.Equal(t, []byte(pub), []byte(decoded.PublicKey))
	assert.Equal(t, enc.EncryptedPrivateKey, decoded.EncryptedPrivateKey)
	assert.Equal(t, enc.Salt, decoded.Salt)
	assert.Equal(t, enc.Nonce, decoded.Nonce)

	decryptedPriv, err := DecryptPrivateKey(decoded, "export-passphrase-1234")
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(decryptedPriv.Seed(), priv.Seed()))
}

// TestIdentityBlob_ContainsNoPlaintextSeedBytes guards against a future
// change accidentally embedding the raw private key seed in the blob -
// only ciphertext should ever appear.
func TestIdentityBlob_ContainsNoPlaintextSeedBytes(t *testing.T) {
	// given
	priv, _, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	enc, err := EncryptPrivateKey(priv, "export-passphrase-1234")
	assert.NoError(t, err)

	// when
	blob, err := EncodeIdentityBlob(enc)
	assert.NoError(t, err)

	// then
	assert.False(t, strings.Contains(blob, string(priv.Seed())), "blob must never contain the raw private key seed")
}

func TestDecodeIdentityBlob_ShouldErrorOnWrongPrefix(t *testing.T) {
	_, err := DecodeIdentityBlob("NOTPRAPSPACE1.abc")
	assert.Error(t, err)
}

func TestDecodeIdentityBlob_ShouldErrorOnBadBase64(t *testing.T) {
	_, err := DecodeIdentityBlob(identityBlobPrefix + "not-valid-base64!!!")
	assert.Error(t, err)
}

func TestDecodeIdentityBlob_ShouldErrorOnTruncatedJSON(t *testing.T) {
	_, err := DecodeIdentityBlob(identityBlobPrefix + "eyJwdWIiOiJhYmMi") // base64url of `{"pub":"abc"` (truncated)
	assert.Error(t, err)
}

func TestDecodeIdentityBlob_ShouldErrorOnWrongFieldSizes(t *testing.T) {
	// given - a well-formed envelope but with an undersized salt
	priv, _, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	enc, err := EncryptPrivateKey(priv, "export-passphrase-1234")
	assert.NoError(t, err)
	enc.Salt = enc.Salt[:16] // not SaltSize (32)
	blob, err := EncodeIdentityBlob(enc)
	assert.NoError(t, err)

	// when
	_, err = DecodeIdentityBlob(blob)

	// then
	assert.Error(t, err)
}

// TestDecryptPrivateKeyFromDecodedBlob_ShouldErrorOnWrongPassphrase covers
// the export/import contract that a decoded blob is still subject to the
// same wrong-passphrase check as any other EncryptedKey.
func TestDecryptPrivateKeyFromDecodedBlob_ShouldErrorOnWrongPassphrase(t *testing.T) {
	// given
	priv, _, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	enc, err := EncryptPrivateKey(priv, "correct-passphrase-1234")
	assert.NoError(t, err)
	blob, err := EncodeIdentityBlob(enc)
	assert.NoError(t, err)
	decoded, err := DecodeIdentityBlob(blob)
	assert.NoError(t, err)

	// when
	_, err = DecryptPrivateKey(decoded, "wrong-passphrase-1234")

	// then
	assert.Error(t, err)
}
