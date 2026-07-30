package user

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeIdentifier_ShouldAcceptValidIdentifiers(t *testing.T) {
	// given
	valid := []string{"alice", "  Alice  ", "ALICE123", "a1_2.3+4@5-6", "abc"}

	for _, raw := range valid {
		// when
		normalized, err := NormalizeIdentifier(raw)

		// then
		assert.NoError(t, err, "expected %q to be accepted", raw)
		assert.NotEmpty(t, normalized)
	}
}

func TestNormalizeIdentifier_ShouldLowercaseAndTrim(t *testing.T) {
	// when
	normalized, err := NormalizeIdentifier("  AliCe  ")

	// then
	assert.NoError(t, err)
	assert.Equal(t, "alice", normalized)
}

func TestNormalizeIdentifier_ShouldRejectInvalidIdentifiers(t *testing.T) {
	// given
	invalid := []string{
		"",                      // empty
		"ab",                    // too short (min 3 chars)
		"_abc",                  // must start with alnum
		"-abc",                  // must start with alnum
		"has space",             // space not allowed
		"has/slash",             // slash not allowed
		strings.Repeat("a", 65), // exceeds max length (64)
	}

	for _, raw := range invalid {
		// when
		normalized, err := NormalizeIdentifier(raw)

		// then
		assert.ErrorIs(t, err, ErrInvalidIdentifier, "expected %q to be rejected", raw)
		assert.Empty(t, normalized)
	}
}

func TestDeterministicSalt_ShouldBeDeterministicForSameInput(t *testing.T) {
	// given
	secret := []byte("secret-1")

	// when
	salt1 := deterministicSalt(secret, "alice")
	salt2 := deterministicSalt(secret, "alice")

	// then
	assert.Equal(t, salt1, salt2)
	assert.Len(t, salt1, 32)
}

func TestDeterministicSalt_ShouldDifferPerIdentifier(t *testing.T) {
	// given
	secret := []byte("secret-1")

	// when
	saltAlice := deterministicSalt(secret, "alice")
	saltBob := deterministicSalt(secret, "bob")

	// then
	assert.NotEqual(t, saltAlice, saltBob)
}

func TestDeterministicSalt_ShouldDifferPerSecret(t *testing.T) {
	// when
	saltA := deterministicSalt([]byte("secret-a"), "alice")
	saltB := deterministicSalt([]byte("secret-b"), "alice")

	// then
	assert.NotEqual(t, saltA, saltB)
}

func randomAuthSecret(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	_, err := rand.Read(b)
	assert.NoError(t, err)
	return base64.StdEncoding.EncodeToString(b)
}

func TestHashAuthSecretAndVerifyAuthSecret_ShouldRoundTrip(t *testing.T) {
	// given
	verifierKey := []byte("verifier-key")
	authSecret := randomAuthSecret(t)

	// when
	stored, err := hashAuthSecret(verifierKey, authSecret)
	assert.NoError(t, err)

	// then
	assert.True(t, verifyAuthSecret(verifierKey, stored, authSecret))
}

func TestVerifyAuthSecret_ShouldReturnFalseForWrongVerifierKey(t *testing.T) {
	// given
	authSecret := randomAuthSecret(t)
	stored, err := hashAuthSecret([]byte("verifier-key-1"), authSecret)
	assert.NoError(t, err)

	// when
	ok := verifyAuthSecret([]byte("verifier-key-2"), stored, authSecret)

	// then
	assert.False(t, ok)
}

func TestVerifyAuthSecret_ShouldReturnFalseForMalformedStoredValue(t *testing.T) {
	// given
	verifierKey := []byte("verifier-key")
	authSecret := randomAuthSecret(t)

	// when / then
	assert.False(t, verifyAuthSecret(verifierKey, "not-a-valid-scheme", authSecret))
	assert.False(t, verifyAuthSecret(verifierKey, "hmac-sha256$not-valid-base64!!", authSecret))
	assert.False(t, verifyAuthSecret(verifierKey, "", authSecret))
}

func TestVerifyAuthSecret_ShouldReturnFalseForMalformedAuthSecret(t *testing.T) {
	// given
	verifierKey := []byte("verifier-key")
	stored, err := hashAuthSecret(verifierKey, randomAuthSecret(t))
	assert.NoError(t, err)

	// when / then
	assert.False(t, verifyAuthSecret(verifierKey, stored, "not-valid-base64!!"))
	assert.False(t, verifyAuthSecret(verifierKey, stored, base64.StdEncoding.EncodeToString([]byte("too-short"))))
}

func TestHashAuthSecret_ShouldFailForMalformedAuthSecret(t *testing.T) {
	// given
	verifierKey := []byte("verifier-key")

	// when / then
	_, err := hashAuthSecret(verifierKey, "not-valid-base64!!")
	assert.ErrorIs(t, err, ErrInvalidAuthSecret)

	_, err = hashAuthSecret(verifierKey, base64.StdEncoding.EncodeToString([]byte("too-short")))
	assert.ErrorIs(t, err, ErrInvalidAuthSecret)
}

func TestDerivePasswordSecrets_ShouldProduceDistinct32ByteKeys(t *testing.T) {
	// given
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	assert.NoError(t, err)

	// when
	saltSecret, verifierKey := DerivePasswordSecrets(seed)

	// then
	assert.Len(t, saltSecret, 32)
	assert.Len(t, verifierKey, 32)
	assert.NotEqual(t, saltSecret, verifierKey)
}

func TestDerivePasswordSecrets_ShouldBeDeterministicForSameSeed(t *testing.T) {
	// given
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	assert.NoError(t, err)

	// when
	saltSecret1, verifierKey1 := DerivePasswordSecrets(seed)
	saltSecret2, verifierKey2 := DerivePasswordSecrets(seed)

	// then
	assert.Equal(t, saltSecret1, saltSecret2)
	assert.Equal(t, verifierKey1, verifierKey2)
}
