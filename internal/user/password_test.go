package user

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeUsername_ShouldTrimWhitespace(t *testing.T) {
	// when
	got, err := NormalizeUsername("  Alice  ")

	// then
	assert.NoError(t, err)
	assert.Equal(t, "Alice", got)
}

func TestNormalizeUsername_ShouldRejectEmpty(t *testing.T) {
	// when
	_, err := NormalizeUsername("   ")

	// then
	assert.Error(t, err)
}

func TestNormalizeUsername_ShouldRejectControlCharacters(t *testing.T) {
	// when
	_, err := NormalizeUsername("Alice\x00Bob")

	// then
	assert.Error(t, err)
}

func TestNormalizeUsername_ShouldAcceptExactly64Runes(t *testing.T) {
	// given
	name := strings.Repeat("a", 64)

	// when
	got, err := NormalizeUsername(name)

	// then
	assert.NoError(t, err)
	assert.Equal(t, name, got)
}

func TestNormalizeUsername_ShouldReject65Runes(t *testing.T) {
	// when
	_, err := NormalizeUsername(strings.Repeat("a", 65))

	// then
	assert.Error(t, err)
}

// TestNormalizeUsername_ShouldPreserveUnicodeAndInteriorSpaces covers the
// deliberate difference from the deleted identifier-shape validator: a
// username is a display name too, so multi-byte characters and interior
// spaces must survive normalization untouched, counted by rune (not byte).
func TestNormalizeUsername_ShouldPreserveUnicodeAndInteriorSpaces(t *testing.T) {
	// given
	name := "日本語 Name"

	// when
	got, err := NormalizeUsername(name)

	// then
	assert.NoError(t, err)
	assert.Equal(t, name, got)
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

func TestValidateEscrowBlob_ShouldAcceptEmptyBlob(t *testing.T) {
	// when
	err := validateEscrowBlob("", maxAccountKeyBlobLen)

	// then
	assert.NoError(t, err)
}

func TestValidateEscrowBlob_ShouldAcceptValidBase64WithinCap(t *testing.T) {
	// given
	blob := base64.StdEncoding.EncodeToString([]byte("sealed-account-key-seed"))

	// when
	err := validateEscrowBlob(blob, maxAccountKeyBlobLen)

	// then
	assert.NoError(t, err)
}

func TestValidateEscrowBlob_ShouldRejectNonBase64(t *testing.T) {
	// when
	err := validateEscrowBlob("not-valid-base64!!", maxAccountKeyBlobLen)

	// then
	assert.ErrorIs(t, err, ErrInvalidEscrowBlob)
}

func TestValidateEscrowBlob_ShouldRejectBlobExceedingMaxLen(t *testing.T) {
	// given - valid base64, but longer than the cap
	oversized := base64.StdEncoding.EncodeToString(make([]byte, maxAccountKeyBlobLen))

	// when
	err := validateEscrowBlob(oversized, maxAccountKeyBlobLen-1)

	// then
	assert.ErrorIs(t, err, ErrInvalidEscrowBlob)
}
