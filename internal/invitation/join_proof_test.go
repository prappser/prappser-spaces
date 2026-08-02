package invitation

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestVerifyJoinProof_ShouldAcceptFreshProof(t *testing.T) {
	// given
	_, devicePriv, deviceB64 := generateDeviceKey(t)
	now := time.Now()
	proof := buildJoinProof(t, devicePriv, "account-pk", deviceB64, "alice", "invite-1", now.Unix())

	// when
	claims, err := verifyJoinProof(proof, "invite-1", now)

	// then
	assert.NoError(t, err)
	assert.Equal(t, "account-pk", claims.PublicKey)
	assert.Equal(t, deviceB64, claims.DevicePublicKey)
	assert.Equal(t, "alice", claims.Username)
	assert.Equal(t, "invite-1", claims.InviteID)
}

func TestVerifyJoinProof_ShouldRejectProofSignedByAnotherKey(t *testing.T) {
	// given: claims name deviceB64 as the signer, but the JWS is actually
	// signed by an unrelated key.
	_, _, deviceB64 := generateDeviceKey(t)
	_, otherPriv, _ := generateDeviceKey(t)
	now := time.Now()
	proof := buildJoinProof(t, otherPriv, "account-pk", deviceB64, "alice", "invite-1", now.Unix())

	// when
	claims, err := verifyJoinProof(proof, "invite-1", now)

	// then
	assert.ErrorIs(t, err, ErrInvalidProof)
	assert.Nil(t, claims)
}

func TestVerifyJoinProof_ShouldRejectStaleIat(t *testing.T) {
	// given: iat older than joinProofTTLSec (60s) + joinProofSkewSec (30s)
	_, devicePriv, deviceB64 := generateDeviceKey(t)
	now := time.Now()
	staleIat := now.Add(-2 * time.Minute).Unix()
	proof := buildJoinProof(t, devicePriv, "account-pk", deviceB64, "alice", "invite-1", staleIat)

	// when
	claims, err := verifyJoinProof(proof, "invite-1", now)

	// then
	assert.ErrorIs(t, err, ErrInvalidProof)
	assert.Nil(t, claims)
}

func TestVerifyJoinProof_ShouldRejectMismatchedInviteID(t *testing.T) {
	// given
	_, devicePriv, deviceB64 := generateDeviceKey(t)
	now := time.Now()
	proof := buildJoinProof(t, devicePriv, "account-pk", deviceB64, "alice", "invite-1", now.Unix())

	// when: verified against a DIFFERENT invite than the one it was minted for
	claims, err := verifyJoinProof(proof, "invite-2", now)

	// then
	assert.ErrorIs(t, err, ErrInvalidProof)
	assert.Nil(t, claims)
}

func TestVerifyJoinProof_ShouldRejectMissingClaims(t *testing.T) {
	_, devicePriv, deviceB64 := generateDeviceKey(t)
	now := time.Now()

	tests := []struct {
		name            string
		publicKey       string
		devicePublicKey string
		username        string
		inviteID        string
	}{
		{"missing publicKey", "", deviceB64, "alice", "invite-1"},
		{"missing devicePublicKey", "account-pk", "", "alice", "invite-1"},
		{"missing username", "account-pk", deviceB64, "", "invite-1"},
		{"missing inviteId", "account-pk", deviceB64, "alice", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proof := buildJoinProof(t, devicePriv, tc.publicKey, tc.devicePublicKey, tc.username, tc.inviteID, now.Unix())
			claims, err := verifyJoinProof(proof, "invite-1", now)
			assert.ErrorIs(t, err, ErrInvalidProof)
			assert.Nil(t, claims)
		})
	}
}

func TestVerifyJoinProof_ShouldRejectNonEdDSAAlgorithm(t *testing.T) {
	// given: HS256 alg-confusion attempt - even if an attacker could obtain
	// the device key's base64 string as an HMAC secret, the EdDSA-only
	// keyfunc rejects the method before ever comparing the signature.
	_, _, deviceB64 := generateDeviceKey(t)
	now := time.Now()
	claims := jwt.MapClaims{
		"publicKey":       "account-pk",
		"devicePublicKey": deviceB64,
		"username":        "alice",
		"inviteId":        "invite-1",
		"iat":             now.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte("secret"))
	assert.NoError(t, err)

	// when
	result, err := verifyJoinProof(signed, "invite-1", now)

	// then
	assert.ErrorIs(t, err, ErrInvalidProof)
	assert.Nil(t, result)
}
