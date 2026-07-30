package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestValidateJWT_ShouldRejectRevokedDevice(t *testing.T) {
	// given
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	repo := newDeviceTestRepo()
	repo.accounts["account-1"] = &User{PublicKey: "account-1", Username: "alice", Role: RoleUser}
	revokedAt := time.Now().Unix()
	repo.devices["device-1"] = &Device{DevicePublicKey: "device-1", UserPublicKey: "account-1", RevokedAt: &revokedAt}

	svc := NewUserService(repo, nil, Config{JWTExpirationHours: 24}, priv, pub)
	token, _, err := svc.GenerateJWT(repo.accounts["account-1"], "device-1")
	assert.NoError(t, err)

	// when
	user, err := svc.ValidateJWT(token)

	// then
	assert.Error(t, err)
	assert.Nil(t, user)
}

func TestValidateJWT_ShouldAcceptLegacyTokenWithEmptyDevicePublicKeyClaim(t *testing.T) {
	// given: a token with no devicePublicKey claim, as minted before the
	// device roster existed. Device #1's key equals the account key
	// (backfilled by migration 000018), so the fallback in ValidateJWT
	// should resolve and accept it.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	repo := newDeviceTestRepo()
	repo.accounts["account-1"] = &User{PublicKey: "account-1", Username: "alice", Role: RoleUser}
	repo.devices["account-1"] = &Device{DevicePublicKey: "account-1", UserPublicKey: "account-1"}

	claims := JWTClaims{
		UserPublicKey: "account-1",
		Username:      "alice",
		Role:          RoleUser,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(priv)
	assert.NoError(t, err)

	svc := NewUserService(repo, nil, Config{JWTExpirationHours: 24}, priv, pub)

	// when
	user, err := svc.ValidateJWT(signed)

	// then
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "account-1", user.DevicePublicKey)
}
