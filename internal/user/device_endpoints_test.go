package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// deviceTestRepo is a UserRepository stub for device endpoint tests. Devices
// and accounts are pre-seeded directly into the maps by each test.
type deviceTestRepo struct {
	devices  map[string]*Device
	accounts map[string]*User
}

func newDeviceTestRepo() *deviceTestRepo {
	return &deviceTestRepo{devices: map[string]*Device{}, accounts: map[string]*User{}}
}

func (r *deviceTestRepo) CreateUser(u *User) error { return nil }
func (r *deviceTestRepo) GetUserByPublicKey(publicKey string) (*User, error) {
	return r.accounts[publicKey], nil
}
func (r *deviceTestRepo) GetUserByUsername(username string) (*User, error) { return nil, nil }
func (r *deviceTestRepo) UpdateUserRole(publicKey, role string) error      { return nil }
func (r *deviceTestRepo) UpdateAvatarStorageID(publicKey string, avatarStorageID *string) error {
	return nil
}
func (r *deviceTestRepo) UpdateUsername(publicKey, username string) error { return nil }

func (r *deviceTestRepo) EnsureDevice(devicePublicKey, userPublicKey string, deviceName *string, createdAt int64) error {
	if _, exists := r.devices[devicePublicKey]; exists {
		return nil
	}
	r.devices[devicePublicKey] = &Device{
		DevicePublicKey: devicePublicKey,
		UserPublicKey:   userPublicKey,
		DeviceName:      deviceName,
		CreatedAt:       createdAt,
	}
	return nil
}
func (r *deviceTestRepo) GetDevice(devicePublicKey string) (*Device, error) {
	return r.devices[devicePublicKey], nil
}
func (r *deviceTestRepo) ListDevices(userPublicKey string) ([]*Device, error) {
	var out []*Device
	for _, d := range r.devices {
		if d.UserPublicKey == userPublicKey && d.RevokedAt == nil {
			out = append(out, d)
		}
	}
	return out, nil
}
func (r *deviceTestRepo) RevokeDevice(devicePublicKey string, ts int64) error {
	if d, ok := r.devices[devicePublicKey]; ok {
		revokedAt := ts
		d.RevokedAt = &revokedAt
	}
	return nil
}
func (r *deviceTestRepo) TouchDeviceLastSeen(devicePublicKey string, ts int64) error { return nil }

// buildDelegationJWS signs a delegation payload with signerPriv using the
// given signing method (EdDSA for valid delegations, something else to
// exercise the alg check).
func buildDelegationJWS(t *testing.T, method jwt.SigningMethod, signKey interface{}, issuer, jti string, iat, exp int64) string {
	t.Helper()
	claims := jwt.MapClaims{"iss": issuer, "jti": jti, "iat": iat, "exp": exp}
	token := jwt.NewWithClaims(method, claims)
	signed, err := token.SignedString(signKey)
	assert.NoError(t, err)
	return signed
}

func TestVerifyDelegation(t *testing.T) {
	now := time.Now().Unix()

	signerPub, signerPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	signerKeyB64 := base64.StdEncoding.EncodeToString(signerPub)

	otherPub, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	_ = otherPub

	newRepo := func() *deviceTestRepo {
		repo := newDeviceTestRepo()
		repo.devices[signerKeyB64] = &Device{DevicePublicKey: signerKeyB64, UserPublicKey: "account-1", CreatedAt: now}
		return repo
	}

	tests := []struct {
		name    string
		build   func(repo *deviceTestRepo, de *DeviceEndpoints) string
		wantErr bool
	}{
		{
			name: "happy path",
			build: func(repo *deviceTestRepo, de *DeviceEndpoints) string {
				return buildDelegationJWS(t, jwt.SigningMethodEdDSA, signerPriv, signerKeyB64, "jti-1", now, now+300)
			},
			wantErr: false,
		},
		{
			name: "expired",
			build: func(repo *deviceTestRepo, de *DeviceEndpoints) string {
				return buildDelegationJWS(t, jwt.SigningMethodEdDSA, signerPriv, signerKeyB64, "jti-2", now-1000, now-400)
			},
			wantErr: true,
		},
		{
			name: "exp-iat too long",
			build: func(repo *deviceTestRepo, de *DeviceEndpoints) string {
				return buildDelegationJWS(t, jwt.SigningMethodEdDSA, signerPriv, signerKeyB64, "jti-3", now, now+700)
			},
			wantErr: true,
		},
		{
			name: "wrong signer signature",
			build: func(repo *deviceTestRepo, de *DeviceEndpoints) string {
				// Signed by a different key than the one registered under signerKeyB64.
				return buildDelegationJWS(t, jwt.SigningMethodEdDSA, otherPriv, signerKeyB64, "jti-4", now, now+300)
			},
			wantErr: true,
		},
		{
			name: "revoked signer",
			build: func(repo *deviceTestRepo, de *DeviceEndpoints) string {
				revokedAt := now
				repo.devices[signerKeyB64].RevokedAt = &revokedAt
				return buildDelegationJWS(t, jwt.SigningMethodEdDSA, signerPriv, signerKeyB64, "jti-5", now, now+300)
			},
			wantErr: true,
		},
		{
			name: "replayed jti",
			build: func(repo *deviceTestRepo, de *DeviceEndpoints) string {
				jws := buildDelegationJWS(t, jwt.SigningMethodEdDSA, signerPriv, signerKeyB64, "jti-6", now, now+300)
				// Consume it once on the SAME endpoints instance the test will
				// re-verify against below - jti tracking is per-instance, so a
				// fresh instance wouldn't see it as replayed.
				_, err := de.verifyDelegation(jws)
				assert.NoError(t, err, "first use should succeed")
				return jws
			},
			wantErr: true,
		},
		{
			name: "alg not EdDSA",
			build: func(repo *deviceTestRepo, de *DeviceEndpoints) string {
				return buildDelegationJWS(t, jwt.SigningMethodHS256, []byte("secret"), signerKeyB64, "jti-7", now, now+300)
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newRepo()
			de := NewDeviceEndpoints(repo)
			jws := tc.build(repo, de)

			signer, err := de.verifyDelegation(jws)

			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, signer)
				assert.Equal(t, "account-1", signer.UserPublicKey)
			}
		})
	}
}

func TestRevokeDevice_ShouldReturn403WhenTargetIsCurrentDevice(t *testing.T) {
	// given
	repo := newDeviceTestRepo()
	repo.devices["device-current"] = &Device{DevicePublicKey: "device-current", UserPublicKey: "account-1"}
	de := NewDeviceEndpoints(repo)

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/users/devices?devicePublicKey=device-current")
	ctx.SetUserValue("user", &User{PublicKey: "account-1", DevicePublicKey: "device-current"})

	// when
	de.RevokeDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
}

func TestRevokeDevice_ShouldReturn404WhenNotOwnedByAuthenticatedAccount(t *testing.T) {
	// given
	repo := newDeviceTestRepo()
	repo.devices["device-other"] = &Device{DevicePublicKey: "device-other", UserPublicKey: "some-other-account"}
	de := NewDeviceEndpoints(repo)

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/users/devices?devicePublicKey=device-other")
	ctx.SetUserValue("user", &User{PublicKey: "account-1", DevicePublicKey: "device-current"})

	// when
	de.RevokeDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNotFound, ctx.Response.StatusCode())
}

func TestRevokeDevice_ShouldReturn204OnSuccess(t *testing.T) {
	// given
	repo := newDeviceTestRepo()
	repo.devices["device-other"] = &Device{DevicePublicKey: "device-other", UserPublicKey: "account-1"}
	de := NewDeviceEndpoints(repo)

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/users/devices?devicePublicKey=device-other")
	ctx.SetUserValue("user", &User{PublicKey: "account-1", DevicePublicKey: "device-current"})

	// when
	de.RevokeDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNoContent, ctx.Response.StatusCode())
	assert.NotNil(t, repo.devices["device-other"].RevokedAt)
}
