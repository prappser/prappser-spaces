package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// deviceTestRepo is a UserRepository stub for device endpoint tests. Devices,
// accounts, and password credentials are pre-seeded directly into the maps
// by each test.
type deviceTestRepo struct {
	devices     map[string]*Device
	accounts    map[string]*User
	credentials map[string]struct{ userPublicKey, verifier string } // keyed by normalized identifier
}

func newDeviceTestRepo() *deviceTestRepo {
	return &deviceTestRepo{
		devices:     map[string]*Device{},
		accounts:    map[string]*User{},
		credentials: map[string]struct{ userPublicKey, verifier string }{},
	}
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

func (r *deviceTestRepo) SetPasswordCredentials(publicKey, identifier, passwordVerifier string) error {
	r.credentials[identifier] = struct{ userPublicKey, verifier string }{publicKey, passwordVerifier}
	return nil
}
func (r *deviceTestRepo) GetPasswordCredential(identifier string) (string, string, error) {
	cred := r.credentials[identifier]
	return cred.userPublicKey, cred.verifier, nil
}

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
			de := NewDeviceEndpoints(repo, nil)
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
	de := NewDeviceEndpoints(repo, nil)

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
	de := NewDeviceEndpoints(repo, nil)

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
	de := NewDeviceEndpoints(repo, nil)

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/users/devices?devicePublicKey=device-other")
	ctx.SetUserValue("user", &User{PublicKey: "account-1", DevicePublicKey: "device-current"})

	// when
	de.RevokeDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNoContent, ctx.Response.StatusCode())
	assert.NotNil(t, repo.devices["device-other"].RevokedAt)
}

// newRegisterDeviceRequestCtx marshals body as the POST /users/devices
// request and returns a ready-to-dispatch context.
func newRegisterDeviceRequestCtx(t *testing.T, body registerDeviceRequest) *fasthttp.RequestCtx {
	t.Helper()
	b, err := json.Marshal(body)
	assert.NoError(t, err)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.SetBody(b)
	return ctx
}

// validNewDevicePublicKey is a syntactically valid (32 std-base64-encoded
// bytes) device public key for RegisterDevice tests that don't care about
// its actual Ed25519 validity.
func validNewDevicePublicKey() string {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return base64.StdEncoding.EncodeToString(pub)
}

// seedPasswordCredential registers a password credential for account
// "account-1" under identifier, returning the plaintext authSecret a caller
// can present to authenticate as it.
func seedPasswordCredential(t *testing.T, repo *deviceTestRepo, verifierKey []byte, identifier string) (authSecret string) {
	t.Helper()
	secretBytes := make([]byte, 32)
	_, err := rand.Read(secretBytes)
	assert.NoError(t, err)
	authSecret = base64.StdEncoding.EncodeToString(secretBytes)

	verifier, err := hashAuthSecret(verifierKey, authSecret)
	assert.NoError(t, err)

	repo.accounts["account-1"] = &User{PublicKey: "account-1", Username: "alice", Role: RoleUser}
	assert.NoError(t, repo.SetPasswordCredentials("account-1", identifier, verifier))
	return authSecret
}

func TestRegisterDevice_ShouldEnrollWithValidPasswordCredential(t *testing.T) {
	// given
	verifierKey := []byte("test-verifier-key")
	repo := newDeviceTestRepo()
	authSecret := seedPasswordCredential(t, repo, verifierKey, "alice")
	de := NewDeviceEndpoints(repo, verifierKey)

	ctx := newRegisterDeviceRequestCtx(t, registerDeviceRequest{
		Identifier:      "alice",
		AuthSecret:      authSecret,
		DevicePublicKey: validNewDevicePublicKey(),
	})

	// when
	de.RegisterDevice(ctx)

	// then - same response shape as the delegation path: 201, account fields populated
	assert.Equal(t, fasthttp.StatusCreated, ctx.Response.StatusCode())
	var resp registerDeviceResponse
	assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	assert.Equal(t, "account-1", resp.UserPublicKey)
	assert.Equal(t, "alice", resp.Username)
}

func TestRegisterDevice_ShouldReturn401ForWrongAuthSecret(t *testing.T) {
	// given
	verifierKey := []byte("test-verifier-key")
	repo := newDeviceTestRepo()
	seedPasswordCredential(t, repo, verifierKey, "alice")
	de := NewDeviceEndpoints(repo, verifierKey)

	wrongSecretBytes := make([]byte, 32)
	ctx := newRegisterDeviceRequestCtx(t, registerDeviceRequest{
		Identifier:      "alice",
		AuthSecret:      base64.StdEncoding.EncodeToString(wrongSecretBytes),
		DevicePublicKey: validNewDevicePublicKey(),
	})

	// when
	de.RegisterDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}

// TestRegisterDevice_ShouldReturn401WithByteIdenticalBodyForUnknownIdentifier
// is the anti-enumeration test for the password enroll path: an unknown
// identifier and a wrong password for a real identifier must be
// indistinguishable from the response alone.
func TestRegisterDevice_ShouldReturn401WithByteIdenticalBodyForUnknownIdentifier(t *testing.T) {
	// given
	verifierKey := []byte("test-verifier-key")
	repo := newDeviceTestRepo()
	seedPasswordCredential(t, repo, verifierKey, "alice")
	de := NewDeviceEndpoints(repo, verifierKey)

	wrongSecretBytes := make([]byte, 32)
	wrongPasswordCtx := newRegisterDeviceRequestCtx(t, registerDeviceRequest{
		Identifier:      "alice",
		AuthSecret:      base64.StdEncoding.EncodeToString(wrongSecretBytes),
		DevicePublicKey: validNewDevicePublicKey(),
	})
	unknownIdentifierCtx := newRegisterDeviceRequestCtx(t, registerDeviceRequest{
		Identifier:      "does-not-exist",
		AuthSecret:      base64.StdEncoding.EncodeToString(wrongSecretBytes),
		DevicePublicKey: validNewDevicePublicKey(),
	})

	// when
	de.RegisterDevice(wrongPasswordCtx)
	de.RegisterDevice(unknownIdentifierCtx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, wrongPasswordCtx.Response.StatusCode())
	assert.Equal(t, fasthttp.StatusUnauthorized, unknownIdentifierCtx.Response.StatusCode())
	assert.Equal(t, wrongPasswordCtx.Response.Body(), unknownIdentifierCtx.Response.Body())
}

func TestRegisterDevice_ShouldReturn400WhenBothCredentialsPresent(t *testing.T) {
	// given
	de := NewDeviceEndpoints(newDeviceTestRepo(), []byte("test-verifier-key"))
	ctx := newRegisterDeviceRequestCtx(t, registerDeviceRequest{
		Delegation:      "some-delegation-jws",
		Identifier:      "alice",
		AuthSecret:      base64.StdEncoding.EncodeToString(make([]byte, 32)),
		DevicePublicKey: validNewDevicePublicKey(),
	})

	// when
	de.RegisterDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestRegisterDevice_ShouldReturn400WhenIdentifierWithoutAuthSecret(t *testing.T) {
	// given
	de := NewDeviceEndpoints(newDeviceTestRepo(), []byte("test-verifier-key"))
	ctx := newRegisterDeviceRequestCtx(t, registerDeviceRequest{
		Identifier:      "alice",
		DevicePublicKey: validNewDevicePublicKey(),
	})

	// when
	de.RegisterDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestRegisterDevice_ShouldReturn400WhenNeitherCredentialPresent(t *testing.T) {
	// given
	de := NewDeviceEndpoints(newDeviceTestRepo(), []byte("test-verifier-key"))
	ctx := newRegisterDeviceRequestCtx(t, registerDeviceRequest{
		DevicePublicKey: validNewDevicePublicKey(),
	})

	// when
	de.RegisterDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}
