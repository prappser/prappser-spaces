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
	credentials map[string]struct{ userPublicKey, verifier string }   // keyed by normalized identifier
	escrow      map[string]struct{ accountKeyBlob, userState string } // keyed by account public key
}

func newDeviceTestRepo() *deviceTestRepo {
	return &deviceTestRepo{
		devices:     map[string]*Device{},
		accounts:    map[string]*User{},
		credentials: map[string]struct{ userPublicKey, verifier string }{},
		escrow:      map[string]struct{ accountKeyBlob, userState string }{},
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

func (r *deviceTestRepo) SetPasswordCredentials(publicKey, identifier, passwordVerifier, accountKeyBlob, userState string) error {
	r.credentials[identifier] = struct{ userPublicKey, verifier string }{publicKey, passwordVerifier}
	r.escrow[publicKey] = struct{ accountKeyBlob, userState string }{accountKeyBlob, userState}
	return nil
}
func (r *deviceTestRepo) GetPasswordCredential(identifier string) (string, string, error) {
	cred := r.credentials[identifier]
	return cred.userPublicKey, cred.verifier, nil
}
func (r *deviceTestRepo) GetEscrow(publicKey string) (string, string, error) {
	escrow := r.escrow[publicKey]
	return escrow.accountKeyBlob, escrow.userState, nil
}

// buildDelegationJWS signs a delegation payload with signerPriv using the
// given signing method (EdDSA for valid delegations, something else to
// exercise the alg check). dpk and aud are the delegation's target device
// and target space - empty strings omit that claim, to exercise the
// required-claim checks.
func buildDelegationJWS(t *testing.T, method jwt.SigningMethod, signKey interface{}, issuer, jti string, iat, exp int64, dpk, aud string) string {
	t.Helper()
	claims := jwt.MapClaims{"iss": issuer, "jti": jti, "iat": iat, "exp": exp}
	if dpk != "" {
		claims["dpk"] = dpk
	}
	if aud != "" {
		claims["aud"] = aud
	}
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

	const (
		enrollingDeviceKeyB64 = "enrolling-device-key"
		spacePublicKeyB64     = "this-space-key"
		wrongDeviceKeyB64     = "some-other-device-key"
		wrongSpaceKeyB64      = "some-other-space-key"
	)

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
				return buildDelegationJWS(t, jwt.SigningMethodEdDSA, signerPriv, signerKeyB64, "jti-1", now, now+300, enrollingDeviceKeyB64, spacePublicKeyB64)
			},
			wantErr: false,
		},
		{
			name: "expired",
			build: func(repo *deviceTestRepo, de *DeviceEndpoints) string {
				return buildDelegationJWS(t, jwt.SigningMethodEdDSA, signerPriv, signerKeyB64, "jti-2", now-1000, now-400, enrollingDeviceKeyB64, spacePublicKeyB64)
			},
			wantErr: true,
		},
		{
			name: "exp-iat too long",
			build: func(repo *deviceTestRepo, de *DeviceEndpoints) string {
				return buildDelegationJWS(t, jwt.SigningMethodEdDSA, signerPriv, signerKeyB64, "jti-3", now, now+700, enrollingDeviceKeyB64, spacePublicKeyB64)
			},
			wantErr: true,
		},
		{
			name: "wrong signer signature",
			build: func(repo *deviceTestRepo, de *DeviceEndpoints) string {
				// Signed by a different key than the one registered under signerKeyB64.
				return buildDelegationJWS(t, jwt.SigningMethodEdDSA, otherPriv, signerKeyB64, "jti-4", now, now+300, enrollingDeviceKeyB64, spacePublicKeyB64)
			},
			wantErr: true,
		},
		{
			name: "revoked signer",
			build: func(repo *deviceTestRepo, de *DeviceEndpoints) string {
				revokedAt := now
				repo.devices[signerKeyB64].RevokedAt = &revokedAt
				return buildDelegationJWS(t, jwt.SigningMethodEdDSA, signerPriv, signerKeyB64, "jti-5", now, now+300, enrollingDeviceKeyB64, spacePublicKeyB64)
			},
			wantErr: true,
		},
		{
			name: "replayed jti",
			build: func(repo *deviceTestRepo, de *DeviceEndpoints) string {
				jws := buildDelegationJWS(t, jwt.SigningMethodEdDSA, signerPriv, signerKeyB64, "jti-6", now, now+300, enrollingDeviceKeyB64, spacePublicKeyB64)
				// Consume it once on the SAME endpoints instance the test will
				// re-verify against below - jti tracking is per-instance, so a
				// fresh instance wouldn't see it as replayed.
				_, err := de.verifyDelegation(jws, enrollingDeviceKeyB64)
				assert.NoError(t, err, "first use should succeed")
				return jws
			},
			wantErr: true,
		},
		{
			name: "alg not EdDSA",
			build: func(repo *deviceTestRepo, de *DeviceEndpoints) string {
				return buildDelegationJWS(t, jwt.SigningMethodHS256, []byte("secret"), signerKeyB64, "jti-7", now, now+300, enrollingDeviceKeyB64, spacePublicKeyB64)
			},
			wantErr: true,
		},
		{
			// dpk is optional (QR/paste device-link flow mints its delegation
			// before the enrolling device's keypair exists) - a delegation
			// with no dpk claim but a valid aud must still be accepted.
			name: "missing dpk is accepted when aud is valid",
			build: func(repo *deviceTestRepo, de *DeviceEndpoints) string {
				return buildDelegationJWS(t, jwt.SigningMethodEdDSA, signerPriv, signerKeyB64, "jti-8", now, now+300, "", spacePublicKeyB64)
			},
			wantErr: false,
		},
		{
			name: "missing aud",
			build: func(repo *deviceTestRepo, de *DeviceEndpoints) string {
				return buildDelegationJWS(t, jwt.SigningMethodEdDSA, signerPriv, signerKeyB64, "jti-9", now, now+300, enrollingDeviceKeyB64, "")
			},
			wantErr: true,
		},
		{
			name: "wrong dpk",
			build: func(repo *deviceTestRepo, de *DeviceEndpoints) string {
				return buildDelegationJWS(t, jwt.SigningMethodEdDSA, signerPriv, signerKeyB64, "jti-10", now, now+300, wrongDeviceKeyB64, spacePublicKeyB64)
			},
			wantErr: true,
		},
		{
			name: "wrong aud",
			build: func(repo *deviceTestRepo, de *DeviceEndpoints) string {
				return buildDelegationJWS(t, jwt.SigningMethodEdDSA, signerPriv, signerKeyB64, "jti-11", now, now+300, enrollingDeviceKeyB64, wrongSpaceKeyB64)
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newRepo()
			de := NewDeviceEndpoints(repo, nil, spacePublicKeyB64)
			jws := tc.build(repo, de)

			signer, err := de.verifyDelegation(jws, enrollingDeviceKeyB64)

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
	de := NewDeviceEndpoints(repo, nil, "space-key")

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
	de := NewDeviceEndpoints(repo, nil, "space-key")

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
	de := NewDeviceEndpoints(repo, nil, "space-key")

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

// seedPasswordCredential registers a password credential (and, optionally,
// escrow blobs) for account "account-1" under identifier, returning the
// plaintext authSecret a caller can present to authenticate as it.
func seedPasswordCredential(t *testing.T, repo *deviceTestRepo, verifierKey []byte, identifier string, accountKeyBlob, userState string) (authSecret string) {
	t.Helper()
	secretBytes := make([]byte, 32)
	_, err := rand.Read(secretBytes)
	assert.NoError(t, err)
	authSecret = base64.StdEncoding.EncodeToString(secretBytes)

	verifier, err := hashAuthSecret(verifierKey, authSecret)
	assert.NoError(t, err)

	repo.accounts["account-1"] = &User{PublicKey: "account-1", Username: "alice", Role: RoleUser}
	assert.NoError(t, repo.SetPasswordCredentials("account-1", identifier, verifier, accountKeyBlob, userState))
	return authSecret
}

func TestRegisterDevice_ShouldEnrollWithValidPasswordCredential(t *testing.T) {
	// given
	verifierKey := []byte("test-verifier-key")
	repo := newDeviceTestRepo()
	authSecret := seedPasswordCredential(t, repo, verifierKey, "alice", "", "")
	de := NewDeviceEndpoints(repo, verifierKey, "space-key")

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
	seedPasswordCredential(t, repo, verifierKey, "alice", "", "")
	de := NewDeviceEndpoints(repo, verifierKey, "space-key")

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
	seedPasswordCredential(t, repo, verifierKey, "alice", "", "")
	de := NewDeviceEndpoints(repo, verifierKey, "space-key")

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
	de := NewDeviceEndpoints(newDeviceTestRepo(), []byte("test-verifier-key"), "space-key")
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
	de := NewDeviceEndpoints(newDeviceTestRepo(), []byte("test-verifier-key"), "space-key")
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
	de := NewDeviceEndpoints(newDeviceTestRepo(), []byte("test-verifier-key"), "space-key")
	ctx := newRegisterDeviceRequestCtx(t, registerDeviceRequest{
		DevicePublicKey: validNewDevicePublicKey(),
	})

	// when
	de.RegisterDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestRegisterDevice_ShouldReturnEscrowBlobsOnPasswordPath(t *testing.T) {
	// given
	verifierKey := []byte("test-verifier-key")
	repo := newDeviceTestRepo()
	accountKeyBlob := base64.StdEncoding.EncodeToString([]byte("sealed-account-key"))
	userState := base64.StdEncoding.EncodeToString([]byte("sealed-user-state"))
	authSecret := seedPasswordCredential(t, repo, verifierKey, "alice", accountKeyBlob, userState)
	de := NewDeviceEndpoints(repo, verifierKey, "space-key")

	ctx := newRegisterDeviceRequestCtx(t, registerDeviceRequest{
		Identifier:      "alice",
		AuthSecret:      authSecret,
		DevicePublicKey: validNewDevicePublicKey(),
	})

	// when
	de.RegisterDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusCreated, ctx.Response.StatusCode())
	var resp registerDeviceResponse
	assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	assert.Equal(t, accountKeyBlob, resp.AccountKeyBlob)
	assert.Equal(t, userState, resp.UserState)
}

// registerViaDelegation builds a valid delegation from an already-enrolled
// signer device to a fresh new device, and dispatches RegisterDevice with it
// - shared setup for the delegation-path RegisterDevice tests below.
func registerViaDelegation(t *testing.T, de *DeviceEndpoints, signerKeyB64 string, signerPriv ed25519.PrivateKey, newDeviceKeyB64, spacePublicKeyB64, jti string) *fasthttp.RequestCtx {
	t.Helper()
	now := time.Now().Unix()
	delegation := buildDelegationJWS(t, jwt.SigningMethodEdDSA, signerPriv, signerKeyB64, jti, now, now+300, newDeviceKeyB64, spacePublicKeyB64)
	ctx := newRegisterDeviceRequestCtx(t, registerDeviceRequest{
		Delegation:      delegation,
		DevicePublicKey: newDeviceKeyB64,
	})
	de.RegisterDevice(ctx)
	return ctx
}

// TestRegisterDevice_ShouldNotReturnEscrowBlobsOnDelegationPath is the
// byte-identical-response requirement from registerDeviceResponse's doc
// comment: even when the account HAS escrow blobs stored, the delegation
// path must not surface them - only the password path does.
func TestRegisterDevice_ShouldNotReturnEscrowBlobsOnDelegationPath(t *testing.T) {
	// given
	const spacePublicKeyB64 = "space-key"
	signerPub, signerPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	signerKeyB64 := base64.StdEncoding.EncodeToString(signerPub)

	repo := newDeviceTestRepo()
	repo.devices[signerKeyB64] = &Device{DevicePublicKey: signerKeyB64, UserPublicKey: "account-1", CreatedAt: time.Now().Unix()}
	repo.accounts["account-1"] = &User{PublicKey: "account-1", Username: "alice", Role: RoleUser}
	repo.escrow["account-1"] = struct{ accountKeyBlob, userState string }{
		base64.StdEncoding.EncodeToString([]byte("sealed-account-key")),
		base64.StdEncoding.EncodeToString([]byte("sealed-user-state")),
	}
	de := NewDeviceEndpoints(repo, nil, spacePublicKeyB64)

	// when
	ctx := registerViaDelegation(t, de, signerKeyB64, signerPriv, validNewDevicePublicKey(), spacePublicKeyB64, "jti-delegate-1")

	// then
	assert.Equal(t, fasthttp.StatusCreated, ctx.Response.StatusCode())
	var resp registerDeviceResponse
	assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	assert.Empty(t, resp.AccountKeyBlob)
	assert.Empty(t, resp.UserState)
}

// TestRegisterDevice_ShouldAcceptDelegationMissingDpk covers the QR/paste
// device-link flow: its delegation is minted before the enrolling device's
// keypair exists, so it never carries a dpk claim. aud alone must be enough
// to enroll successfully.
func TestRegisterDevice_ShouldAcceptDelegationMissingDpk(t *testing.T) {
	// given
	const spacePublicKeyB64 = "space-key"
	signerPub, signerPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	signerKeyB64 := base64.StdEncoding.EncodeToString(signerPub)

	repo := newDeviceTestRepo()
	repo.devices[signerKeyB64] = &Device{DevicePublicKey: signerKeyB64, UserPublicKey: "account-1", CreatedAt: time.Now().Unix()}
	repo.accounts["account-1"] = &User{PublicKey: "account-1", Username: "alice", Role: RoleUser}
	de := NewDeviceEndpoints(repo, nil, spacePublicKeyB64)
	newDeviceKeyB64 := validNewDevicePublicKey()
	now := time.Now().Unix()

	missingDpk := buildDelegationJWS(t, jwt.SigningMethodEdDSA, signerPriv, signerKeyB64, "jti-missing-dpk", now, now+300, "", spacePublicKeyB64)

	// when
	ctx := newRegisterDeviceRequestCtx(t, registerDeviceRequest{Delegation: missingDpk, DevicePublicKey: newDeviceKeyB64})
	de.RegisterDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusCreated, ctx.Response.StatusCode())
}

func TestRegisterDevice_ShouldReturn401ForDelegationMissingAud(t *testing.T) {
	// given
	const spacePublicKeyB64 = "space-key"
	signerPub, signerPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	signerKeyB64 := base64.StdEncoding.EncodeToString(signerPub)

	repo := newDeviceTestRepo()
	repo.devices[signerKeyB64] = &Device{DevicePublicKey: signerKeyB64, UserPublicKey: "account-1", CreatedAt: time.Now().Unix()}
	de := NewDeviceEndpoints(repo, nil, spacePublicKeyB64)
	newDeviceKeyB64 := validNewDevicePublicKey()
	now := time.Now().Unix()

	missingAud := buildDelegationJWS(t, jwt.SigningMethodEdDSA, signerPriv, signerKeyB64, "jti-missing-aud", now, now+300, newDeviceKeyB64, "")

	// when
	ctx := newRegisterDeviceRequestCtx(t, registerDeviceRequest{Delegation: missingAud, DevicePublicKey: newDeviceKeyB64})
	de.RegisterDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}

func TestRegisterDevice_ShouldReturn401ForDelegationWithWrongDpk(t *testing.T) {
	// given
	const spacePublicKeyB64 = "space-key"
	signerPub, signerPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	signerKeyB64 := base64.StdEncoding.EncodeToString(signerPub)

	repo := newDeviceTestRepo()
	repo.devices[signerKeyB64] = &Device{DevicePublicKey: signerKeyB64, UserPublicKey: "account-1", CreatedAt: time.Now().Unix()}
	de := NewDeviceEndpoints(repo, nil, spacePublicKeyB64)
	newDeviceKeyB64 := validNewDevicePublicKey()
	now := time.Now().Unix()

	// when - delegation minted for a DIFFERENT device than the one enrolling
	delegation := buildDelegationJWS(t, jwt.SigningMethodEdDSA, signerPriv, signerKeyB64, "jti-wrong-dpk", now, now+300, "wrong-device-key", spacePublicKeyB64)
	ctx := newRegisterDeviceRequestCtx(t, registerDeviceRequest{Delegation: delegation, DevicePublicKey: newDeviceKeyB64})
	de.RegisterDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}

func TestRegisterDevice_ShouldReturn401ForDelegationWithWrongAud(t *testing.T) {
	// given
	const spacePublicKeyB64 = "space-key"
	signerPub, signerPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	signerKeyB64 := base64.StdEncoding.EncodeToString(signerPub)

	repo := newDeviceTestRepo()
	repo.devices[signerKeyB64] = &Device{DevicePublicKey: signerKeyB64, UserPublicKey: "account-1", CreatedAt: time.Now().Unix()}
	de := NewDeviceEndpoints(repo, nil, spacePublicKeyB64)
	newDeviceKeyB64 := validNewDevicePublicKey()
	now := time.Now().Unix()

	// when - delegation minted for a DIFFERENT space than this one
	delegation := buildDelegationJWS(t, jwt.SigningMethodEdDSA, signerPriv, signerKeyB64, "jti-wrong-aud", now, now+300, newDeviceKeyB64, "some-other-space-key")
	ctx := newRegisterDeviceRequestCtx(t, registerDeviceRequest{Delegation: delegation, DevicePublicKey: newDeviceKeyB64})
	de.RegisterDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}
