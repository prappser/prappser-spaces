package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// deviceTestRepo is a UserRepository stub for device endpoint tests. Devices,
// accounts, and password credentials are pre-seeded directly into the maps
// by each test. Verifier is a per-account column (verifiers keyed by public
// key, matching users.password_verifier);
// GetPasswordCredential joins against each account's CURRENT username live -
// the same way the real repository's query does - so a rename transparently
// carries a previously-set password forward (see
// TestRegisterDevice_ShouldEnrollWithPasswordSetBeforeRename below).
type deviceTestRepo struct {
	devices   map[string]*Device
	accounts  map[string]*User
	verifiers map[string]string                                     // keyed by public key
	escrow    map[string]struct{ accountKeyBlob, userState string } // keyed by public key
}

func newDeviceTestRepo() *deviceTestRepo {
	return &deviceTestRepo{
		devices:   map[string]*Device{},
		accounts:  map[string]*User{},
		verifiers: map[string]string{},
		escrow:    map[string]struct{ accountKeyBlob, userState string }{},
	}
}

func (r *deviceTestRepo) CreateUser(u *User) error {
	r.accounts[u.PublicKey] = u
	return nil
}
func (r *deviceTestRepo) GetUserByPublicKey(publicKey string) (*User, error) {
	return r.accounts[publicKey], nil
}
func (r *deviceTestRepo) UpdateUserRole(publicKey, role string) error { return nil }
func (r *deviceTestRepo) UpdateAvatarStorageID(publicKey string, avatarStorageID *string) error {
	return nil
}
func (r *deviceTestRepo) UpdateUsername(publicKey, username string) error {
	if account, ok := r.accounts[publicKey]; ok {
		account.Username = username
	}
	return nil
}
func (r *deviceTestRepo) UpdateUserIssuer(publicKey, issuer string) error { return nil }

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
func (r *deviceTestRepo) RenameDevice(devicePublicKey, deviceName string) error {
	if d, ok := r.devices[devicePublicKey]; ok {
		name := deviceName
		d.DeviceName = &name
	}
	return nil
}
func (r *deviceTestRepo) TouchDeviceLastSeen(devicePublicKey string, ts int64) error { return nil }

func (r *deviceTestRepo) SetPasswordCredentials(publicKey, passwordVerifier, handle, accountKeyBlob, userState string) error {
	if _, ok := r.accounts[publicKey]; !ok {
		return fmt.Errorf("no account for public key %s", publicKey)
	}
	r.verifiers[publicKey] = passwordVerifier
	r.escrow[publicKey] = struct{ accountKeyBlob, userState string }{accountKeyBlob, userState}
	return nil
}
func (r *deviceTestRepo) GetPasswordCredential(username string) (string, string, error) {
	for pk, account := range r.accounts {
		if r.verifiers[pk] != "" && strings.EqualFold(account.Username, username) {
			return pk, r.verifiers[pk], nil
		}
	}
	return "", "", nil
}
func (r *deviceTestRepo) GetPasswordHandle(username string) (string, error) {
	return "", nil
}
func (r *deviceTestRepo) GetEscrow(publicKey string) (string, string, error) {
	escrow := r.escrow[publicKey]
	return escrow.accountKeyBlob, escrow.userState, nil
}
func (r *deviceTestRepo) UpdateUserState(publicKey, userState string) error {
	escrow := r.escrow[publicKey]
	escrow.userState = userState
	r.escrow[publicKey] = escrow
	return nil
}
func (r *deviceTestRepo) ClaimOwner(publicKey, username, passwordVerifier, handle, accountKeyBlob, userState string, deviceName *string, createdAt int64) error {
	return nil
}
func (r *deviceTestRepo) HasClaim() (bool, error) { return false, nil }

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
// escrow blobs) for account "account-1" under username, returning the
// plaintext authSecret a caller can present to authenticate as it.
func seedPasswordCredential(t *testing.T, repo *deviceTestRepo, verifierKey []byte, username string, accountKeyBlob, userState string) (authSecret string) {
	t.Helper()
	secretBytes := make([]byte, 32)
	_, err := rand.Read(secretBytes)
	assert.NoError(t, err)
	authSecret = base64.StdEncoding.EncodeToString(secretBytes)

	verifier, err := hashAuthSecret(verifierKey, authSecret)
	assert.NoError(t, err)

	repo.accounts["account-1"] = &User{PublicKey: "account-1", Username: username, Role: RoleUser}
	assert.NoError(t, repo.SetPasswordCredentials("account-1", verifier, "", accountKeyBlob, userState))
	return authSecret
}

func TestRegisterDevice_ShouldEnrollWithValidPasswordCredential(t *testing.T) {
	// given
	verifierKey := []byte("test-verifier-key")
	repo := newDeviceTestRepo()
	authSecret := seedPasswordCredential(t, repo, verifierKey, "alice", "", "")
	de := NewDeviceEndpoints(repo, verifierKey, "space-key")

	ctx := newRegisterDeviceRequestCtx(t, registerDeviceRequest{
		Username:        "alice",
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
		Username:        "alice",
		AuthSecret:      base64.StdEncoding.EncodeToString(wrongSecretBytes),
		DevicePublicKey: validNewDevicePublicKey(),
	})

	// when
	de.RegisterDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}

// TestRegisterDevice_ShouldReturn401WithByteIdenticalBodyForUnknownUsername
// is the anti-enumeration test for the password enroll path: an unknown
// username and a wrong password for a real username must be
// indistinguishable from the response alone.
func TestRegisterDevice_ShouldReturn401WithByteIdenticalBodyForUnknownUsername(t *testing.T) {
	// given
	verifierKey := []byte("test-verifier-key")
	repo := newDeviceTestRepo()
	seedPasswordCredential(t, repo, verifierKey, "alice", "", "")
	de := NewDeviceEndpoints(repo, verifierKey, "space-key")

	wrongSecretBytes := make([]byte, 32)
	wrongPasswordCtx := newRegisterDeviceRequestCtx(t, registerDeviceRequest{
		Username:        "alice",
		AuthSecret:      base64.StdEncoding.EncodeToString(wrongSecretBytes),
		DevicePublicKey: validNewDevicePublicKey(),
	})
	unknownUsernameCtx := newRegisterDeviceRequestCtx(t, registerDeviceRequest{
		Username:        "does-not-exist",
		AuthSecret:      base64.StdEncoding.EncodeToString(wrongSecretBytes),
		DevicePublicKey: validNewDevicePublicKey(),
	})

	// when
	de.RegisterDevice(wrongPasswordCtx)
	de.RegisterDevice(unknownUsernameCtx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, wrongPasswordCtx.Response.StatusCode())
	assert.Equal(t, fasthttp.StatusUnauthorized, unknownUsernameCtx.Response.StatusCode())
	assert.Equal(t, wrongPasswordCtx.Response.Body(), unknownUsernameCtx.Response.Body())
}

// TestRegisterDevice_ShouldEnrollWithPasswordSetBeforeRename covers a
// rename's downstream effect on the password enroll path: the SAME verifier
// (set before the rename) still authenticates the account under its NEW
// username, because GetPasswordCredential joins against whichever username
// currently sits on the account row - not a frozen copy from set-password
// time. The OLD username must stop resolving once the rename lands.
func TestRegisterDevice_ShouldEnrollWithPasswordSetBeforeRename(t *testing.T) {
	// given
	verifierKey := []byte("test-verifier-key")
	repo := newDeviceTestRepo()
	authSecret := seedPasswordCredential(t, repo, verifierKey, "alice", "", "")
	assert.NoError(t, repo.UpdateUsername("account-1", "alice2"))
	de := NewDeviceEndpoints(repo, verifierKey, "space-key")

	// when - enroll using the NEW username with the password set BEFORE the rename
	newUsernameCtx := newRegisterDeviceRequestCtx(t, registerDeviceRequest{
		Username:        "alice2",
		AuthSecret:      authSecret,
		DevicePublicKey: validNewDevicePublicKey(),
	})
	de.RegisterDevice(newUsernameCtx)

	// then
	assert.Equal(t, fasthttp.StatusCreated, newUsernameCtx.Response.StatusCode())
	var resp registerDeviceResponse
	assert.NoError(t, json.Unmarshal(newUsernameCtx.Response.Body(), &resp))
	assert.Equal(t, "account-1", resp.UserPublicKey)

	// and - the OLD username no longer resolves
	oldUsernameCtx := newRegisterDeviceRequestCtx(t, registerDeviceRequest{
		Username:        "alice",
		AuthSecret:      authSecret,
		DevicePublicKey: validNewDevicePublicKey(),
	})
	de.RegisterDevice(oldUsernameCtx)
	assert.Equal(t, fasthttp.StatusUnauthorized, oldUsernameCtx.Response.StatusCode())
}

func TestRegisterDevice_ShouldReturn400WhenBothCredentialsPresent(t *testing.T) {
	// given
	de := NewDeviceEndpoints(newDeviceTestRepo(), []byte("test-verifier-key"), "space-key")
	ctx := newRegisterDeviceRequestCtx(t, registerDeviceRequest{
		Delegation:      "some-delegation-jws",
		Username:        "alice",
		AuthSecret:      base64.StdEncoding.EncodeToString(make([]byte, 32)),
		DevicePublicKey: validNewDevicePublicKey(),
	})

	// when
	de.RegisterDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestRegisterDevice_ShouldReturn400WhenUsernameWithoutAuthSecret(t *testing.T) {
	// given
	de := NewDeviceEndpoints(newDeviceTestRepo(), []byte("test-verifier-key"), "space-key")
	ctx := newRegisterDeviceRequestCtx(t, registerDeviceRequest{
		Username:        "alice",
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
		Username:        "alice",
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

// ---- #127: NormalizeDeviceName ----

func TestNormalizeDeviceName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantName string
		wantOk   bool
	}{
		{name: "plain name", input: "My Laptop", wantName: "My Laptop", wantOk: true},
		{name: "trims surrounding whitespace", input: "  My Laptop  ", wantName: "My Laptop", wantOk: true},
		{name: "empty is rejected", input: "", wantOk: false},
		{name: "whitespace-only is rejected", input: "   ", wantOk: false},
		{name: "exactly 64 runes is accepted", input: strings.Repeat("a", 64), wantName: strings.Repeat("a", 64), wantOk: true},
		{name: "65 runes is rejected", input: strings.Repeat("a", 65), wantOk: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name, ok := NormalizeDeviceName(tc.input)
			assert.Equal(t, tc.wantOk, ok)
			if tc.wantOk {
				assert.Equal(t, tc.wantName, name)
			}
		})
	}
}

// ---- #127: RenameDevice endpoint ----

// newRenameDeviceRequestCtx marshals body as the PATCH /users/devices
// request and returns a ready-to-dispatch context, with authenticatedUser
// set in ctx when non-nil (nil exercises the missing-user/401 branch).
func newRenameDeviceRequestCtx(t *testing.T, authenticatedUser *User, body renameDeviceRequest) *fasthttp.RequestCtx {
	t.Helper()
	b, err := json.Marshal(body)
	assert.NoError(t, err)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("PATCH")
	ctx.Request.SetBody(b)
	if authenticatedUser != nil {
		ctx.SetUserValue("user", authenticatedUser)
	}
	return ctx
}

func TestRenameDevice_ShouldReturn204AndUpdateRepoOnSuccess(t *testing.T) {
	// given
	repo := newDeviceTestRepo()
	repo.devices["device-other"] = &Device{DevicePublicKey: "device-other", UserPublicKey: "account-1"}
	de := NewDeviceEndpoints(repo, nil, "space-key")
	ctx := newRenameDeviceRequestCtx(t, &User{PublicKey: "account-1", DevicePublicKey: "device-current"}, renameDeviceRequest{
		DevicePublicKey: "device-other",
		DeviceName:      "New Name",
	})

	// when
	de.RenameDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNoContent, ctx.Response.StatusCode())
	if assert.NotNil(t, repo.devices["device-other"].DeviceName) {
		assert.Equal(t, "New Name", *repo.devices["device-other"].DeviceName)
	}
}

// TestRenameDevice_ShouldAllowRenamingCurrentDevice covers the one deliberate
// difference from RevokeDevice's shape: renaming the device currently in use
// is allowed (revoking it isn't).
func TestRenameDevice_ShouldAllowRenamingCurrentDevice(t *testing.T) {
	// given
	repo := newDeviceTestRepo()
	repo.devices["device-current"] = &Device{DevicePublicKey: "device-current", UserPublicKey: "account-1"}
	de := NewDeviceEndpoints(repo, nil, "space-key")
	ctx := newRenameDeviceRequestCtx(t, &User{PublicKey: "account-1", DevicePublicKey: "device-current"}, renameDeviceRequest{
		DevicePublicKey: "device-current",
		DeviceName:      "This One",
	})

	// when
	de.RenameDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNoContent, ctx.Response.StatusCode())
}

func TestRenameDevice_ShouldReturn404WhenNotOwnedByAuthenticatedAccount(t *testing.T) {
	// given
	repo := newDeviceTestRepo()
	repo.devices["device-other"] = &Device{DevicePublicKey: "device-other", UserPublicKey: "some-other-account"}
	de := NewDeviceEndpoints(repo, nil, "space-key")
	ctx := newRenameDeviceRequestCtx(t, &User{PublicKey: "account-1", DevicePublicKey: "device-current"}, renameDeviceRequest{
		DevicePublicKey: "device-other",
		DeviceName:      "New Name",
	})

	// when
	de.RenameDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNotFound, ctx.Response.StatusCode())
}

func TestRenameDevice_ShouldReturn404WhenTargetRevoked(t *testing.T) {
	// given
	repo := newDeviceTestRepo()
	revokedAt := time.Now().Unix()
	repo.devices["device-other"] = &Device{DevicePublicKey: "device-other", UserPublicKey: "account-1", RevokedAt: &revokedAt}
	de := NewDeviceEndpoints(repo, nil, "space-key")
	ctx := newRenameDeviceRequestCtx(t, &User{PublicKey: "account-1", DevicePublicKey: "device-current"}, renameDeviceRequest{
		DevicePublicKey: "device-other",
		DeviceName:      "New Name",
	})

	// when
	de.RenameDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNotFound, ctx.Response.StatusCode())
}

func TestRenameDevice_ShouldReturn400ForEmptyName(t *testing.T) {
	// given
	repo := newDeviceTestRepo()
	repo.devices["device-other"] = &Device{DevicePublicKey: "device-other", UserPublicKey: "account-1"}
	de := NewDeviceEndpoints(repo, nil, "space-key")
	ctx := newRenameDeviceRequestCtx(t, &User{PublicKey: "account-1", DevicePublicKey: "device-current"}, renameDeviceRequest{
		DevicePublicKey: "device-other",
		DeviceName:      "",
	})

	// when
	de.RenameDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestRenameDevice_ShouldReturn400ForWhitespaceOnlyName(t *testing.T) {
	// given
	repo := newDeviceTestRepo()
	repo.devices["device-other"] = &Device{DevicePublicKey: "device-other", UserPublicKey: "account-1"}
	de := NewDeviceEndpoints(repo, nil, "space-key")
	ctx := newRenameDeviceRequestCtx(t, &User{PublicKey: "account-1", DevicePublicKey: "device-current"}, renameDeviceRequest{
		DevicePublicKey: "device-other",
		DeviceName:      "   ",
	})

	// when
	de.RenameDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestRenameDevice_ShouldReturn400ForOversizedName(t *testing.T) {
	// given
	repo := newDeviceTestRepo()
	repo.devices["device-other"] = &Device{DevicePublicKey: "device-other", UserPublicKey: "account-1"}
	de := NewDeviceEndpoints(repo, nil, "space-key")
	ctx := newRenameDeviceRequestCtx(t, &User{PublicKey: "account-1", DevicePublicKey: "device-current"}, renameDeviceRequest{
		DevicePublicKey: "device-other",
		DeviceName:      strings.Repeat("a", 65),
	})

	// when
	de.RenameDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestRenameDevice_ShouldTrimSurroundingSpaces(t *testing.T) {
	// given
	repo := newDeviceTestRepo()
	repo.devices["device-other"] = &Device{DevicePublicKey: "device-other", UserPublicKey: "account-1"}
	de := NewDeviceEndpoints(repo, nil, "space-key")
	ctx := newRenameDeviceRequestCtx(t, &User{PublicKey: "account-1", DevicePublicKey: "device-current"}, renameDeviceRequest{
		DevicePublicKey: "device-other",
		DeviceName:      "  Padded Name  ",
	})

	// when
	de.RenameDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNoContent, ctx.Response.StatusCode())
	if assert.NotNil(t, repo.devices["device-other"].DeviceName) {
		assert.Equal(t, "Padded Name", *repo.devices["device-other"].DeviceName)
	}
}

func TestRenameDevice_ShouldReturn401WhenUnauthenticated(t *testing.T) {
	// given
	repo := newDeviceTestRepo()
	repo.devices["device-other"] = &Device{DevicePublicKey: "device-other", UserPublicKey: "account-1"}
	de := NewDeviceEndpoints(repo, nil, "space-key")
	ctx := newRenameDeviceRequestCtx(t, nil, renameDeviceRequest{
		DevicePublicKey: "device-other",
		DeviceName:      "New Name",
	})

	// when
	de.RenameDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}
