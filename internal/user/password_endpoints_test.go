package user

import (
	"encoding/base64"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// passwordTestRepo is a UserRepository stub for password endpoint tests. It
// mimics the real repository's SetPasswordCredentials contract: setting an
// identifier already claimed by a different account returns
// ErrIdentifierTaken, matching the unique index on lower(identifier).
type passwordTestRepo struct {
	accounts    map[string]*User
	credentials map[string]struct{ userPublicKey, verifier string }   // keyed by normalized identifier
	escrow      map[string]struct{ accountKeyBlob, userState string } // keyed by account public key
}

func newPasswordTestRepo() *passwordTestRepo {
	return &passwordTestRepo{
		accounts:    map[string]*User{},
		credentials: map[string]struct{ userPublicKey, verifier string }{},
		escrow:      map[string]struct{ accountKeyBlob, userState string }{},
	}
}

func (r *passwordTestRepo) CreateUser(u *User) error { return nil }
func (r *passwordTestRepo) GetUserByPublicKey(publicKey string) (*User, error) {
	return r.accounts[publicKey], nil
}
func (r *passwordTestRepo) GetUserByUsername(username string) (*User, error) { return nil, nil }
func (r *passwordTestRepo) UpdateUserRole(publicKey, role string) error      { return nil }
func (r *passwordTestRepo) UpdateAvatarStorageID(publicKey string, avatarStorageID *string) error {
	return nil
}
func (r *passwordTestRepo) UpdateUsername(publicKey, username string) error { return nil }
func (r *passwordTestRepo) UpdateUserIssuer(publicKey, issuer string) error { return nil }
func (r *passwordTestRepo) EnsureDevice(devicePublicKey, userPublicKey string, deviceName *string, createdAt int64) error {
	return nil
}
func (r *passwordTestRepo) GetDevice(devicePublicKey string) (*Device, error) { return nil, nil }
func (r *passwordTestRepo) ListDevices(userPublicKey string) ([]*Device, error) {
	return nil, nil
}
func (r *passwordTestRepo) RevokeDevice(devicePublicKey string, ts int64) error        { return nil }
func (r *passwordTestRepo) RenameDevice(devicePublicKey, deviceName string) error      { return nil }
func (r *passwordTestRepo) TouchDeviceLastSeen(devicePublicKey string, ts int64) error { return nil }

func (r *passwordTestRepo) SetPasswordCredentials(publicKey, identifier, passwordVerifier, accountKeyBlob, userState string) error {
	if existing, ok := r.credentials[identifier]; ok && existing.userPublicKey != publicKey {
		return ErrIdentifierTaken
	}
	r.credentials[identifier] = struct{ userPublicKey, verifier string }{publicKey, passwordVerifier}
	// Mirrors the real UPDATE's per-column NULLIF($n,''): each blob clears
	// independently of the other, not only when both are empty.
	r.escrow[publicKey] = struct{ accountKeyBlob, userState string }{accountKeyBlob, userState}
	return nil
}
func (r *passwordTestRepo) GetPasswordCredential(identifier string) (string, string, error) {
	cred := r.credentials[identifier]
	return cred.userPublicKey, cred.verifier, nil
}
func (r *passwordTestRepo) GetEscrow(publicKey string) (string, string, error) {
	escrow := r.escrow[publicKey]
	return escrow.accountKeyBlob, escrow.userState, nil
}

func newSaltRequestCtx(identifier string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/users/salt?identifier=" + identifier)
	return ctx
}

// TestGetSalt_ShouldReturnByteIdenticalShapeForKnownAndUnknownIdentifier is
// THE anti-enumeration test: a registered identifier and an unregistered one
// must both succeed with the same response shape and the same HMAC formula -
// no database-driven branch (404 for unknown, different fields, etc.) may
// leak whether an identifier is registered.
func TestGetSalt_ShouldReturnByteIdenticalShapeForKnownAndUnknownIdentifier(t *testing.T) {
	// given
	saltSecret := []byte("salt-secret")
	verifierKey := []byte("verifier-key")
	repo := newPasswordTestRepo()
	repo.accounts["account-1"] = &User{PublicKey: "account-1", Username: "alice"}
	verifier, err := hashAuthSecret(verifierKey, randomAuthSecret(t))
	assert.NoError(t, err)
	assert.NoError(t, repo.SetPasswordCredentials("account-1", "alice", verifier, "", ""))

	pe := NewPasswordEndpoints(repo, saltSecret, verifierKey)

	knownCtx := newSaltRequestCtx("alice")
	unknownCtx := newSaltRequestCtx("does-not-exist")

	// when
	pe.GetSalt(knownCtx)
	pe.GetSalt(unknownCtx)

	// then - both succeed with the same response shape
	assert.Equal(t, fasthttp.StatusOK, knownCtx.Response.StatusCode())
	assert.Equal(t, fasthttp.StatusOK, unknownCtx.Response.StatusCode())

	var knownResp, unknownResp saltResponse
	assert.NoError(t, json.Unmarshal(knownCtx.Response.Body(), &knownResp))
	assert.NoError(t, json.Unmarshal(unknownCtx.Response.Body(), &unknownResp))
	assert.NotEmpty(t, knownResp.Salt)
	assert.NotEmpty(t, unknownResp.Salt)

	// and each salt equals the pure HMAC-derived value for its identifier,
	// with no database round trip involved
	assert.Equal(t, base64.StdEncoding.EncodeToString(deterministicSalt(saltSecret, "alice")), knownResp.Salt)
	assert.Equal(t, base64.StdEncoding.EncodeToString(deterministicSalt(saltSecret, "does-not-exist")), unknownResp.Salt)
}

func TestGetSalt_ShouldReturn400ForMissingIdentifier(t *testing.T) {
	// given
	pe := NewPasswordEndpoints(newPasswordTestRepo(), []byte("salt-secret"), []byte("verifier-key"))
	ctx := newSaltRequestCtx("")

	// when
	pe.GetSalt(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func newSetPasswordRequestCtx(t *testing.T, authenticatedUser *User, body setPasswordRequest) *fasthttp.RequestCtx {
	t.Helper()
	b, err := json.Marshal(body)
	assert.NoError(t, err)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.SetBody(b)
	if authenticatedUser != nil {
		ctx.SetUserValue("user", authenticatedUser)
	}
	return ctx
}

func TestSetPassword_ShouldReturn204OnSuccess(t *testing.T) {
	// given
	repo := newPasswordTestRepo()
	verifierKey := []byte("verifier-key")
	pe := NewPasswordEndpoints(repo, []byte("salt-secret"), verifierKey)
	authSecret := randomAuthSecret(t)
	ctx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-1"}, setPasswordRequest{Identifier: "alice", AuthSecret: authSecret})

	// when
	pe.SetPassword(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNoContent, ctx.Response.StatusCode())
	userPublicKey, verifier, err := repo.GetPasswordCredential("alice")
	assert.NoError(t, err)
	assert.Equal(t, "account-1", userPublicKey)
	assert.True(t, verifyAuthSecret(verifierKey, verifier, authSecret))
}

func TestSetPassword_ShouldReturn409WhenIdentifierTaken(t *testing.T) {
	// given
	repo := newPasswordTestRepo()
	verifierKey := []byte("verifier-key")
	verifier, err := hashAuthSecret(verifierKey, randomAuthSecret(t))
	assert.NoError(t, err)
	assert.NoError(t, repo.SetPasswordCredentials("account-1", "alice", verifier, "", ""))

	pe := NewPasswordEndpoints(repo, []byte("salt-secret"), verifierKey)
	ctx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-2"}, setPasswordRequest{Identifier: "alice", AuthSecret: randomAuthSecret(t)})

	// when
	pe.SetPassword(ctx)

	// then
	assert.Equal(t, fasthttp.StatusConflict, ctx.Response.StatusCode())
}

func TestSetPassword_ShouldReturn400ForInvalidIdentifier(t *testing.T) {
	// given
	pe := NewPasswordEndpoints(newPasswordTestRepo(), []byte("salt-secret"), []byte("verifier-key"))
	ctx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-1"}, setPasswordRequest{Identifier: "a", AuthSecret: randomAuthSecret(t)})

	// when
	pe.SetPassword(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestSetPassword_ShouldReturn400ForInvalidAuthSecret(t *testing.T) {
	// given
	pe := NewPasswordEndpoints(newPasswordTestRepo(), []byte("salt-secret"), []byte("verifier-key"))
	ctx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-1"}, setPasswordRequest{Identifier: "alice", AuthSecret: "not-valid-base64!!"})

	// when
	pe.SetPassword(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestSetPassword_ShouldReturn401WhenUnauthenticated(t *testing.T) {
	// given
	pe := NewPasswordEndpoints(newPasswordTestRepo(), []byte("salt-secret"), []byte("verifier-key"))
	ctx := newSetPasswordRequestCtx(t, nil, setPasswordRequest{Identifier: "alice", AuthSecret: randomAuthSecret(t)})

	// when
	pe.SetPassword(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}

func TestSetPassword_ShouldPersistEscrowBlobs(t *testing.T) {
	// given
	repo := newPasswordTestRepo()
	pe := NewPasswordEndpoints(repo, []byte("salt-secret"), []byte("verifier-key"))
	accountKeyBlob := base64.StdEncoding.EncodeToString([]byte("sealed-account-key"))
	userState := base64.StdEncoding.EncodeToString([]byte("sealed-user-state"))
	ctx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-1"}, setPasswordRequest{
		Identifier:     "alice",
		AuthSecret:     randomAuthSecret(t),
		AccountKeyBlob: accountKeyBlob,
		UserState:      userState,
	})

	// when
	pe.SetPassword(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNoContent, ctx.Response.StatusCode())
	gotAccountKeyBlob, gotUserState, err := repo.GetEscrow("account-1")
	assert.NoError(t, err)
	assert.Equal(t, accountKeyBlob, gotAccountKeyBlob)
	assert.Equal(t, userState, gotUserState)
}

// TestSetPassword_ShouldClearEscrowWhenBlobsOmitted covers the NULLIF
// clear-on-omit contract (see user_repository.go's SetPasswordCredentials): a
// second SetPassword call with no blobs clears whatever escrow the first
// call stored, rather than leaving it in place.
func TestSetPassword_ShouldClearEscrowWhenBlobsOmitted(t *testing.T) {
	// given
	repo := newPasswordTestRepo()
	pe := NewPasswordEndpoints(repo, []byte("salt-secret"), []byte("verifier-key"))
	ctx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-1"}, setPasswordRequest{
		Identifier:     "alice",
		AuthSecret:     randomAuthSecret(t),
		AccountKeyBlob: base64.StdEncoding.EncodeToString([]byte("sealed-account-key")),
		UserState:      base64.StdEncoding.EncodeToString([]byte("sealed-user-state")),
	})
	pe.SetPassword(ctx)
	assert.Equal(t, fasthttp.StatusNoContent, ctx.Response.StatusCode())

	// when - re-set the password with no escrow blobs
	clearCtx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-1"}, setPasswordRequest{
		Identifier: "alice",
		AuthSecret: randomAuthSecret(t),
	})
	pe.SetPassword(clearCtx)

	// then
	assert.Equal(t, fasthttp.StatusNoContent, clearCtx.Response.StatusCode())
	gotAccountKeyBlob, gotUserState, err := repo.GetEscrow("account-1")
	assert.NoError(t, err)
	assert.Empty(t, gotAccountKeyBlob)
	assert.Empty(t, gotUserState)
}

func TestSetPassword_ShouldReturn400ForNonBase64AccountKeyBlob(t *testing.T) {
	// given
	pe := NewPasswordEndpoints(newPasswordTestRepo(), []byte("salt-secret"), []byte("verifier-key"))
	ctx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-1"}, setPasswordRequest{
		Identifier:     "alice",
		AuthSecret:     randomAuthSecret(t),
		AccountKeyBlob: "not-valid-base64!!",
	})

	// when
	pe.SetPassword(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestSetPassword_ShouldReturn400ForOversizedUserState(t *testing.T) {
	// given
	pe := NewPasswordEndpoints(newPasswordTestRepo(), []byte("salt-secret"), []byte("verifier-key"))
	oversized := base64.StdEncoding.EncodeToString(make([]byte, maxUserStateBlobLen+1))
	ctx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-1"}, setPasswordRequest{
		Identifier: "alice",
		AuthSecret: randomAuthSecret(t),
		UserState:  oversized,
	})

	// when
	pe.SetPassword(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}
