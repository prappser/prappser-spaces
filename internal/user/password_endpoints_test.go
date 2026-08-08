package user

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// passwordTestRepo is a UserRepository stub for password endpoint tests. It
// mirrors the real repository's SetPasswordCredentials contract: verifier
// and handle are per-account columns (accounts, verifiers, handles all keyed
// by public key, matching users.password_verifier/password_handle), and
// GetPasswordCredential/GetPasswordHandle join against each account's
// CURRENT username live - the same way the real `lower(username) =
// lower($1) AND password_verifier IS NOT NULL` queries do - rather than
// freezing a username snapshot at set-password time. That live join is what
// makes a rename transparently carry a previously-set password forward. The
// handle itself (unlike a derived salt) may differ from the account's
// CURRENT username - see TestGetSalt_ShouldUseStoredHandleNotCurrentUsername.
type passwordTestRepo struct {
	accounts  map[string]*User
	verifiers map[string]string                                     // keyed by public key
	handles   map[string]string                                     // keyed by public key
	escrow    map[string]struct{ accountKeyBlob, userState string } // keyed by public key
}

func newPasswordTestRepo() *passwordTestRepo {
	return &passwordTestRepo{
		accounts:  map[string]*User{},
		verifiers: map[string]string{},
		handles:   map[string]string{},
		escrow:    map[string]struct{ accountKeyBlob, userState string }{},
	}
}

func (r *passwordTestRepo) CreateUser(u *User) error {
	r.accounts[u.PublicKey] = u
	return nil
}
func (r *passwordTestRepo) GetUserByPublicKey(publicKey string) (*User, error) {
	return r.accounts[publicKey], nil
}
func (r *passwordTestRepo) UpdateUserRole(publicKey, role string) error { return nil }
func (r *passwordTestRepo) UpdateAvatarStorageID(publicKey string, avatarStorageID *string) error {
	return nil
}
func (r *passwordTestRepo) UpdateUsername(publicKey, username string) error {
	if account, ok := r.accounts[publicKey]; ok {
		account.Username = username
	}
	return nil
}
func (r *passwordTestRepo) UpdateUserIssuer(publicKey, issuer string) error { return nil }
func (r *passwordTestRepo) SetUserIssuer(publicKey, issuer string) error    { return nil }
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

func (r *passwordTestRepo) SetPasswordCredentials(publicKey, passwordVerifier, handle, accountKeyBlob, userState string) error {
	account, ok := r.accounts[publicKey]
	if !ok {
		return fmt.Errorf("no account for public key %s", publicKey)
	}
	// Case-insensitive collision check against every OTHER password-enabled
	// account's CURRENT username - mirrors the partial unique index's scope.
	for pk, other := range r.accounts {
		if pk == publicKey {
			continue
		}
		if r.verifiers[pk] != "" && strings.EqualFold(other.Username, account.Username) {
			return ErrUsernameTaken
		}
	}
	r.verifiers[publicKey] = passwordVerifier
	// Mirrors the real UPDATE's COALESCE(password_handle, $2): a handle
	// already on file for this account is never re-pointed.
	if _, exists := r.handles[publicKey]; !exists {
		r.handles[publicKey] = handle
	}
	// Mirrors the real UPDATE's per-column NULLIF($n,''): each blob clears
	// independently of the other, not only when both are empty.
	r.escrow[publicKey] = struct{ accountKeyBlob, userState string }{accountKeyBlob, userState}
	return nil
}
func (r *passwordTestRepo) GetPasswordCredential(username string) (string, string, error) {
	for pk, account := range r.accounts {
		if r.verifiers[pk] != "" && strings.EqualFold(account.Username, username) {
			return pk, r.verifiers[pk], nil
		}
	}
	return "", "", nil
}
func (r *passwordTestRepo) GetPasswordHandle(username string) (string, error) {
	for pk, account := range r.accounts {
		if r.verifiers[pk] != "" && strings.EqualFold(account.Username, username) {
			return r.handles[pk], nil
		}
	}
	return "", nil
}
func (r *passwordTestRepo) GetEscrow(publicKey string) (string, string, error) {
	escrow := r.escrow[publicKey]
	return escrow.accountKeyBlob, escrow.userState, nil
}
func (r *passwordTestRepo) UpdateUserState(publicKey, userState string) error {
	escrow := r.escrow[publicKey]
	escrow.userState = userState
	r.escrow[publicKey] = escrow
	return nil
}
func (r *passwordTestRepo) ClaimOwner(publicKey, username, passwordVerifier, handle, accountKeyBlob, userState string, deviceName *string, createdAt int64) error {
	return nil
}
func (r *passwordTestRepo) HasClaim() (bool, error) { return false, nil }

func newSaltRequestCtx(username string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/users/salt?username=" + username)
	return ctx
}

// TestGetSalt_ShouldReturnDeterministicFallbackForUnknownUsername covers the
// no-stored-salt branch: with no password-enabled account for this
// username, GetSalt must return exactly the HMAC fallback for the
// (lowercased) username.
func TestGetSalt_ShouldReturnDeterministicFallbackForUnknownUsername(t *testing.T) {
	// given
	saltSecret := []byte("salt-secret")
	pe := NewPasswordEndpoints(newPasswordTestRepo(), saltSecret, []byte("verifier-key"))
	ctx := newSaltRequestCtx("does-not-exist")

	// when
	pe.GetSalt(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	var resp saltResponse
	assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	assert.Equal(t, base64.StdEncoding.EncodeToString(deterministicSalt(saltSecret, "does-not-exist")), resp.Salt)
}

// TestGetSalt_ShouldReturnStoredSaltForPasswordEnabledAccount covers the
// stored-row branch: once SetPassword has run for an account, GetSalt must
// derive the salt from the HANDLE persisted at that time, not recompute a
// fresh fallback.
func TestGetSalt_ShouldReturnStoredSaltForPasswordEnabledAccount(t *testing.T) {
	// given
	saltSecret := []byte("salt-secret")
	repo := newPasswordTestRepo()
	repo.accounts["account-1"] = &User{PublicKey: "account-1", Username: "alice"}
	pe := NewPasswordEndpoints(repo, saltSecret, []byte("verifier-key"))
	setCtx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-1", Username: "alice"}, setPasswordRequest{AuthSecret: randomAuthSecret(t)})
	pe.SetPassword(setCtx)
	assert.Equal(t, fasthttp.StatusNoContent, setCtx.Response.StatusCode())

	// when
	ctx := newSaltRequestCtx("alice")
	pe.GetSalt(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	var resp saltResponse
	assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	storedHandle, err := repo.GetPasswordHandle("alice")
	assert.NoError(t, err)
	assert.NotEmpty(t, storedHandle)
	assert.Equal(t, base64.StdEncoding.EncodeToString(deterministicSalt(saltSecret, storedHandle)), resp.Salt)
}

// TestGetSalt_ShouldUseStoredHandleNotCurrentUsername is the migration-safety
// proof: an account whose stored handle differs from its CURRENT username
// (exactly what migration 000023's backfill produces for every pre-#126
// password-enabled account - handle = lower(old identifier), username =
// whatever display name it happens to have) must get a salt derived from the
// HANDLE, never from the username.
func TestGetSalt_ShouldUseStoredHandleNotCurrentUsername(t *testing.T) {
	// given - simulates a migrated row directly, bypassing SetPassword, since
	// this handle/username split can only arise from the backfill.
	saltSecret := []byte("salt-secret")
	repo := newPasswordTestRepo()
	repo.accounts["account-1"] = &User{PublicKey: "account-1", Username: "displayname"}
	repo.verifiers["account-1"] = "hmac-sha256$AAAA"
	repo.handles["account-1"] = "old-identifier"
	pe := NewPasswordEndpoints(repo, saltSecret, []byte("verifier-key"))

	// when
	ctx := newSaltRequestCtx("displayname")
	pe.GetSalt(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	var resp saltResponse
	assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	assert.Equal(t, base64.StdEncoding.EncodeToString(deterministicSalt(saltSecret, "old-identifier")), resp.Salt)
	assert.NotEqual(t, base64.StdEncoding.EncodeToString(deterministicSalt(saltSecret, "displayname")), resp.Salt)
}

// TestGetSalt_ShouldStaySameAcrossUsernameRename is the COALESCE proof from
// the client's perspective: renaming the account must not change the salt
// GetSalt hands out under the NEW username - the client's escrow blob was
// sealed under a wrapKey derived from the ORIGINAL salt, so a regression
// here would make that escrow permanently undecryptable.
func TestGetSalt_ShouldStaySameAcrossUsernameRename(t *testing.T) {
	// given
	saltSecret := []byte("salt-secret")
	repo := newPasswordTestRepo()
	repo.accounts["account-1"] = &User{PublicKey: "account-1", Username: "alice"}
	pe := NewPasswordEndpoints(repo, saltSecret, []byte("verifier-key"))
	setCtx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-1", Username: "alice"}, setPasswordRequest{AuthSecret: randomAuthSecret(t)})
	pe.SetPassword(setCtx)
	assert.Equal(t, fasthttp.StatusNoContent, setCtx.Response.StatusCode())

	beforeCtx := newSaltRequestCtx("alice")
	pe.GetSalt(beforeCtx)
	var before saltResponse
	assert.NoError(t, json.Unmarshal(beforeCtx.Response.Body(), &before))

	// when - rename, then re-set the password as the renamed account (mirrors
	// a client re-authenticating under its new username)
	assert.NoError(t, repo.UpdateUsername("account-1", "alice2"))
	renameSetCtx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-1", Username: "alice2"}, setPasswordRequest{AuthSecret: randomAuthSecret(t)})
	pe.SetPassword(renameSetCtx)
	assert.Equal(t, fasthttp.StatusNoContent, renameSetCtx.Response.StatusCode())

	afterCtx := newSaltRequestCtx("alice2")
	pe.GetSalt(afterCtx)
	var after saltResponse
	assert.NoError(t, json.Unmarshal(afterCtx.Response.Body(), &after))

	// then - same salt under the new username, NOT the fresh HMAC fallback
	assert.Equal(t, before.Salt, after.Salt)
	assert.NotEqual(t, base64.StdEncoding.EncodeToString(deterministicSalt(saltSecret, "alice2")), after.Salt)
}

func TestGetSalt_ShouldReturn400ForEmptyUsername(t *testing.T) {
	// given
	pe := NewPasswordEndpoints(newPasswordTestRepo(), []byte("salt-secret"), []byte("verifier-key"))
	ctx := newSaltRequestCtx("")

	// when
	pe.GetSalt(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestGetSalt_ShouldReturn400ForOversizedUsername(t *testing.T) {
	// given
	pe := NewPasswordEndpoints(newPasswordTestRepo(), []byte("salt-secret"), []byte("verifier-key"))
	ctx := newSaltRequestCtx(strings.Repeat("a", 65))

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
	repo.accounts["account-1"] = &User{PublicKey: "account-1", Username: "alice"}
	verifierKey := []byte("verifier-key")
	pe := NewPasswordEndpoints(repo, []byte("salt-secret"), verifierKey)
	authSecret := randomAuthSecret(t)
	ctx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-1", Username: "alice"}, setPasswordRequest{AuthSecret: authSecret})

	// when
	pe.SetPassword(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNoContent, ctx.Response.StatusCode())
	userPublicKey, verifier, err := repo.GetPasswordCredential("alice")
	assert.NoError(t, err)
	assert.Equal(t, "account-1", userPublicKey)
	assert.True(t, verifyAuthSecret(verifierKey, verifier, authSecret))
}

// TestSetPassword_ShouldReturn409WhenUsernameAlreadyTakenForPasswordLogin
// covers the collision check now scoped to password-enabled accounts only,
// case-insensitively: a second, DIFFERENT account whose own username
// matches (case-insensitively) an already password-enabled account's
// username is rejected.
func TestSetPassword_ShouldReturn409WhenUsernameAlreadyTakenForPasswordLogin(t *testing.T) {
	// given
	repo := newPasswordTestRepo()
	repo.accounts["account-1"] = &User{PublicKey: "account-1", Username: "alice"}
	repo.accounts["account-2"] = &User{PublicKey: "account-2", Username: "ALICE"}
	pe := NewPasswordEndpoints(repo, []byte("salt-secret"), []byte("verifier-key"))
	firstCtx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-1", Username: "alice"}, setPasswordRequest{AuthSecret: randomAuthSecret(t)})
	pe.SetPassword(firstCtx)
	assert.Equal(t, fasthttp.StatusNoContent, firstCtx.Response.StatusCode())

	ctx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-2", Username: "ALICE"}, setPasswordRequest{AuthSecret: randomAuthSecret(t)})

	// when
	pe.SetPassword(ctx)

	// then
	assert.Equal(t, fasthttp.StatusConflict, ctx.Response.StatusCode())
}

func TestSetPassword_ShouldReturn400ForInvalidAuthSecret(t *testing.T) {
	// given
	pe := NewPasswordEndpoints(newPasswordTestRepo(), []byte("salt-secret"), []byte("verifier-key"))
	ctx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-1", Username: "alice"}, setPasswordRequest{AuthSecret: "not-valid-base64!!"})

	// when
	pe.SetPassword(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestSetPassword_ShouldReturn401WhenUnauthenticated(t *testing.T) {
	// given
	pe := NewPasswordEndpoints(newPasswordTestRepo(), []byte("salt-secret"), []byte("verifier-key"))
	ctx := newSetPasswordRequestCtx(t, nil, setPasswordRequest{AuthSecret: randomAuthSecret(t)})

	// when
	pe.SetPassword(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}

// TestSetPassword_ShouldIgnoreStrayIdentifierOrUsernameBodyKeys covers the
// post-#126 request shape: setPasswordRequest has no identifier/username
// field at all, so the login handle always comes from the AUTHENTICATED
// caller's own Username - any stray "identifier" or "username" key a client
// sends in the body is silently ignored by json.Unmarshal, never a way to
// set someone else's handle.
func TestSetPassword_ShouldIgnoreStrayIdentifierOrUsernameBodyKeys(t *testing.T) {
	// given
	repo := newPasswordTestRepo()
	repo.accounts["account-1"] = &User{PublicKey: "account-1", Username: "alice"}
	pe := NewPasswordEndpoints(repo, []byte("salt-secret"), []byte("verifier-key"))
	body, err := json.Marshal(map[string]string{
		"identifier": "someone-else",
		"username":   "someone-else-too",
		"authSecret": randomAuthSecret(t),
	})
	assert.NoError(t, err)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.SetBody(body)
	ctx.SetUserValue("user", &User{PublicKey: "account-1", Username: "alice"})

	// when
	pe.SetPassword(ctx)

	// then - credential lands under the authenticated caller's OWN username
	assert.Equal(t, fasthttp.StatusNoContent, ctx.Response.StatusCode())
	userPublicKey, _, err := repo.GetPasswordCredential("alice")
	assert.NoError(t, err)
	assert.Equal(t, "account-1", userPublicKey)
	unknownPK, _, err := repo.GetPasswordCredential("someone-else")
	assert.NoError(t, err)
	assert.Empty(t, unknownPK)
}

// TestSetPassword_ShouldNotChangeHandleOnSelfReset is the COALESCE proof at
// the repository-call layer: a second SetPassword call for the SAME
// account+username must succeed and leave the previously-persisted HANDLE
// exactly as-is (see SetPasswordCredentials's doc comment), never re-pointed
// to a freshly-lowercased username.
func TestSetPassword_ShouldNotChangeHandleOnSelfReset(t *testing.T) {
	// given
	repo := newPasswordTestRepo()
	repo.accounts["account-1"] = &User{PublicKey: "account-1", Username: "alice"}
	pe := NewPasswordEndpoints(repo, []byte("salt-secret"), []byte("verifier-key"))
	firstCtx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-1", Username: "alice"}, setPasswordRequest{AuthSecret: randomAuthSecret(t)})
	pe.SetPassword(firstCtx)
	assert.Equal(t, fasthttp.StatusNoContent, firstCtx.Response.StatusCode())
	handleBefore, err := repo.GetPasswordHandle("alice")
	assert.NoError(t, err)
	assert.NotEmpty(t, handleBefore)

	// when - re-set the password for the same account+username
	secondCtx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-1", Username: "alice"}, setPasswordRequest{AuthSecret: randomAuthSecret(t)})
	pe.SetPassword(secondCtx)

	// then
	assert.Equal(t, fasthttp.StatusNoContent, secondCtx.Response.StatusCode())
	handleAfter, err := repo.GetPasswordHandle("alice")
	assert.NoError(t, err)
	assert.Equal(t, handleBefore, handleAfter)
}

func TestSetPassword_ShouldPersistEscrowBlobs(t *testing.T) {
	// given
	repo := newPasswordTestRepo()
	repo.accounts["account-1"] = &User{PublicKey: "account-1", Username: "alice"}
	pe := NewPasswordEndpoints(repo, []byte("salt-secret"), []byte("verifier-key"))
	accountKeyBlob := base64.StdEncoding.EncodeToString([]byte("sealed-account-key"))
	userState := base64.StdEncoding.EncodeToString([]byte("sealed-user-state"))
	ctx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-1", Username: "alice"}, setPasswordRequest{
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
	repo.accounts["account-1"] = &User{PublicKey: "account-1", Username: "alice"}
	pe := NewPasswordEndpoints(repo, []byte("salt-secret"), []byte("verifier-key"))
	ctx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-1", Username: "alice"}, setPasswordRequest{
		AuthSecret:     randomAuthSecret(t),
		AccountKeyBlob: base64.StdEncoding.EncodeToString([]byte("sealed-account-key")),
		UserState:      base64.StdEncoding.EncodeToString([]byte("sealed-user-state")),
	})
	pe.SetPassword(ctx)
	assert.Equal(t, fasthttp.StatusNoContent, ctx.Response.StatusCode())

	// when - re-set the password with no escrow blobs
	clearCtx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-1", Username: "alice"}, setPasswordRequest{
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
	ctx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-1", Username: "alice"}, setPasswordRequest{
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
	ctx := newSetPasswordRequestCtx(t, &User{PublicKey: "account-1", Username: "alice"}, setPasswordRequest{
		AuthSecret: randomAuthSecret(t),
		UserState:  oversized,
	})

	// when
	pe.SetPassword(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}
