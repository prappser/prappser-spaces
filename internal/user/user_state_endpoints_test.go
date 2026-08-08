package user

import (
	"encoding/base64"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

func newUpdateUserStateRequestCtx(t *testing.T, authenticatedUser *User, body updateUserStateRequest) *fasthttp.RequestCtx {
	t.Helper()
	b, err := json.Marshal(body)
	assert.NoError(t, err)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("PUT")
	ctx.Request.SetBody(b)
	if authenticatedUser != nil {
		ctx.SetUserValue("user", authenticatedUser)
	}
	return ctx
}

// TestUpdateUserState_ShouldPersistAndBeReadableViaGetProfile covers the
// happy path end to end: the account-key device refreshes the escrow, and
// GetProfile (the other half of #137's wire contract) reads it straight
// back.
func TestUpdateUserState_ShouldPersistAndBeReadableViaGetProfile(t *testing.T) {
	// given
	repo := newPasswordTestRepo()
	repo.accounts["account-1"] = &User{PublicKey: "account-1", Username: "alice"}
	pe := NewPasswordEndpoints(repo, []byte("salt-secret"), []byte("verifier-key"))
	blob := base64.StdEncoding.EncodeToString([]byte("sealed-user-state"))
	ctx := newUpdateUserStateRequestCtx(t, &User{PublicKey: "account-1", DevicePublicKey: "account-1"}, updateUserStateRequest{UserState: blob})

	// when
	pe.UpdateUserState(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNoContent, ctx.Response.StatusCode())
	_, gotUserState, err := repo.GetEscrow("account-1")
	assert.NoError(t, err)
	assert.Equal(t, blob, gotUserState)

	ue := UserEndpoints{userRepository: repo}
	profileCtx := &fasthttp.RequestCtx{}
	profileCtx.SetUserValue("user", &User{PublicKey: "account-1", DevicePublicKey: "account-1", Username: "alice"})
	ue.GetProfile(profileCtx)
	var profile User
	assert.NoError(t, json.Unmarshal(profileCtx.Response.Body(), &profile))
	assert.Equal(t, blob, profile.UserStateBlob)
}

// TestUpdateUserState_ShouldReturn403ForSecondaryDevice covers the
// account-key-device-only guard: a JWT whose DevicePublicKey differs from
// the account's PublicKey (a secondary device) must be rejected.
func TestUpdateUserState_ShouldReturn403ForSecondaryDevice(t *testing.T) {
	// given
	repo := newPasswordTestRepo()
	repo.accounts["account-1"] = &User{PublicKey: "account-1", Username: "alice"}
	pe := NewPasswordEndpoints(repo, []byte("salt-secret"), []byte("verifier-key"))
	blob := base64.StdEncoding.EncodeToString([]byte("sealed-user-state"))
	ctx := newUpdateUserStateRequestCtx(t, &User{PublicKey: "account-1", DevicePublicKey: "device-2"}, updateUserStateRequest{UserState: blob})

	// when
	pe.UpdateUserState(ctx)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	_, gotUserState, err := repo.GetEscrow("account-1")
	assert.NoError(t, err)
	assert.Empty(t, gotUserState)
}

func TestUpdateUserState_ShouldReturn400ForOversizedBlob(t *testing.T) {
	// given
	pe := NewPasswordEndpoints(newPasswordTestRepo(), []byte("salt-secret"), []byte("verifier-key"))
	oversized := base64.StdEncoding.EncodeToString(make([]byte, maxUserStateBlobLen+1))
	ctx := newUpdateUserStateRequestCtx(t, &User{PublicKey: "account-1", DevicePublicKey: "account-1"}, updateUserStateRequest{UserState: oversized})

	// when
	pe.UpdateUserState(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestUpdateUserState_ShouldReturn400ForNonBase64Blob(t *testing.T) {
	// given
	pe := NewPasswordEndpoints(newPasswordTestRepo(), []byte("salt-secret"), []byte("verifier-key"))
	ctx := newUpdateUserStateRequestCtx(t, &User{PublicKey: "account-1", DevicePublicKey: "account-1"}, updateUserStateRequest{UserState: "not-valid-base64!!"})

	// when
	pe.UpdateUserState(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

// TestUpdateUserState_ShouldClearToNullOnEmptyString covers the NULLIF
// clear-on-empty contract (see user_repository.go's UpdateUserState).
func TestUpdateUserState_ShouldClearToNullOnEmptyString(t *testing.T) {
	// given
	repo := newPasswordTestRepo()
	repo.accounts["account-1"] = &User{PublicKey: "account-1", Username: "alice"}
	pe := NewPasswordEndpoints(repo, []byte("salt-secret"), []byte("verifier-key"))
	blob := base64.StdEncoding.EncodeToString([]byte("sealed-user-state"))
	setCtx := newUpdateUserStateRequestCtx(t, &User{PublicKey: "account-1", DevicePublicKey: "account-1"}, updateUserStateRequest{UserState: blob})
	pe.UpdateUserState(setCtx)
	assert.Equal(t, fasthttp.StatusNoContent, setCtx.Response.StatusCode())

	// when
	clearCtx := newUpdateUserStateRequestCtx(t, &User{PublicKey: "account-1", DevicePublicKey: "account-1"}, updateUserStateRequest{UserState: ""})
	pe.UpdateUserState(clearCtx)

	// then
	assert.Equal(t, fasthttp.StatusNoContent, clearCtx.Response.StatusCode())
	_, gotUserState, err := repo.GetEscrow("account-1")
	assert.NoError(t, err)
	assert.Empty(t, gotUserState)
}

func TestUpdateUserState_ShouldReturn401WhenUnauthenticated(t *testing.T) {
	// given
	pe := NewPasswordEndpoints(newPasswordTestRepo(), []byte("salt-secret"), []byte("verifier-key"))
	ctx := newUpdateUserStateRequestCtx(t, nil, updateUserStateRequest{UserState: ""})

	// when
	pe.UpdateUserState(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}
