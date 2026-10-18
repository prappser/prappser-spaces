package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// registerTestRepo embeds a nil UserRepository so only the methods Register
// calls are implemented; any other call panics, which is the point.
type registerTestRepo struct {
	UserRepository
	count       int
	countErr    error
	registerErr error

	registerCalls int
	gotHandle     string
	gotUsername   string
	gotDeviceName *string
}

func (r *registerTestRepo) CountUsers() (int, error) { return r.count, r.countErr }

func (r *registerTestRepo) RegisterUser(publicKey, username, passwordVerifier, handle, accountKeyBlob, userState, devicePublicKey string, deviceName *string, createdAt int64) error {
	r.registerCalls++
	r.gotUsername = username
	r.gotHandle = handle
	r.gotDeviceName = deviceName
	return r.registerErr
}

func randomKeyB64(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	return base64.StdEncoding.EncodeToString(pub)
}

func validRegisterRequest(t *testing.T, username string) registerRequest {
	t.Helper()
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	assert.NoError(t, err)
	return registerRequest{
		Username:        username,
		PublicKey:       randomKeyB64(t),
		DevicePublicKey: randomKeyB64(t),
		AuthSecret:      base64.StdEncoding.EncodeToString(secret),
		AccountKeyBlob:  base64.StdEncoding.EncodeToString([]byte("sealed-account-key")),
	}
}

func newRegisterCtx(t *testing.T, body any) *fasthttp.RequestCtx {
	t.Helper()
	b, err := json.Marshal(body)
	assert.NoError(t, err)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.SetBody(b)
	return ctx
}

func newOpenRegisterEndpoints(repo UserRepository, maxAccounts int) *RegisterEndpoints {
	return NewRegisterEndpoints(repo, []byte("verifier-key"), true, maxAccounts)
}

func TestRegister_ShouldReturnRegistrationClosedEvenForGarbageBody(t *testing.T) {
	// given
	repo := &registerTestRepo{}
	re := NewRegisterEndpoints(repo, []byte("verifier-key"), false, 0)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetBody([]byte("not json"))

	// when
	re.Register(ctx)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	assert.Equal(t, "application/json", string(ctx.Response.Header.ContentType()))
	assert.JSONEq(t, `{"error":"registration is closed on this space","code":"registration_closed"}`, string(ctx.Response.Body()))
	assert.Equal(t, 0, repo.registerCalls)
}

func TestRegister_ShouldRejectInvalidRequestsWith400(t *testing.T) {
	bigState := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 64*1024)))
	cases := []struct {
		name   string
		mutate func(r *registerRequest)
	}{
		{"empty username", func(r *registerRequest) { r.Username = "  " }},
		{"bad publicKey", func(r *registerRequest) { r.PublicKey = "nope" }},
		{"missing devicePublicKey", func(r *registerRequest) { r.DevicePublicKey = "" }},
		{"bad devicePublicKey", func(r *registerRequest) { r.DevicePublicKey = "nope" }},
		{"missing authSecret", func(r *registerRequest) { r.AuthSecret = "" }},
		{"bad authSecret", func(r *registerRequest) { r.AuthSecret = base64.StdEncoding.EncodeToString([]byte("short")) }},
		{"missing accountKeyBlob", func(r *registerRequest) { r.AccountKeyBlob = "" }},
		{"oversized accountKeyBlob", func(r *registerRequest) { r.AccountKeyBlob = strings.Repeat("A", 513) }},
		{"oversized userState", func(r *registerRequest) { r.UserState = bigState }},
	}
	for _, tc := range cases {
		// given
		repo := &registerTestRepo{}
		re := newOpenRegisterEndpoints(repo, 0)
		req := validRegisterRequest(t, "alice")
		tc.mutate(&req)
		ctx := newRegisterCtx(t, req)

		// when
		re.Register(ctx)

		// then
		assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode(), tc.name)
		assert.NotEqual(t, "application/json", string(ctx.Response.Header.ContentType()), tc.name)
		assert.Equal(t, 0, repo.registerCalls, tc.name)
	}
}

func TestRegister_ShouldRejectBadJSONWith400(t *testing.T) {
	// given
	repo := &registerTestRepo{}
	re := newOpenRegisterEndpoints(repo, 0)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetBody([]byte("{"))

	// when
	re.Register(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	assert.Equal(t, 0, repo.registerCalls)
}

func TestRegister_ShouldReturnAccountLimitReachedWhenCountAtCap(t *testing.T) {
	// given
	repo := &registerTestRepo{count: 3}
	re := newOpenRegisterEndpoints(repo, 3)
	ctx := newRegisterCtx(t, validRegisterRequest(t, "alice"))

	// when
	re.Register(ctx)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	assert.Equal(t, "application/json", string(ctx.Response.Header.ContentType()))
	assert.JSONEq(t, `{"error":"this space is not accepting new accounts","code":"account_limit_reached"}`, string(ctx.Response.Body()))
	assert.Equal(t, 0, repo.registerCalls)
}

func TestRegister_ShouldNotCountWhenMaxAccountsIsZero(t *testing.T) {
	// given
	repo := &registerTestRepo{count: 1000, countErr: errors.New("must not be called")}
	re := newOpenRegisterEndpoints(repo, 0)
	ctx := newRegisterCtx(t, validRegisterRequest(t, "alice"))

	// when
	re.Register(ctx)

	// then
	assert.Equal(t, fasthttp.StatusCreated, ctx.Response.StatusCode())
}

func TestRegister_ShouldReturn500WhenCountFails(t *testing.T) {
	// given
	repo := &registerTestRepo{countErr: errors.New("db down")}
	re := newOpenRegisterEndpoints(repo, 5)
	ctx := newRegisterCtx(t, validRegisterRequest(t, "alice"))

	// when
	re.Register(ctx)

	// then
	assert.Equal(t, fasthttp.StatusInternalServerError, ctx.Response.StatusCode())
	assert.Equal(t, 0, repo.registerCalls)
}

func TestRegister_ShouldMapRepositoryErrorsTo409Codes(t *testing.T) {
	cases := []struct {
		err  error
		code string
	}{
		{ErrUsernameTaken, "username_taken"},
		{ErrAccountExists, "account_exists"},
		{ErrDeviceKeyTaken, "device_key_taken"},
	}
	for _, tc := range cases {
		// given
		repo := &registerTestRepo{registerErr: tc.err}
		re := newOpenRegisterEndpoints(repo, 0)
		ctx := newRegisterCtx(t, validRegisterRequest(t, "alice"))

		// when
		re.Register(ctx)

		// then
		var body map[string]string
		assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &body), tc.code)
		assert.Equal(t, fasthttp.StatusConflict, ctx.Response.StatusCode(), tc.code)
		assert.Equal(t, tc.code, body["code"])
		assert.NotEmpty(t, body["error"], tc.code)
	}
}

func TestRegister_ShouldReturn500ForUnexpectedRepositoryError(t *testing.T) {
	// given
	repo := &registerTestRepo{registerErr: errors.New("boom")}
	re := newOpenRegisterEndpoints(repo, 0)
	ctx := newRegisterCtx(t, validRegisterRequest(t, "alice"))

	// when
	re.Register(ctx)

	// then
	assert.Equal(t, fasthttp.StatusInternalServerError, ctx.Response.StatusCode())
}

func TestRegister_ShouldReturn201AndStoreLowercasedHandle(t *testing.T) {
	// given
	repo := &registerTestRepo{}
	re := newOpenRegisterEndpoints(repo, 0)
	req := validRegisterRequest(t, "Alice")
	ctx := newRegisterCtx(t, req)

	// when
	re.Register(ctx)

	// then
	assert.Equal(t, fasthttp.StatusCreated, ctx.Response.StatusCode())
	assert.Equal(t, "application/json", string(ctx.Response.Header.ContentType()))
	var body map[string]any
	assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &body))
	assert.Equal(t, req.PublicKey, body["userPublicKey"])
	assert.Equal(t, "Alice", body["username"])
	assert.Equal(t, "user", body["role"])
	assert.Greater(t, body["createdAt"], float64(0))
	assert.Equal(t, "Alice", repo.gotUsername)
	assert.Equal(t, "alice", repo.gotHandle)
	assert.Nil(t, repo.gotDeviceName)
}

func TestRegister_ShouldPassDeviceNameWhenGiven(t *testing.T) {
	// given
	repo := &registerTestRepo{}
	re := newOpenRegisterEndpoints(repo, 0)
	req := validRegisterRequest(t, "alice")
	req.DeviceName = "Pixel"
	ctx := newRegisterCtx(t, req)

	// when
	re.Register(ctx)

	// then
	assert.Equal(t, fasthttp.StatusCreated, ctx.Response.StatusCode())
	if assert.NotNil(t, repo.gotDeviceName) {
		assert.Equal(t, "Pixel", *repo.gotDeviceName)
	}
}

func TestRegistrationOpen_ShouldReflectFlagCapAndCountErrors(t *testing.T) {
	closed := NewRegisterEndpoints(&registerTestRepo{}, nil, false, 0)
	assert.False(t, closed.RegistrationOpen())

	underCap := newOpenRegisterEndpoints(&registerTestRepo{count: 1}, 2)
	assert.True(t, underCap.RegistrationOpen())

	atCap := newOpenRegisterEndpoints(&registerTestRepo{count: 2}, 2)
	assert.False(t, atCap.RegistrationOpen())

	countFails := newOpenRegisterEndpoints(&registerTestRepo{countErr: errors.New("db down")}, 2)
	assert.False(t, countFails.RegistrationOpen())
}
