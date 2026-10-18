//go:build integration

package user

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"

	"github.com/prappser/prappser-spaces/internal/health"
)

var (
	registerTestSaltSecret, registerTestVerifierKey = DerivePasswordSecrets([]byte("register-integration-seed"))
	registerTestSpaceKey                            = base64.StdEncoding.EncodeToString(make([]byte, 32))
)

func uniqueUsername(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 4)
	_, err := rand.Read(b)
	assert.NoError(t, err)
	return prefix + hex.EncodeToString(b)
}

func newRegisterIntegrationEndpoints(t *testing.T, open bool, maxAccounts int) (*sql.DB, UserRepository, *RegisterEndpoints) {
	t.Helper()
	db := getTestDB(t)
	t.Cleanup(func() { db.Close() })
	repo := NewUserRepository(db)
	return db, repo, NewRegisterEndpoints(repo, registerTestVerifierKey, open, maxAccounts)
}

func cleanupRegistered(t *testing.T, db *sql.DB, req registerRequest) {
	t.Helper()
	t.Cleanup(func() {
		_, err := db.Exec("DELETE FROM user_devices WHERE user_public_key = $1 OR device_public_key = $2", req.PublicKey, req.DevicePublicKey)
		assert.NoError(t, err)
		_, err = db.Exec("DELETE FROM users WHERE public_key = $1", req.PublicKey)
		assert.NoError(t, err)
	})
}

func register(t *testing.T, db *sql.DB, re *RegisterEndpoints, req registerRequest) *fasthttp.RequestCtx {
	t.Helper()
	cleanupRegistered(t, db, req)
	ctx := newRegisterCtx(t, req)
	re.Register(ctx)
	return ctx
}

func responseCode(t *testing.T, ctx *fasthttp.RequestCtx) string {
	t.Helper()
	var body map[string]string
	assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &body))
	return body["code"]
}

func getSalt(t *testing.T, repo UserRepository, username string) string {
	t.Helper()
	pe := NewPasswordEndpoints(repo, registerTestSaltSecret, registerTestVerifierKey)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/users/salt?username=" + username)
	pe.GetSalt(ctx)
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	return string(ctx.Response.Body())
}

func countRows(t *testing.T, db *sql.DB, query string) int {
	t.Helper()
	var n int
	assert.NoError(t, db.QueryRow(query).Scan(&n))
	return n
}

func TestRegister_ShouldPersistAccountAndKeepSaltStable_Integration(t *testing.T) {
	// given
	db, repo, re := newRegisterIntegrationEndpoints(t, true, 0)
	username := uniqueUsername(t, "Mixed")
	req := validRegisterRequest(t, username)
	claimsBefore := countRows(t, db, "SELECT COUNT(*) FROM space_owner_claim")
	spacesBefore := countRows(t, db, "SELECT COUNT(*) FROM spaces")
	saltBefore := getSalt(t, repo, username)

	// when
	ctx := register(t, db, re, req)
	saltAfter := getSalt(t, repo, username)

	// then
	assert.Equal(t, fasthttp.StatusCreated, ctx.Response.StatusCode())
	assert.Equal(t, saltBefore, saltAfter)
	var role, issuer, handle string
	assert.NoError(t, db.QueryRow("SELECT role, issuer, password_handle FROM users WHERE public_key = $1", req.PublicKey).Scan(&role, &issuer, &handle))
	assert.Equal(t, "user", role)
	assert.Equal(t, req.PublicKey, issuer)
	assert.Equal(t, strings.ToLower(username), handle)
	assert.Equal(t, claimsBefore, countRows(t, db, "SELECT COUNT(*) FROM space_owner_claim"))
	assert.Equal(t, spacesBefore, countRows(t, db, "SELECT COUNT(*) FROM spaces"))
}

func TestRegister_ShouldLetPasswordDeviceEnrollmentReturnEscrow_Integration(t *testing.T) {
	// given
	db, repo, re := newRegisterIntegrationEndpoints(t, true, 0)
	req := validRegisterRequest(t, uniqueUsername(t, "Dev"))
	req.UserState = base64.StdEncoding.EncodeToString([]byte("sealed-user-state"))
	assert.Equal(t, fasthttp.StatusCreated, register(t, db, re, req).Response.StatusCode())
	newDevice := randomKeyB64(t)
	t.Cleanup(func() { db.Exec("DELETE FROM user_devices WHERE device_public_key = $1", newDevice) })
	de := NewDeviceEndpoints(repo, registerTestVerifierKey, registerTestSpaceKey)
	ctx := newRegisterCtx(t, registerDeviceRequest{Username: req.Username, AuthSecret: req.AuthSecret, DevicePublicKey: newDevice})

	// when
	de.RegisterDevice(ctx)

	// then
	assert.Equal(t, fasthttp.StatusCreated, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	var resp registerDeviceResponse
	assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	assert.Equal(t, req.PublicKey, resp.UserPublicKey)
	assert.Equal(t, req.AccountKeyBlob, resp.AccountKeyBlob)
	assert.Equal(t, req.UserState, resp.UserState)
}

func TestRegister_ShouldRejectUsernameCaseInsensitivelyViaIndex_Integration(t *testing.T) {
	// given
	db, _, re := newRegisterIntegrationEndpoints(t, true, 0)
	name := uniqueUsername(t, "Alice")
	first := validRegisterRequest(t, name)
	second := validRegisterRequest(t, strings.ToLower(name))
	assert.Equal(t, fasthttp.StatusCreated, register(t, db, re, first).Response.StatusCode())

	// when
	ctx := register(t, db, re, second)

	// then
	assert.Equal(t, fasthttp.StatusConflict, ctx.Response.StatusCode())
	assert.Equal(t, "username_taken", responseCode(t, ctx))
	assert.Equal(t, 0, countRows(t, db, "SELECT COUNT(*) FROM users WHERE public_key = '"+second.PublicKey+"'"))
}

func TestRegister_ShouldReturnAccountExistsForReusedPublicKey_Integration(t *testing.T) {
	// given
	db, _, re := newRegisterIntegrationEndpoints(t, true, 0)
	first := validRegisterRequest(t, uniqueUsername(t, "Pk"))
	again := validRegisterRequest(t, uniqueUsername(t, "Pk"))
	again.PublicKey = first.PublicKey
	assert.Equal(t, fasthttp.StatusCreated, register(t, db, re, first).Response.StatusCode())

	// when
	ctx := register(t, db, re, again)

	// then
	assert.Equal(t, fasthttp.StatusConflict, ctx.Response.StatusCode())
	assert.Equal(t, "account_exists", responseCode(t, ctx))
}

func TestRegister_ShouldReturnAccountExistsForIdenticalRetry_Integration(t *testing.T) {
	// given
	db, _, re := newRegisterIntegrationEndpoints(t, true, 0)
	req := validRegisterRequest(t, uniqueUsername(t, "Retry"))
	assert.Equal(t, fasthttp.StatusCreated, register(t, db, re, req).Response.StatusCode())

	// when
	ctx := register(t, db, re, req)

	// then
	assert.Equal(t, fasthttp.StatusConflict, ctx.Response.StatusCode())
	assert.Equal(t, "account_exists", responseCode(t, ctx))
}

func TestRegister_ShouldReturnDeviceKeyTakenAndRollBackUserRow_Integration(t *testing.T) {
	// given
	db, _, re := newRegisterIntegrationEndpoints(t, true, 0)
	first := validRegisterRequest(t, uniqueUsername(t, "Dk"))
	reused := validRegisterRequest(t, uniqueUsername(t, "Dk"))
	reused.DevicePublicKey = first.DevicePublicKey
	assert.Equal(t, fasthttp.StatusCreated, register(t, db, re, first).Response.StatusCode())

	// when
	ctx := register(t, db, re, reused)

	// then
	assert.Equal(t, fasthttp.StatusConflict, ctx.Response.StatusCode())
	assert.Equal(t, "device_key_taken", responseCode(t, ctx))
	assert.Equal(t, 0, countRows(t, db, "SELECT COUNT(*) FROM users WHERE public_key = '"+reused.PublicKey+"'"))
}

func TestRegister_ShouldRefuseWhenClosedWithoutWriting_Integration(t *testing.T) {
	// given
	db, _, re := newRegisterIntegrationEndpoints(t, false, 0)
	req := validRegisterRequest(t, uniqueUsername(t, "Closed"))

	// when
	ctx := register(t, db, re, req)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	assert.Equal(t, "registration_closed", responseCode(t, ctx))
	assert.Equal(t, 0, countRows(t, db, "SELECT COUNT(*) FROM users WHERE public_key = '"+req.PublicKey+"'"))
}

func TestRegister_ShouldRefuseAtAccountCapWithoutWriting_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	t.Cleanup(func() { db.Close() })
	repo := NewUserRepository(db)
	existing := validRegisterRequest(t, uniqueUsername(t, "Seed"))
	register(t, db, NewRegisterEndpoints(repo, registerTestVerifierKey, true, 0), existing)
	current, err := repo.CountUsers()
	assert.NoError(t, err)
	re := NewRegisterEndpoints(repo, registerTestVerifierKey, true, current)
	req := validRegisterRequest(t, uniqueUsername(t, "Cap"))

	// when
	ctx := register(t, db, re, req)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	assert.Equal(t, "account_limit_reached", responseCode(t, ctx))
	assert.Equal(t, 0, countRows(t, db, "SELECT COUNT(*) FROM users WHERE public_key = '"+req.PublicKey+"'"))
}

func TestRegister_ShouldFlipHealthRegistrationOpenWhenCapIsHit_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	t.Cleanup(func() { db.Close() })
	repo := NewUserRepository(db)
	current, err := repo.CountUsers()
	assert.NoError(t, err)
	re := NewRegisterEndpoints(repo, registerTestVerifierKey, true, current+1)
	he := health.NewEndpoints("test", re.RegistrationOpen)
	registrationOpen := func() bool {
		ctx := &fasthttp.RequestCtx{}
		he.Health(ctx)
		var body map[string]any
		assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &body))
		open, _ := body["registrationOpen"].(bool)
		return open
	}
	assert.True(t, registrationOpen())

	// when
	ctx := register(t, db, re, validRegisterRequest(t, uniqueUsername(t, "Last")))

	// then
	assert.Equal(t, fasthttp.StatusCreated, ctx.Response.StatusCode())
	assert.False(t, registrationOpen())
}
