//go:build integration

package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"net/url"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prappser/prappser-spaces/internal/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

// itSpace is one real space: its own schema, key and wired handlers.
type itSpace struct {
	db   *sql.DB
	repo UserRepository
	key  string
	svc  *UserService
	ue   *UserEndpoints
	ae   *AssertionEndpoints
}

func newITSpace(t *testing.T, schema string) *itSpace {
	t.Helper()
	db := testdb.Connect(t, schema)
	t.Cleanup(func() { db.Close() })
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key := base64.StdEncoding.EncodeToString(pub)
	repo := NewUserRepository(db)
	cfg := Config{JWTExpirationHours: 24, ChallengeTTLSec: 300}
	svc := NewUserService(repo, nil, cfg, priv, pub)
	ue := NewEndpoints(repo, cfg, priv, pub, svc, nil)
	b := NewBindings(repo, key)
	ue.Bindings = b
	return &itSpace{db: db, repo: repo, key: key, svc: svc, ue: ue, ae: NewAssertionEndpoints(repo, priv, key, b)}
}

func (s *itSpace) login(t *testing.T, devPriv ed25519.PrivateKey, dev, body string) *fasthttp.RequestCtx {
	t.Helper()
	cctx := &fasthttp.RequestCtx{}
	cctx.Request.SetRequestURI("/users/challenge?publicKey=" + url.QueryEscape(dev))
	s.ue.GetChallenge(cctx)
	require.Equal(t, fasthttp.StatusOK, cctx.Response.StatusCode())
	var ch ChallengeResponse
	require.NoError(t, json.Unmarshal(cctx.Response.Body(), &ch))
	jws, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"publicKey": dev, "challenge": ch.Challenge, "iat": time.Now().Unix(),
	}).SignedString(devPriv)
	require.NoError(t, err)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("Authorization", "Bearer "+jws)
	ctx.Request.SetBodyString(body)
	s.ue.UserAuth(ctx)
	return ctx
}

func tokenOf(t *testing.T, ctx *fasthttp.RequestCtx) string {
	t.Helper()
	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	var resp LoginResponse
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	return resp.Token
}

func (s *itSpace) rosterUser(t *testing.T, devPriv ed25519.PrivateKey, dev string) *User {
	t.Helper()
	u, err := s.svc.ValidateJWT(tokenOf(t, s.login(t, devPriv, dev, "")))
	require.NoError(t, err)
	return u
}

func (s *itSpace) assertionFor(t *testing.T, u *User, audience string) string {
	t.Helper()
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetBodyString(`{"audience":"` + audience + `"}`)
	ctx.SetUserValue("user", u)
	s.ae.IssueAssertion(ctx)
	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	var resp issueAssertionResponse
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	return resp.Assertion
}

func (s *itSpace) escrow(t *testing.T, acct string) string {
	t.Helper()
	blob, _, err := s.repo.GetEscrow(acct)
	require.NoError(t, err)
	return blob
}

func authBody(t *testing.T, assertion, binding string) string {
	t.Helper()
	b, err := json.Marshal(userAuthRequest{Assertion: assertion, Binding: binding})
	require.NoError(t, err)
	return string(b)
}

// itWorld is one account (device D1 = the account key, device D2) across
// the identity space O, a move target T and an external space E.
type itWorld struct {
	o, tt, e *itSpace
	acctPriv ed25519.PrivateKey
	acct     string
	d2Priv   ed25519.PrivateKey
	d2       string
}

func newITWorld(t *testing.T) *itWorld {
	t.Helper()
	w := &itWorld{o: newITSpace(t, "user_o"), tt: newITSpace(t, "user_t"), e: newITSpace(t, "user_e")}
	w.acctPriv, w.acct = newTestKey(t)
	w.d2Priv, w.d2 = newTestKey(t)
	for _, s := range []*itSpace{w.o, w.tt, w.e} {
		require.NoError(t, s.repo.CreateUser(&User{PublicKey: w.acct, Username: "alice", Role: RoleUser, CreatedAt: time.Now().Unix()}))
	}
	for _, s := range []*itSpace{w.o, w.tt} {
		require.NoError(t, s.repo.EnsureDevice(w.acct, w.acct, nil, time.Now().Unix()))
		require.NoError(t, s.repo.EnsureDevice(w.d2, w.acct, nil, time.Now().Unix()))
	}
	w.setEscrow(t, w.o)
	return w
}

func (w *itWorld) setEscrow(t *testing.T, s *itSpace) {
	t.Helper()
	_, err := s.db.Exec(`UPDATE users SET account_key_blob = 'blob' WHERE public_key = $1`, w.acct)
	require.NoError(t, err)
}

func (w *itWorld) binding(t *testing.T, iat int64, sub string) string {
	t.Helper()
	return buildBindingJWS(t, w.acctPriv, bindingTyp, w.acct, sub, iat)
}

// putBinding has D1 (the account key) PUT a binding on s.
func (w *itWorld) putBinding(t *testing.T, s *itSpace, iat int64, sub string) string {
	t.Helper()
	binding := w.binding(t, iat, sub)
	u := s.rosterUser(t, w.acctPriv, w.acct)
	body, err := json.Marshal(putBindingRequest{Binding: binding})
	require.NoError(t, err)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetBody(body)
	ctx.SetUserValue("user", u)
	s.ae.PutBinding(ctx)
	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	return binding
}

func TestIdentityBinding_ShouldEnrollDeviceOnExternalSpace_Integration(t *testing.T) {
	// given
	w := newITWorld(t)
	binding := w.putBinding(t, w.o, time.Now().Unix()-10, w.o.key)
	assertion := w.o.assertionFor(t, w.o.rosterUser(t, w.d2Priv, w.d2), w.e.key)

	// when
	ctx := w.e.login(t, w.d2Priv, w.d2, authBody(t, assertion, binding))

	// then
	u, err := w.e.svc.ValidateJWT(tokenOf(t, ctx))
	assert.NoError(t, err)
	assert.Equal(t, w.acct, u.PublicKey)
	assert.Equal(t, w.d2, u.DevicePublicKey)
	d, err := w.e.repo.GetDevice(w.d2)
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestIdentityBinding_ShouldGiveRevokedDeviceNoAssertionOnIdentitySpace_Integration(t *testing.T) {
	// given
	w := newITWorld(t)
	w.putBinding(t, w.o, time.Now().Unix()-10, w.o.key)
	token := tokenOf(t, w.o.login(t, w.d2Priv, w.d2, ""))
	require.NoError(t, w.o.repo.RevokeDevice(w.d2, time.Now().Unix()))

	// when
	_, errJWT := w.o.svc.ValidateJWT(token)
	rosterLogin := w.o.login(t, w.d2Priv, w.d2, "")

	// then
	assert.Error(t, errJWT)
	assert.Equal(t, fasthttp.StatusUnauthorized, rosterLogin.Response.StatusCode())
}

func TestIdentityBinding_ShouldReviveDeviceRevokedOnlyOnExternalSpace_Integration(t *testing.T) {
	// given
	w := newITWorld(t)
	binding := w.putBinding(t, w.o, time.Now().Unix()-10, w.o.key)
	u2 := w.o.rosterUser(t, w.d2Priv, w.d2)
	require.NoError(t, w.e.repo.EnsureDevice(w.d2, w.acct, nil, time.Now().Unix()-1000))
	require.NoError(t, w.e.repo.RevokeDevice(w.d2, time.Now().Unix()+1000))

	// when: the revocation is newer than the assertion, then older
	refused := w.e.login(t, w.d2Priv, w.d2, authBody(t, w.o.assertionFor(t, u2, w.e.key), binding))
	_, err := w.e.db.Exec(`UPDATE user_devices SET revoked_at = $1 WHERE device_public_key = $2`, time.Now().Unix()-100, w.d2)
	require.NoError(t, err)
	revived := w.e.login(t, w.d2Priv, w.d2, authBody(t, w.o.assertionFor(t, u2, w.e.key), binding))

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, refused.Response.StatusCode())
	_, errJWT := w.e.svc.ValidateJWT(tokenOf(t, revived))
	assert.NoError(t, errJWT)
	d, _ := w.e.repo.GetDevice(w.d2)
	assert.Nil(t, d.RevokedAt)
}

func TestIdentityBinding_ShouldRejectOlderBindingAndStaleTokensAfterMove_Integration(t *testing.T) {
	// given: D2 enrolled on E under binding n
	w := newITWorld(t)
	now := time.Now().Unix()
	bindingN := w.putBinding(t, w.o, now-10, w.o.key)
	assertionO := w.o.assertionFor(t, w.o.rosterUser(t, w.d2Priv, w.d2), w.e.key)
	tokenE := tokenOf(t, w.e.login(t, w.d2Priv, w.d2, authBody(t, assertionO, bindingN)))

	// when: the identity moves O -> T with binding n+1
	w.setEscrow(t, w.tt)
	bindingN1 := w.putBinding(t, w.tt, now, w.tt.key)
	w.putBinding(t, w.o, now, w.tt.key)
	assertionT := w.tt.assertionFor(t, w.tt.rosterUser(t, w.d2Priv, w.d2), w.e.key)
	learned := w.e.login(t, w.d2Priv, w.d2, authBody(t, assertionT, bindingN1))
	olderBinding := w.e.login(t, w.d2Priv, w.d2, authBody(t, assertionO, bindingN))
	oldAssertionNewBinding := w.e.login(t, w.d2Priv, w.d2, authBody(t, assertionO, bindingN1))

	// then
	assert.Equal(t, fasthttp.StatusOK, learned.Response.StatusCode())
	assert.Equal(t, fasthttp.StatusUnauthorized, olderBinding.Response.StatusCode())
	assert.JSONEq(t, `{"code":"binding_required","binding":"`+bindingN1+`"}`, string(olderBinding.Response.Body()))
	assert.Equal(t, fasthttp.StatusUnauthorized, oldAssertionNewBinding.Response.StatusCode())
	assert.NotContains(t, string(oldAssertionNewBinding.Response.Body()), "binding_required")
	_, errStale := w.e.svc.ValidateJWT(tokenE)
	assert.Error(t, errStale)
	assert.Empty(t, w.o.escrow(t, w.acct))
	assert.NotEmpty(t, w.tt.escrow(t, w.acct))
}

func TestIdentityBinding_ShouldRejectForgedOrMismatchedAdmissions_Integration(t *testing.T) {
	// given
	w := newITWorld(t)
	now := time.Now().Unix()
	binding := w.putBinding(t, w.o, now-10, w.o.key)
	u2 := w.o.rosterUser(t, w.d2Priv, w.d2)
	good := w.o.assertionFor(t, u2, w.e.key)
	attackerPriv, _ := newTestKey(t)
	_, stranger := newTestKey(t)
	d3Priv, d3 := newTestKey(t)
	cases := map[string]struct {
		devPriv ed25519.PrivateKey
		dev     string
		body    string
	}{
		"attacker binding": {w.d2Priv, w.d2, authBody(t, good, buildBindingJWS(t, attackerPriv, bindingTyp, w.acct, w.o.key, now))},
		"wrong iss":        {w.d2Priv, w.d2, authBody(t, good, buildBindingJWS(t, w.acctPriv, bindingTyp, stranger, w.o.key, now))},
		"wrong dpk":        {d3Priv, d3, authBody(t, good, binding)},
		"wrong aud":        {w.d2Priv, w.d2, authBody(t, w.o.assertionFor(t, u2, w.tt.key), binding)},
	}

	for name, c := range cases {
		// when
		ctx := w.e.login(t, c.devPriv, c.dev, c.body)

		// then
		assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode(), name)
		assert.NotContains(t, string(ctx.Response.Body()), "binding_required", name)
	}
	d, _ := w.e.repo.GetDevice(w.d2)
	assert.Nil(t, d)
}

func TestIdentityBinding_ShouldKeepSecondDeviceWorkingAfterTwoDeviceMove_Integration(t *testing.T) {
	// given: D1 moves the identity O -> T while D2 already has a row on T
	w := newITWorld(t)
	now := time.Now().Unix()
	w.setEscrow(t, w.tt)
	bindingN1 := w.putBinding(t, w.tt, now, w.tt.key)
	w.putBinding(t, w.o, now, w.tt.key)

	// when
	onO := w.o.login(t, w.d2Priv, w.d2, "")
	onT := w.tt.login(t, w.d2Priv, w.d2, "")
	assertionT := w.tt.assertionFor(t, w.tt.rosterUser(t, w.d2Priv, w.d2), w.o.key)
	viaAssertion := w.o.login(t, w.d2Priv, w.d2, authBody(t, assertionT, bindingN1))

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, onO.Response.StatusCode())
	assert.JSONEq(t, `{"code":"binding_required","binding":"`+bindingN1+`"}`, string(onO.Response.Body()))
	assert.Equal(t, fasthttp.StatusOK, onT.Response.StatusCode())
	assert.Equal(t, fasthttp.StatusOK, viaAssertion.Response.StatusCode())
}
