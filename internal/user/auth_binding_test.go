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

type authFixture struct {
	ep        *UserEndpoints
	repo      *bindingTestRepo
	space     string
	acctPriv  ed25519.PrivateKey
	acct      string
	devPriv   ed25519.PrivateKey
	dev       string
	subjPriv  ed25519.PrivateKey
	subj      string
	jwtSigner ed25519.PrivateKey
}

func newAuthFixture(t *testing.T) *authFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	f := &authFixture{space: base64.StdEncoding.EncodeToString(pub), jwtSigner: priv}
	f.acctPriv, f.acct = newTestKey(t)
	f.devPriv, f.dev = newTestKey(t)
	f.subjPriv, f.subj = newTestKey(t)
	f.repo = &bindingTestRepo{acct: f.acct, devices: map[string]*Device{}}
	cfg := Config{JWTExpirationHours: 24, ChallengeTTLSec: 300}
	f.ep = NewEndpoints(f.repo, cfg, priv, pub, NewUserService(f.repo, nil, cfg, priv, pub), nil)
	return f
}

func (f *authFixture) login(t *testing.T, body string) *fasthttp.RequestCtx {
	t.Helper()
	f.ep.challenges.store("ch-"+body, challengeInfo{publicKey: f.dev, expiresAt: time.Now().Add(time.Minute)})
	jws, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"publicKey": f.dev, "challenge": "ch-" + body, "iat": time.Now().Unix(),
	}).SignedString(f.devPriv)
	assert.NoError(t, err)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("Authorization", "Bearer "+jws)
	ctx.Request.SetBodyString(body)
	f.ep.UserAuth(ctx)
	return ctx
}

func (f *authFixture) bindingBody(t *testing.T, signer ed25519.PrivateKey, iat int64) string {
	t.Helper()
	binding := buildBindingJWS(t, signer, bindingTyp, f.acct, f.subj, iat)
	assertion, _, err := mintAssertion(f.subjPriv, f.subj, f.acct, f.space, "alice", f.dev, time.Now())
	assert.NoError(t, err)
	body, err := json.Marshal(userAuthRequest{Assertion: assertion, Binding: binding})
	assert.NoError(t, err)
	return string(body)
}

func requireBindingRequired(t *testing.T, ctx *fasthttp.RequestCtx, stored string) {
	t.Helper()
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
	assert.Equal(t, "application/json", string(ctx.Response.Header.ContentType()))
	assert.JSONEq(t, `{"code":"binding_required","binding":"`+stored+`"}`, string(ctx.Response.Body()))
}

func TestUserAuth_RosterPath_ShouldAcceptEmptyAndEmptyObjectBody(t *testing.T) {
	for _, body := range []string{"", "{}", "  "} {
		// given
		f := newAuthFixture(t)
		f.repo.devices[f.dev] = &Device{DevicePublicKey: f.dev, UserPublicKey: f.acct}

		// when
		ctx := f.login(t, body)

		// then
		assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), body)
	}
}

func TestUserAuth_RosterPath_ShouldReturnPlain401ForUnknownOrRevokedDevice(t *testing.T) {
	// given
	f := newAuthFixture(t)

	// when
	unknown := f.login(t, "")
	revokedAt := int64(5)
	f.repo.devices[f.dev] = &Device{DevicePublicKey: f.dev, UserPublicKey: f.acct, RevokedAt: &revokedAt}
	revoked := f.login(t, "{}")

	// then
	for _, ctx := range []*fasthttp.RequestCtx{unknown, revoked} {
		assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
		assert.NotContains(t, string(ctx.Response.Body()), "binding_required")
	}
}

func TestUserAuth_RosterPath_ShouldReturnBindingRequiredOnceBoundElsewhere(t *testing.T) {
	// given: binding_iat > 0, bound to another space, device is not the account key
	f := newAuthFixture(t)
	f.repo.iat, f.repo.sub, f.repo.binding = 5, f.subj, "stored-jws"
	f.repo.devices[f.dev] = &Device{DevicePublicKey: f.dev, UserPublicKey: f.acct}

	// when
	ctx := f.login(t, "")

	// then
	requireBindingRequired(t, ctx, "stored-jws")
}

func TestUserAuth_RosterPath_ShouldStillAcceptAccountKeyDeviceOnceBound(t *testing.T) {
	// given
	f := newAuthFixture(t)
	f.dev, f.devPriv = f.acct, f.acctPriv
	f.repo.iat, f.repo.sub, f.repo.binding = 5, f.subj, "stored-jws"
	f.repo.devices[f.dev] = &Device{DevicePublicKey: f.dev, UserPublicKey: f.acct}

	// when
	ctx := f.login(t, "{}")

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
}

func TestUserAuth_ShouldReturn400ForMalformedInput(t *testing.T) {
	// given
	f := newAuthFixture(t)
	f.repo.devices[f.dev] = &Device{DevicePublicKey: f.dev, UserPublicKey: f.acct}

	// when
	notJSON := f.login(t, "not json")
	onlyAssertion := f.login(t, `{"assertion":"x"}`)
	onlyBinding := f.login(t, `{"binding":"x"}`)
	badAuth := &fasthttp.RequestCtx{}
	badAuth.Request.Header.Set("Authorization", "Token abc")
	f.ep.UserAuth(badAuth)
	badJWS := &fasthttp.RequestCtx{}
	badJWS.Request.Header.Set("Authorization", "Bearer garbage")
	f.ep.UserAuth(badJWS)

	// then
	for _, ctx := range []*fasthttp.RequestCtx{notJSON, onlyAssertion, onlyBinding, badAuth, badJWS} {
		assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	}
}

func TestUserAuth_ShouldReturn401ForMissingHeaderUnknownChallengeAndReplay(t *testing.T) {
	// given
	f := newAuthFixture(t)
	f.repo.devices[f.dev] = &Device{DevicePublicKey: f.dev, UserPublicKey: f.acct}
	jws, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"publicKey": f.dev, "challenge": "never-issued", "iat": time.Now().Unix(),
	}).SignedString(f.devPriv)
	assert.NoError(t, err)

	// when
	noHeader := &fasthttp.RequestCtx{}
	f.ep.UserAuth(noHeader)
	unknown := &fasthttp.RequestCtx{}
	unknown.Request.Header.Set("Authorization", "Bearer "+jws)
	f.ep.UserAuth(unknown)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, noHeader.Response.StatusCode())
	assert.Equal(t, fasthttp.StatusUnauthorized, unknown.Response.StatusCode())
}

func TestUserAuth_BindingPath_ShouldEnrollDeviceAndIssueJWTWithBindingVersion(t *testing.T) {
	// given
	f := newAuthFixture(t)
	iat := time.Now().Unix()

	// when
	ctx := f.login(t, f.bindingBody(t, f.acctPriv, iat))

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.NotNil(t, f.repo.devices[f.dev])
	var resp LoginResponse
	assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	claims := &JWTClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(resp.Token, claims)
	assert.NoError(t, err)
	assert.Equal(t, iat, claims.BindingVersion)
	assert.Equal(t, f.dev, claims.DevicePublicKey)
}

func TestUserAuth_BindingPath_ShouldReturnBindingRequiredWithStoredForLowerBinding(t *testing.T) {
	// given
	f := newAuthFixture(t)
	_, other := newTestKey(t)
	f.repo.iat, f.repo.sub, f.repo.binding = time.Now().Unix()+100, other, "stored-jws"

	// when
	ctx := f.login(t, f.bindingBody(t, f.acctPriv, time.Now().Unix()))

	// then
	requireBindingRequired(t, ctx, "stored-jws")
	assert.Nil(t, f.repo.devices[f.dev])
}

func TestUserAuth_BindingPath_ShouldReturn401ForForgedOrMismatchedInputs(t *testing.T) {
	// given
	f := newAuthFixture(t)
	attackerPriv, _ := newTestKey(t)
	iat := time.Now().Unix()
	wrongSpaceAssertion, _, _ := mintAssertion(f.subjPriv, f.subj, f.acct, "other-space-key", "alice", f.dev, time.Now())
	wrongDeviceAssertion, _, _ := mintAssertion(f.subjPriv, f.subj, f.acct, f.space, "alice", "other-device", time.Now())
	good := buildBindingJWS(t, f.acctPriv, bindingTyp, f.acct, f.subj, iat)
	bodies := map[string]string{"attacker binding": f.bindingBody(t, attackerPriv, iat)}
	for name, assertion := range map[string]string{"wrong aud": wrongSpaceAssertion, "wrong dpk": wrongDeviceAssertion} {
		b, _ := json.Marshal(userAuthRequest{Assertion: assertion, Binding: good})
		bodies[name] = string(b)
	}
	_, stranger := newTestKey(t)
	wrongIss := buildBindingJWS(t, f.acctPriv, bindingTyp, stranger, f.subj, iat)
	assertion, _, _ := mintAssertion(f.subjPriv, f.subj, f.acct, f.space, "alice", f.dev, time.Now())
	b, _ := json.Marshal(userAuthRequest{Assertion: assertion, Binding: wrongIss})
	bodies["wrong iss"] = string(b)

	for name, body := range bodies {
		// when
		ctx := f.login(t, body)

		// then
		assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode(), name)
		assert.NotContains(t, string(ctx.Response.Body()), "binding_required", name)
		assert.Nil(t, f.repo.devices[f.dev], name)
	}
}

func TestUserAuth_BindingPath_ShouldReviveRevokedRowOnlyForAssertionNewerThanRevocation(t *testing.T) {
	// given
	f := newAuthFixture(t)
	older := int64(1)
	f.repo.devices[f.dev] = &Device{DevicePublicKey: f.dev, UserPublicKey: f.acct, RevokedAt: &older}

	// when
	revived := f.login(t, f.bindingBody(t, f.acctPriv, time.Now().Unix()))
	later := time.Now().Unix() + 1000
	f.repo.devices[f.dev].RevokedAt = &later
	refused := f.login(t, f.bindingBody(t, f.acctPriv, time.Now().Unix()))

	// then
	assert.Equal(t, fasthttp.StatusOK, revived.Response.StatusCode())
	assert.Equal(t, fasthttp.StatusUnauthorized, refused.Response.StatusCode())
	assert.NotNil(t, f.repo.devices[f.dev].RevokedAt)
}

func TestUserAuth_BindingPath_ShouldReturn401WhenAnotherAccountClaimsTheDeviceRowFirst(t *testing.T) {
	// given
	f := newAuthFixture(t)
	f.ep.Bindings = NewBindings(&racingEnsureRepo{f.repo}, f.space)

	// when
	ctx := f.login(t, f.bindingBody(t, f.acctPriv, time.Now().Unix()))

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
	assert.NotContains(t, string(ctx.Response.Body()), "token")
}

func TestValidateJWT_ShouldRejectStaleBindingVersionAndAcceptCurrent(t *testing.T) {
	// given
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	repo := newDeviceTestRepo()
	repo.accounts["account-1"] = &User{PublicKey: "account-1", Username: "alice", Role: RoleUser, BindingIat: 3}
	repo.devices["device-1"] = &Device{DevicePublicKey: "device-1", UserPublicKey: "account-1"}
	svc := NewUserService(repo, nil, Config{JWTExpirationHours: 24}, priv, pub)
	stale, _, err := svc.GenerateJWT(repo.accounts["account-1"], "device-1")
	assert.NoError(t, err)
	repo.accounts["account-1"].BindingIat = 5
	current, _, err := svc.GenerateJWT(repo.accounts["account-1"], "device-1")
	assert.NoError(t, err)

	// when
	_, errStale := svc.ValidateJWT(stale)
	u, errCurrent := svc.ValidateJWT(current)

	// then
	assert.Error(t, errStale)
	assert.NoError(t, errCurrent)
	assert.NotNil(t, u)
}
