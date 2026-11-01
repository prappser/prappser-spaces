//go:build integration

package oauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/middleware"
	"github.com/prappser/prappser-spaces/internal/testdb"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

type fixture struct {
	t         *testing.T
	db        *sql.DB
	svc       *Service
	endpoints *Endpoints
	users     user.UserRepository
	userSvc   *user.UserService
	agents    *user.AgentService
	auth      *middleware.AuthMiddleware
	clientID  string
}

func newFixture(t *testing.T, mutateDoc func(d map[string]any)) *fixture {
	t.Helper()
	db := testdb.Connect(t, "oauth")
	t.Cleanup(func() { db.Close() })
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	users := user.NewUserRepository(db)
	userSvc := user.NewUserService(users, nil, user.Config{JWTExpirationHours: 24}, priv, pub)
	agents := user.NewAgentService(db, users, priv, pub, testIssuer)

	f := &fixture{t: t, db: db, users: users, userSvc: userSvc, agents: agents, auth: middleware.NewAuthMiddleware(userSvc)}
	srv, fetcher := docServer(t, func(w http.ResponseWriter, r *http.Request) {
		doc := goodDoc(f.clientID)
		if mutateDoc != nil {
			mutateDoc(doc)
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	f.clientID = srv.URL + "/client.json"
	f.svc = NewService(agents, users, testIssuer, "https://app.test")
	f.svc.fetcher = fetcher
	f.endpoints = NewEndpoints(f.svc, false)
	return f
}

// human creates an account with one human device and returns its public key and JWT.
func (f *fixture) human() (string, string) {
	f.t.Helper()
	pk := "oauth-user-" + rand.Text()
	require.NoError(f.t, f.users.CreateUser(&user.User{PublicKey: pk, Username: pk, Role: user.RoleUser, CreatedAt: time.Now().Unix()}))
	require.NoError(f.t, f.users.EnsureDevice(pk, pk, nil, time.Now().Unix()))
	jwt, _, err := f.userSvc.GenerateJWT(&user.User{PublicKey: pk, Username: pk, Role: user.RoleUser}, pk)
	require.NoError(f.t, err)
	return pk, jwt
}

func pkcePair() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func run(handler fasthttp.RequestHandler, method, uri, bearer string, form url.Values, userValues map[string]any) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(method)
	ctx.Request.SetRequestURI(uri)
	if bearer != "" {
		ctx.Request.Header.Set("Authorization", "Bearer "+bearer)
	}
	if form != nil {
		ctx.Request.Header.SetContentType("application/x-www-form-urlencoded")
		ctx.Request.SetBodyString(form.Encode())
	}
	for k, v := range userValues {
		ctx.SetUserValue(k, v)
	}
	handler(ctx)
	return ctx
}

func (f *fixture) authorize(challenge string, extra url.Values) *fasthttp.RequestCtx {
	q := url.Values{
		"client_id":             {f.clientID},
		"redirect_uri":          {loopbackRedir},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {"xyz"},
	}
	for k, v := range extra {
		q[k] = v
	}
	return run(f.endpoints.Authorize, "GET", "/oauth/authorize?"+q.Encode(), "", nil, nil)
}

func requestID(t *testing.T, ctx *fasthttp.RequestCtx) string {
	t.Helper()
	require.Equal(t, fasthttp.StatusFound, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	loc := string(ctx.Response.Header.Peek("Location"))
	require.True(t, strings.HasPrefix(loc, "https://app.test/#/oauth/consent?space="), loc)
	u, err := url.Parse(strings.Replace(loc, "/#/", "/", 1))
	require.NoError(t, err)
	return u.Query().Get("request")
}

func (f *fixture) consent(handler fasthttp.RequestHandler, method, id, bearer string) *fasthttp.RequestCtx {
	return run(f.auth.RequireAuth(handler), method, "/oauth/requests/"+id, bearer, nil, map[string]any{"requestID": id})
}

func redirectParams(t *testing.T, ctx *fasthttp.RequestCtx) url.Values {
	t.Helper()
	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	var body struct {
		RedirectURI string `json:"redirectUri"`
	}
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &body))
	u, err := url.Parse(body.RedirectURI)
	require.NoError(t, err)
	return u.Query()
}

func (f *fixture) token(form url.Values) *fasthttp.RequestCtx {
	return run(f.endpoints.Token, "POST", "/oauth/token", "", form, nil)
}

func (f *fixture) codeForm(code, verifier string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {loopbackRedir},
		"client_id":     {f.clientID},
		"code_verifier": {verifier},
	}
}

// approvedCode runs authorize and approve for a fresh user and returns the code.
func (f *fixture) approvedCode(challenge string) (pk, code string) {
	f.t.Helper()
	pk, jwt := f.human()
	id := requestID(f.t, f.authorize(challenge, nil))
	params := redirectParams(f.t, f.consent(f.endpoints.Approve, "POST", id, jwt))
	return pk, params.Get("code")
}

func tokenError(t *testing.T, ctx *fasthttp.RequestCtx) (code, description string) {
	t.Helper()
	require.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	var body map[string]string
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &body))
	return body["error"], body["error_description"]
}

func TestOAuthFlow_ShouldIssueWorkingTokens_Integration(t *testing.T) {
	// given
	f := newFixture(t, nil)
	verifier, challenge := pkcePair()
	pk, jwt := f.human()

	// when
	id := requestID(t, f.authorize(challenge, url.Values{"resource": {testIssuer + "/mcp"}, "scope": {"mcp offline_access"}}))
	infoCtx := f.consent(f.endpoints.GetRequest, "GET", id, jwt)
	approved := redirectParams(t, f.consent(f.endpoints.Approve, "POST", id, jwt))
	tokenCtx := f.token(f.codeForm(approved.Get("code"), verifier))

	// then
	require.Equal(t, fasthttp.StatusOK, infoCtx.Response.StatusCode())
	var info RequestInfo
	require.NoError(t, json.Unmarshal(infoCtx.Response.Body(), &info))
	assert.Equal(t, "Test Agent", info.ClientName)
	assert.Equal(t, f.clientID, info.ClientID)
	assert.True(t, info.RedirectLoopback)
	assert.Equal(t, "127.0.0.1:51234", info.RedirectHost)
	assert.Equal(t, "mcp", info.Scope)
	assert.Equal(t, "xyz", approved.Get("state"))
	assert.Equal(t, testIssuer, approved.Get("iss"))

	require.Equal(t, fasthttp.StatusOK, tokenCtx.Response.StatusCode(), string(tokenCtx.Response.Body()))
	assert.Equal(t, "no-store", string(tokenCtx.Response.Header.Peek("Cache-Control")))
	assert.Equal(t, "no-cache", string(tokenCtx.Response.Header.Peek("Pragma")))
	var tok TokenResponse
	require.NoError(t, json.Unmarshal(tokenCtx.Response.Body(), &tok))
	assert.Equal(t, "Bearer", tok.TokenType)
	assert.Equal(t, "mcp", tok.Scope)
	assert.InDelta(t, 3600, tok.ExpiresIn, 5)
	agentUser, err := f.agents.ValidateAccessToken(tok.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, pk, agentUser.PublicKey)

	refreshCtx := f.token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "resource": {testIssuer + "/mcp"}})
	require.Equal(t, fasthttp.StatusOK, refreshCtx.Response.StatusCode(), string(refreshCtx.Response.Body()))
	var refreshed TokenResponse
	require.NoError(t, json.Unmarshal(refreshCtx.Response.Body(), &refreshed))
	assert.NotEqual(t, tok.RefreshToken, refreshed.RefreshToken)
	_, err = f.agents.ValidateAccessToken(refreshed.AccessToken)
	assert.NoError(t, err)
}

func TestOAuthFlow_ResourceAbsent_ShouldWork_Integration(t *testing.T) {
	// given
	f := newFixture(t, nil)
	verifier, challenge := pkcePair()
	_, code := f.approvedCode(challenge)

	// when
	ctx := f.token(f.codeForm(code, verifier))

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), string(ctx.Response.Body()))
}

func TestOAuthToken_BadVerifier_ShouldReturnInvalidGrant_Integration(t *testing.T) {
	// given
	f := newFixture(t, nil)
	_, challenge := pkcePair()
	other, _ := pkcePair()
	_, code := f.approvedCode(challenge)

	// when
	ctx := f.token(f.codeForm(code, other))

	// then
	errCode, _ := tokenError(t, ctx)
	assert.Equal(t, CodeInvalidGrant, errCode)
}

func TestOAuthToken_ReusedCode_ShouldRevokeDevice_Integration(t *testing.T) {
	// given
	f := newFixture(t, nil)
	verifier, challenge := pkcePair()
	_, code := f.approvedCode(challenge)
	first := f.token(f.codeForm(code, verifier))
	require.Equal(t, fasthttp.StatusOK, first.Response.StatusCode())
	var tok TokenResponse
	require.NoError(t, json.Unmarshal(first.Response.Body(), &tok))
	_, err := f.agents.ValidateAccessToken(tok.AccessToken)
	require.NoError(t, err)

	// when
	second := f.token(f.codeForm(code, verifier))

	// then
	errCode, _ := tokenError(t, second)
	assert.Equal(t, CodeInvalidGrant, errCode)
	_, err = f.agents.ValidateAccessToken(tok.AccessToken)
	assert.Error(t, err)
}

func (f *fixture) failFirstIssue() (restore func()) {
	broken, err := sql.Open("postgres", "")
	require.NoError(f.t, err)
	require.NoError(f.t, broken.Close())
	working := f.svc.agents
	f.svc.agents = user.NewAgentService(broken, f.users, nil, nil, testIssuer)
	return func() { f.svc.agents = working }
}

func TestOAuthToken_IssueFailsThenRetry_ShouldSucceed_Integration(t *testing.T) {
	// given
	f := newFixture(t, nil)
	verifier, challenge := pkcePair()
	_, code := f.approvedCode(challenge)
	restore := f.failFirstIssue()
	failed := f.token(f.codeForm(code, verifier))
	restore()

	// when
	retry := f.token(f.codeForm(code, verifier))

	// then
	assert.Equal(t, fasthttp.StatusInternalServerError, failed.Response.StatusCode())
	require.Equal(t, fasthttp.StatusOK, retry.Response.StatusCode(), string(retry.Response.Body()))
	var tok TokenResponse
	require.NoError(t, json.Unmarshal(retry.Response.Body(), &tok))
	_, err := f.agents.ValidateAccessToken(tok.AccessToken)
	assert.NoError(t, err)
}

func TestOAuthToken_IssueFailsRetrySucceedsThenReuse_ShouldRevokeRetryDevice_Integration(t *testing.T) {
	// given
	f := newFixture(t, nil)
	verifier, challenge := pkcePair()
	_, code := f.approvedCode(challenge)
	restore := f.failFirstIssue()
	_ = f.token(f.codeForm(code, verifier))
	restore()
	retry := f.token(f.codeForm(code, verifier))
	require.Equal(t, fasthttp.StatusOK, retry.Response.StatusCode(), string(retry.Response.Body()))
	var tok TokenResponse
	require.NoError(t, json.Unmarshal(retry.Response.Body(), &tok))
	_, err := f.agents.ValidateAccessToken(tok.AccessToken)
	require.NoError(t, err)

	// when
	third := f.token(f.codeForm(code, verifier))

	// then
	errCode, _ := tokenError(t, third)
	assert.Equal(t, CodeInvalidGrant, errCode)
	_, err = f.agents.ValidateAccessToken(tok.AccessToken)
	assert.Error(t, err)
}

func TestOAuthAuthorize_WrongResource_ShouldReturn400_Integration(t *testing.T) {
	// given
	f := newFixture(t, nil)
	_, challenge := pkcePair()

	// when
	ctx := f.authorize(challenge, url.Values{"resource": {"https://other.test/mcp"}})

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	assert.Contains(t, string(ctx.Response.Body()), CodeInvalidTarget)
	assert.Empty(t, ctx.Response.Header.Peek("Location"))
}

func TestOAuthToken_WrongResource_ShouldReturnInvalidTarget_Integration(t *testing.T) {
	// given
	f := newFixture(t, nil)
	verifier, challenge := pkcePair()
	_, code := f.approvedCode(challenge)
	form := f.codeForm(code, verifier)
	form.Set("resource", "https://other.test/mcp")

	// when
	ctx := f.token(form)

	// then
	errCode, _ := tokenError(t, ctx)
	assert.Equal(t, CodeInvalidTarget, errCode)
}

func TestOAuthAuthorize_MismatchedRedirect_ShouldReturn400_Integration(t *testing.T) {
	// given
	f := newFixture(t, nil)
	_, challenge := pkcePair()

	// when
	ctx := f.authorize(challenge, url.Values{"redirect_uri": {"https://evil.example/cb"}})

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	assert.Empty(t, ctx.Response.Header.Peek("Location"))
}

func TestOAuthToken_MismatchedRedirect_ShouldReturnInvalidGrant_Integration(t *testing.T) {
	// given
	f := newFixture(t, nil)
	verifier, challenge := pkcePair()
	_, code := f.approvedCode(challenge)
	form := f.codeForm(code, verifier)
	form.Set("redirect_uri", "http://127.0.0.1:51234/callback2")

	// when
	ctx := f.token(form)

	// then
	errCode, _ := tokenError(t, ctx)
	assert.Equal(t, CodeInvalidGrant, errCode)
}

func TestOAuthConsent_AgentAccessToken_ShouldReturn401_Integration(t *testing.T) {
	// given
	f := newFixture(t, nil)
	pk, _ := f.human()
	agent, err := f.agents.IssueTokens(pk, "agent")
	require.NoError(t, err)
	_, challenge := pkcePair()
	id := requestID(t, f.authorize(challenge, nil))

	// when
	ctx := f.consent(f.endpoints.Approve, "POST", id, agent.AccessToken)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}

func TestOAuthConsent_DifferentUser_ShouldReturn403_Integration(t *testing.T) {
	// given
	f := newFixture(t, nil)
	_, alice := f.human()
	_, bob := f.human()
	_, challenge := pkcePair()
	id := requestID(t, f.authorize(challenge, nil))
	require.Equal(t, fasthttp.StatusOK, f.consent(f.endpoints.GetRequest, "GET", id, alice).Response.StatusCode())

	// when
	get := f.consent(f.endpoints.GetRequest, "GET", id, bob)
	approve := f.consent(f.endpoints.Approve, "POST", id, bob)
	deny := f.consent(f.endpoints.Deny, "POST", id, bob)

	// then
	for _, ctx := range []*fasthttp.RequestCtx{get, approve, deny} {
		assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
		assert.Contains(t, string(ctx.Response.Body()), "wrong_user")
	}
	assert.Equal(t, fasthttp.StatusOK, f.consent(f.endpoints.GetRequest, "GET", id, alice).Response.StatusCode())
}

func TestOAuthConsent_ExpiredOrUnknownRequest_ShouldReturn410_Integration(t *testing.T) {
	// given
	f := newFixture(t, nil)
	_, jwt := f.human()
	_, challenge := pkcePair()
	id := requestID(t, f.authorize(challenge, nil))
	f.svc.store.mu.Lock()
	f.svc.store.pending[id].expiresAt = time.Now().Add(-time.Second)
	f.svc.store.mu.Unlock()

	// when
	expired := f.consent(f.endpoints.GetRequest, "GET", id, jwt)
	unknown := f.consent(f.endpoints.Approve, "POST", "nope", jwt)

	// then
	assert.Equal(t, fasthttp.StatusGone, expired.Response.StatusCode())
	assert.Contains(t, string(expired.Response.Body()), "request_expired")
	assert.Equal(t, fasthttp.StatusGone, unknown.Response.StatusCode())
}

func TestOAuthConsent_DecidedRequest_ShouldReturn410_Integration(t *testing.T) {
	// given
	f := newFixture(t, nil)
	_, jwt := f.human()
	_, challenge := pkcePair()
	id := requestID(t, f.authorize(challenge, nil))
	redirectParams(t, f.consent(f.endpoints.Deny, "POST", id, jwt))

	// when
	again := f.consent(f.endpoints.Approve, "POST", id, jwt)

	// then
	assert.Equal(t, fasthttp.StatusGone, again.Response.StatusCode())
}

func TestOAuthConsent_Deny_ShouldRedirectWithAccessDenied_Integration(t *testing.T) {
	// given
	f := newFixture(t, nil)
	_, jwt := f.human()
	_, challenge := pkcePair()
	id := requestID(t, f.authorize(challenge, nil))

	// when
	params := redirectParams(t, f.consent(f.endpoints.Deny, "POST", id, jwt))

	// then
	assert.Equal(t, "access_denied", params.Get("error"))
	assert.Equal(t, "xyz", params.Get("state"))
	assert.Equal(t, testIssuer, params.Get("iss"))
	assert.Empty(t, params.Get("code"))
}

func TestOAuthConsent_AgentLimitAtApprove_ShouldReturn409_Integration(t *testing.T) {
	// given
	f := newFixture(t, nil)
	pk, jwt := f.human()
	for i := 0; i < 5; i++ {
		_, err := f.agents.IssueTokens(pk, "")
		require.NoError(t, err)
	}
	_, challenge := pkcePair()
	id := requestID(t, f.authorize(challenge, nil))

	// when
	ctx := f.consent(f.endpoints.Approve, "POST", id, jwt)

	// then
	assert.Equal(t, fasthttp.StatusConflict, ctx.Response.StatusCode())
	assert.Contains(t, string(ctx.Response.Body()), "agent_limit")
}

func TestOAuthToken_AgentLimitAtToken_ShouldReturnInvalidGrant_Integration(t *testing.T) {
	// given
	f := newFixture(t, nil)
	verifier, challenge := pkcePair()
	pk, code := f.approvedCode(challenge)
	for i := 0; i < 5; i++ {
		_, err := f.agents.IssueTokens(pk, "")
		require.NoError(t, err)
	}

	// when
	ctx := f.token(f.codeForm(code, verifier))

	// then
	errCode, description := tokenError(t, ctx)
	assert.Equal(t, CodeInvalidGrant, errCode)
	assert.Equal(t, "agent limit reached, revoke an agent in Prappser settings", description)
}

func TestOAuthAuthorize_InvalidClientDoc_ShouldReturn400_Integration(t *testing.T) {
	// given
	f := newFixture(t, func(d map[string]any) { d["client_secret"] = "x" })
	_, challenge := pkcePair()

	// when
	ctx := f.authorize(challenge, nil)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	assert.Empty(t, ctx.Response.Header.Peek("Location"))
}

func TestOAuthToken_IssueTokensServerError_ShouldKeepCodeUsable_Integration(t *testing.T) {
	// given
	f := newFixture(t, nil)
	verifier, challenge := pkcePair()
	_, code := f.approvedCode(challenge)
	require.NoError(t, f.db.Close())

	// when
	ctx := f.token(f.codeForm(code, verifier))

	// then
	assert.Equal(t, fasthttp.StatusInternalServerError, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	assert.Contains(t, string(ctx.Response.Body()), CodeServerError)
	f.svc.store.mu.Lock()
	defer f.svc.store.mu.Unlock()
	assert.False(t, f.svc.store.codes[hashCode(code)].used)
}

func TestAuthorize_ShouldRefuseHTTPSLoopbackClientID_WhenSSRFGuardIsActive_Integration(t *testing.T) {
	// given
	f := newFixture(t, nil)
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(goodDoc(f.clientID))
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	f.clientID = srv.URL + "/client.json"
	f.svc.fetcher = &metadataFetcher{client: newSafeClient(isPublicAddr, pool)}
	_, challenge := pkcePair()

	// when
	ctx := f.authorize(challenge, nil)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	assert.Zero(t, hits.Load())
}

func TestAuthorize_ShouldRefuseHTTPLoopbackClientID_WithProductionFetcher_Integration(t *testing.T) {
	// given
	f := newFixture(t, nil)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(goodDoc(f.clientID))
	}))
	t.Cleanup(srv.Close)
	f.clientID = srv.URL + "/client.json"
	f.svc.fetcher = newMetadataFetcher()
	_, challenge := pkcePair()

	// when
	ctx := f.authorize(challenge, nil)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	assert.Zero(t, hits.Load())
}
