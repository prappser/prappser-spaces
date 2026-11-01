//go:build integration

package internal

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/oauth"
	"github.com/prappser/prappser-spaces/internal/testdb"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

func TestOAuthRoutes_FullFlow_ShouldIssueValidAgentToken_Integration(t *testing.T) {
	// given
	db := testdb.Connect(t, "oauthhttp")
	t.Cleanup(func() { db.Close() })
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	const issuer = "https://space.test"
	users := user.NewUserRepository(db)
	userSvc := user.NewUserService(users, nil, user.Config{JWTExpirationHours: 24}, priv, pub)
	agents := user.NewAgentService(db, users, priv, pub, issuer)

	var clientID string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":                  clientID,
			"client_name":                "Test Agent",
			"redirect_uris":              []any{"http://127.0.0.1/callback"},
			"token_endpoint_auth_method": "none",
		})
	}))
	t.Cleanup(srv.Close)
	clientID = srv.URL + "/client.json"
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	svc := oauth.NewService(agents, users, issuer, "https://app.test")
	svc.TestOnlyDisableSSRFGuard(pool)
	cfg := &Config{TrustProxyHeaders: true, MCPEnabled: true, ExternalURL: issuer}
	handler := NewRequestHandler(cfg, nil, nil, nil, userSvc, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, oauth.NewEndpoints(svc, true))

	pk := "oauth-http-" + rand.Text()
	require.NoError(t, users.CreateUser(&user.User{PublicKey: pk, Username: pk, Role: user.RoleUser, CreatedAt: time.Now().Unix()}))
	require.NoError(t, users.EnsureDevice(pk, pk, nil, time.Now().Unix()))
	jwt, _, err := userSvc.GenerateJWT(&user.User{PublicKey: pk, Username: pk, Role: user.RoleUser}, pk)
	require.NoError(t, err)

	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	do := func(method, uri, bearer string, form url.Values) *fasthttp.RequestCtx {
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
		handler(ctx)
		return ctx
	}

	// when
	q := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {"http://127.0.0.1:51234/callback"},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	authorize := do("GET", "/oauth/authorize?"+q.Encode(), "", nil)
	require.Equal(t, fasthttp.StatusFound, authorize.Response.StatusCode(), string(authorize.Response.Body()))
	loc, err := url.Parse(strings.Replace(string(authorize.Response.Header.Peek("Location")), "/#/", "/", 1))
	require.NoError(t, err)
	id := loc.Query().Get("request")
	require.NotEmpty(t, id)

	info := do("GET", "/oauth/requests/"+id, jwt, nil)
	approve := do("POST", "/oauth/requests/"+id+"/approve", jwt, nil)
	require.Equal(t, fasthttp.StatusOK, approve.Response.StatusCode(), string(approve.Response.Body()))
	var approved struct {
		RedirectURI string `json:"redirectUri"`
	}
	require.NoError(t, json.Unmarshal(approve.Response.Body(), &approved))
	redirect, err := url.Parse(approved.RedirectURI)
	require.NoError(t, err)
	token := do("POST", "/oauth/token", "", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {redirect.Query().Get("code")},
		"redirect_uri":  {"http://127.0.0.1:51234/callback"},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	})

	// then
	assert.Equal(t, fasthttp.StatusOK, info.Response.StatusCode(), string(info.Response.Body()))
	require.Equal(t, fasthttp.StatusOK, token.Response.StatusCode(), string(token.Response.Body()))
	var tok oauth.TokenResponse
	require.NoError(t, json.Unmarshal(token.Response.Body(), &tok))
	agentUser, err := agents.ValidateAccessToken(tok.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, pk, agentUser.PublicKey)
}
