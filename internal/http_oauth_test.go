package internal

import (
	"testing"

	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

func newOAuthTestHandler(mcpEnabled bool) fasthttp.RequestHandler {
	endpoints := oauth.NewEndpoints(oauth.NewService(nil, nil, "https://space.test/", "https://app.test"))
	cfg := &Config{TrustProxyHeaders: true, MCPEnabled: mcpEnabled}
	return NewRequestHandler(cfg, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, endpoints)
}

func TestOAuthRoutes_MCPDisabled_ShouldReturn404(t *testing.T) {
	// given
	handler := newOAuthTestHandler(false)
	paths := []struct{ method, path string }{
		{"GET", "/.well-known/oauth-authorization-server"},
		{"GET", "/oauth/authorize"},
		{"POST", "/oauth/token"},
		{"GET", "/oauth/requests/abc"},
		{"POST", "/oauth/requests/abc/approve"},
	}

	// when / then
	for _, p := range paths {
		ctx := newAuthRouteRequestCtxWithMethod(p.method, p.path)
		handler(ctx)
		assert.Equal(t, fasthttp.StatusNotFound, ctx.Response.StatusCode(), p.path)
	}
}

func TestOAuthRoutes_WrongMethodOrShape_ShouldReturn405Or404(t *testing.T) {
	// given
	handler := newOAuthTestHandler(true)
	cases := []struct {
		method, path string
		want         int
	}{
		{"POST", "/.well-known/oauth-authorization-server", fasthttp.StatusMethodNotAllowed},
		{"POST", "/oauth/authorize", fasthttp.StatusMethodNotAllowed},
		{"GET", "/oauth/token", fasthttp.StatusMethodNotAllowed},
		{"GET", "/oauth/requests/abc/approve", fasthttp.StatusMethodNotAllowed},
		{"GET", "/oauth/requests/", fasthttp.StatusNotFound},
		{"POST", "/oauth/requests/abc/other", fasthttp.StatusNotFound},
		{"GET", "/oauth/requests/a/b/c", fasthttp.StatusNotFound},
	}

	// when / then
	for _, c := range cases {
		ctx := newAuthRouteRequestCtxWithMethod(c.method, c.path)
		handler(ctx)
		assert.Equal(t, c.want, ctx.Response.StatusCode(), c.method+" "+c.path)
	}
}

func TestOAuthRoutes_ConsentWithoutJWT_ShouldReturn401(t *testing.T) {
	// given
	handler := newOAuthTestHandler(true)

	// when
	ctx := newAuthRouteRequestCtxWithMethod("GET", "/oauth/requests/abc")
	handler(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}

func TestOAuthRoutes_Metadata_ShouldDescribeServer(t *testing.T) {
	// given
	handler := newOAuthTestHandler(true)

	// when
	ctx := newAuthRouteRequestCtxWithMethod("GET", "/.well-known/oauth-authorization-server")
	handler(ctx)

	// then
	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	var got map[string]any
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &got))
	assert.Equal(t, "https://space.test", got["issuer"])
	assert.Equal(t, "https://space.test/oauth/authorize", got["authorization_endpoint"])
	assert.Equal(t, "https://space.test/oauth/token", got["token_endpoint"])
	assert.Equal(t, []any{"S256"}, got["code_challenge_methods_supported"])
	assert.Equal(t, []any{"none"}, got["token_endpoint_auth_methods_supported"])
	assert.Equal(t, true, got["client_id_metadata_document_supported"])
	assert.Equal(t, true, got["authorization_response_iss_parameter_supported"])
	assert.NotContains(t, got, "registration_endpoint")
}

func TestOAuthRoutes_TokenRateLimit_ShouldTripAt60PerMinute(t *testing.T) {
	// given
	handler := newOAuthTestHandler(true)

	// when
	var last int
	for i := 0; i < oauthTokenRateLimitPerMinute+1; i++ {
		ctx := newAuthRouteRequestCtxWithMethod("POST", "/oauth/token")
		handler(ctx)
		last = ctx.Response.StatusCode()
	}

	// then
	assert.Equal(t, fasthttp.StatusTooManyRequests, last)
}
