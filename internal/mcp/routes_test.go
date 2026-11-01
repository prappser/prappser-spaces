package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"

	"github.com/prappser/prappser-spaces/internal/middleware"
	"github.com/prappser/prappser-spaces/internal/user"
)

func mcpCtx(body string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.SetRequestURI(pathMCP)
	ctx.Request.SetBodyString(body)
	return ctx
}

func TestMount_ShouldRateLimitByIP(t *testing.T) {
	// given
	handler := Mount(func(*fasthttp.RequestCtx) {}, Deps{ExternalURL: "https://space.example"})
	for i := 0; i < ipLimitPerMinute; i++ {
		ctx := mcpCtx("{}")
		handler(ctx)
		assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
	}

	// when
	ctx := mcpCtx("{}")
	handler(ctx)

	// then
	assert.Equal(t, fasthttp.StatusTooManyRequests, ctx.Response.StatusCode())
	assert.NotEmpty(t, ctx.Response.Header.Peek("Retry-After"))
}

func TestMount_ShouldRejectBodyOverLimit(t *testing.T) {
	// given
	handler := Mount(func(*fasthttp.RequestCtx) {}, Deps{ExternalURL: "https://space.example"})
	declared := mcpCtx("")
	declared.Request.Header.SetContentLength(maxBodyBytes + 1)
	chunked := mcpCtx(strings.Repeat("a", maxBodyBytes+1))
	small := mcpCtx(strings.Repeat("a", maxBodyBytes))

	// when
	handler(declared)
	handler(chunked)
	handler(small)

	// then
	assert.Equal(t, fasthttp.StatusRequestEntityTooLarge, declared.Response.StatusCode())
	assert.Equal(t, fasthttp.StatusRequestEntityTooLarge, chunked.Response.StatusCode())
	assert.Equal(t, fasthttp.StatusUnauthorized, small.Response.StatusCode())
}

func TestLimitByDevice_ShouldLimitPerDeviceAndSendRetryAfter(t *testing.T) {
	// given
	rl := middleware.NewRateLimiter(2, time.Minute, false)
	verifier := func(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		u := &user.User{PublicKey: "same-account", DevicePublicKey: token}
		return &auth.TokenInfo{Scopes: []string{scopeMCP}, UserID: u.PublicKey, Extra: map[string]any{"user": u}}, nil
	}
	h := auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{AllowMissingExpiration: true})(
		limitByDevice(rl, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))
	do := func(device string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, pathMCP, nil)
		req.Header.Set("Authorization", "Bearer "+device)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// when
	do("dev-a")
	do("dev-a")
	over := do("dev-a")
	other := do("dev-b")

	// then
	assert.Equal(t, http.StatusTooManyRequests, over.Code)
	seconds, err := strconv.Atoi(over.Header().Get("Retry-After"))
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, seconds, 1)
	assert.Equal(t, http.StatusOK, other.Code)
}
