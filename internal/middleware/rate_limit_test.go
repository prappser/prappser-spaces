package middleware

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

func TestRateLimiter_AllowsUpToLimitThenBlocks(t *testing.T) {
	// given
	rl := NewRateLimiter(2, time.Minute, NewClientIPResolver("", true))

	// when
	allowed1, _ := rl.Allow("key")
	allowed2, _ := rl.Allow("key")
	allowed3, retryAfter := rl.Allow("key")

	// then
	assert.True(t, allowed1)
	assert.True(t, allowed2)
	assert.False(t, allowed3)
	assert.Greater(t, retryAfter, time.Duration(0))
}

func TestRateLimiter_IndependentKeysDoNotShareBudget(t *testing.T) {
	// given
	rl := NewRateLimiter(1, time.Minute, NewClientIPResolver("", true))

	// when
	allowedA, _ := rl.Allow("a")
	allowedB, _ := rl.Allow("b")
	blockedA, _ := rl.Allow("a")

	// then
	assert.True(t, allowedA)
	assert.True(t, allowedB)
	assert.False(t, blockedA)
}

func TestRateLimiter_WindowRollsOverAfterExpiry(t *testing.T) {
	// given
	rl := NewRateLimiter(1, 10*time.Millisecond, NewClientIPResolver("", true))
	allowed1, _ := rl.Allow("key")
	assert.True(t, allowed1)
	blocked, _ := rl.Allow("key")
	assert.False(t, blocked)

	// when
	time.Sleep(15 * time.Millisecond)
	allowedAfterWindow, _ := rl.Allow("key")

	// then
	assert.True(t, allowedAfterWindow)
}

func TestClientIP_ShouldUseLastForwardedForEntryWhenProxyTrusted(t *testing.T) {
	// given
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("X-Forwarded-For", "203.0.113.1, 10.0.0.5")

	// when
	ip := ClientIP(ctx, true)

	// then
	assert.Equal(t, "10.0.0.5", ip)
}

func TestClientIP_ShouldFallBackToRemoteIPWithoutForwardedFor(t *testing.T) {
	// given
	ctx := &fasthttp.RequestCtx{}

	// when
	ip := ClientIP(ctx, true)

	// then
	assert.Equal(t, ctx.RemoteIP().String(), ip)
}

func TestClientIP_ShouldIgnoreForwardedForWhenProxyNotTrusted(t *testing.T) {
	// given - no reverse proxy in front (local dev / direct exposure), so
	// X-Forwarded-For is attacker-controlled input and must be ignored.
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("X-Forwarded-For", "203.0.113.1, 10.0.0.5")

	// when
	ip := ClientIP(ctx, false)

	// then
	assert.Equal(t, ctx.RemoteIP().String(), ip)
	assert.NotEqual(t, "10.0.0.5", ip)
}

func TestLimitByKey_ShouldSkipLimitingWhenKeyIsEmpty(t *testing.T) {
	// given
	rl := NewRateLimiter(0, time.Minute, NewClientIPResolver("", true)) // a limit of 0 would block any non-empty key
	called := false
	handler := rl.LimitByKey(func(ctx *fasthttp.RequestCtx) {
		called = true
	}, func(ctx *fasthttp.RequestCtx) string {
		return ""
	})
	ctx := &fasthttp.RequestCtx{}

	// when
	handler(ctx)

	// then
	assert.True(t, called)
	assert.NotEqual(t, fasthttp.StatusTooManyRequests, ctx.Response.StatusCode())
}

func TestLimitByIP_ShouldReturn429WithRetryAfterWhenExceeded(t *testing.T) {
	// given
	rl := NewRateLimiter(1, time.Minute, NewClientIPResolver("", true))
	handler := rl.LimitByIP(func(ctx *fasthttp.RequestCtx) {})
	ctx := &fasthttp.RequestCtx{}

	// when - first request consumes the budget, second is over the limit
	handler(ctx)
	handler(ctx)

	// then
	assert.Equal(t, fasthttp.StatusTooManyRequests, ctx.Response.StatusCode())
	assert.NotEmpty(t, ctx.Response.Header.Peek("Retry-After"))
}

func TestLimitByIP_ShouldNotBeBypassedBySpoofedForwardedForWhenProxyNotTrusted(t *testing.T) {
	// given - trustProxyHeaders=false, as when there's no Railway proxy in
	// front (local dev / direct exposure). Without this, a client could send
	// a fresh X-Forwarded-For value per request and get a fresh bucket every
	// time, bypassing the limiter entirely.
	rl := NewRateLimiter(1, time.Minute, NewClientIPResolver("", false))
	handler := rl.LimitByIP(func(ctx *fasthttp.RequestCtx) {})

	firstCtx := &fasthttp.RequestCtx{}
	firstCtx.Request.Header.Set("X-Forwarded-For", "1.1.1.1")
	handler(firstCtx)

	secondCtx := &fasthttp.RequestCtx{}
	secondCtx.Request.Header.Set("X-Forwarded-For", "2.2.2.2") // different spoofed IP each request

	// when
	handler(secondCtx)

	// then - both requests share the same real connection IP, so the second
	// is still blocked despite the different X-Forwarded-For value
	assert.Equal(t, fasthttp.StatusTooManyRequests, secondCtx.Response.StatusCode())
}

func TestClientIPResolver(t *testing.T) {
	tests := []struct {
		name   string
		header string
		trust  bool
		set    map[string]string
		want   string // "" means ctx.RemoteIP()
	}{
		{"header set and valid", "CF-Connecting-IP", true, map[string]string{"CF-Connecting-IP": " 198.51.100.7 ", "X-Forwarded-For": "1.1.1.1, 10.0.0.5"}, "198.51.100.7"},
		{"header set but absent falls back to XFF", "CF-Connecting-IP", true, map[string]string{"X-Forwarded-For": "1.1.1.1, 10.0.0.5"}, "10.0.0.5"},
		{"header set but malformed falls back", "CF-Connecting-IP", true, map[string]string{"CF-Connecting-IP": "not-an-ip"}, ""},
		{"unset, trust on uses last XFF", "", true, map[string]string{"X-Forwarded-For": "1.1.1.1, 10.0.0.5"}, "10.0.0.5"},
		{"unset, trust off uses remote", "", false, map[string]string{"X-Forwarded-For": "1.1.1.1"}, ""},
		{"unset ignores spoofed header", "", true, map[string]string{"CF-Connecting-IP": "6.6.6.6"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &fasthttp.RequestCtx{}
			for k, v := range tt.set {
				ctx.Request.Header.Set(k, v)
			}
			want := tt.want
			if want == "" {
				want = ctx.RemoteIP().String()
			}
			assert.Equal(t, want, NewClientIPResolver(tt.header, tt.trust)(ctx))
		})
	}
}

func TestLimitByIP_ShouldBucketSeparatelyPerClientIPHeaderValue(t *testing.T) {
	// given - every request shares one RemoteIP (the proxy); only the header differs
	rl := NewRateLimiter(1, time.Minute, NewClientIPResolver("CF-Connecting-IP", true))
	handler := rl.LimitByIP(func(ctx *fasthttp.RequestCtx) { ctx.SetStatusCode(fasthttp.StatusOK) })
	call := func(ip string) int {
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.Header.Set("CF-Connecting-IP", ip)
		handler(ctx)
		return ctx.Response.StatusCode()
	}

	// when / then
	assert.Equal(t, fasthttp.StatusOK, call("198.51.100.1"))
	assert.Equal(t, fasthttp.StatusOK, call("198.51.100.2"))
	assert.Equal(t, fasthttp.StatusTooManyRequests, call("198.51.100.1"))
}
