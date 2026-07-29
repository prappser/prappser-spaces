package middleware

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

func TestRateLimiter_AllowsUpToLimitThenBlocks(t *testing.T) {
	// given
	rl := NewRateLimiter(2, time.Minute, true)

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
	rl := NewRateLimiter(1, time.Minute, true)

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
	rl := NewRateLimiter(1, 10*time.Millisecond, true)
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
	rl := NewRateLimiter(0, time.Minute, true) // a limit of 0 would block any non-empty key
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
	rl := NewRateLimiter(1, time.Minute, true)
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
	rl := NewRateLimiter(1, time.Minute, false)
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
