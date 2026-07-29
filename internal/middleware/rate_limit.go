package middleware

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

// RateLimiter is an in-memory fixed-window rate limiter keyed by an arbitrary
// string (client IP, a user identifier, etc).
//
// ponytail: per-instance in-memory counters, not shared across replicas -
// fine for the current single-instance deployment; move to a shared store
// (e.g. Redis) if the service ever runs with more than one instance.
type RateLimiter struct {
	mu                sync.Mutex
	limit             int
	window            time.Duration
	buckets           map[string]*rateLimitBucket
	trustProxyHeaders bool
}

type rateLimitBucket struct {
	count       int
	windowStart time.Time
}

// NewRateLimiter creates a rate limiter that allows up to limit requests per
// key within the given window. trustProxyHeaders controls whether LimitByIP
// (via ClientIP) trusts X-Forwarded-For - see ClientIP's doc comment.
func NewRateLimiter(limit int, window time.Duration, trustProxyHeaders bool) *RateLimiter {
	return &RateLimiter{
		limit:             limit,
		window:            window,
		buckets:           make(map[string]*rateLimitBucket),
		trustProxyHeaders: trustProxyHeaders,
	}
}

// Allow reports whether a request for key is within the rate limit. When it
// is not, the returned duration is how long the caller should wait before
// retrying.
func (rl *RateLimiter) Allow(key string) (bool, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, exists := rl.buckets[key]
	if !exists || now.Sub(b.windowStart) >= rl.window {
		rl.buckets[key] = &rateLimitBucket{count: 1, windowStart: now}
		// ponytail: O(n) prune sweep on every new window; fine at this
		// scale, switch to a ticking janitor if key cardinality grows large.
		rl.prune(now)
		return true, 0
	}

	if b.count >= rl.limit {
		return false, rl.window - now.Sub(b.windowStart)
	}

	b.count++
	return true, 0
}

func (rl *RateLimiter) prune(now time.Time) {
	for key, b := range rl.buckets {
		if now.Sub(b.windowStart) >= rl.window {
			delete(rl.buckets, key)
		}
	}
}

// LimitByIP wraps handler with a rate limit keyed by the request's client IP.
func (rl *RateLimiter) LimitByIP(handler fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if allowed, retryAfter := rl.Allow(ClientIP(ctx, rl.trustProxyHeaders)); !allowed {
			writeTooManyRequests(ctx, retryAfter)
			return
		}
		handler(ctx)
	}
}

// LimitByKey wraps handler with a rate limit keyed by whatever keyFn extracts
// from the request (e.g. a publicKey query param or JWT claim). Requests for
// which keyFn returns an empty string are not rate limited here - the
// wrapped handler is responsible for rejecting malformed requests.
func (rl *RateLimiter) LimitByKey(handler fasthttp.RequestHandler, keyFn func(ctx *fasthttp.RequestCtx) string) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if key := keyFn(ctx); key != "" {
			if allowed, retryAfter := rl.Allow(key); !allowed {
				writeTooManyRequests(ctx, retryAfter)
				return
			}
		}
		handler(ctx)
	}
}

func writeTooManyRequests(ctx *fasthttp.RequestCtx, retryAfter time.Duration) {
	seconds := int(retryAfter.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	// ctx.Error resets the response, so headers must be set after it, not before.
	ctx.Error("Too Many Requests", fasthttp.StatusTooManyRequests)
	ctx.Response.Header.Set("Retry-After", strconv.Itoa(seconds))
}

// ClientIP returns the request's client IP. In production the server sits
// behind a proxy (Railway), so ctx.RemoteIP() would just be the proxy's
// address - when trustProxyHeaders is true, prefer the last entry of
// X-Forwarded-For (the hop the proxy itself appends, which a client can't
// spoof) when present. When trustProxyHeaders is false (no proxy in front -
// local dev, direct port exposure), X-Forwarded-For is attacker-controlled
// input: honoring it would let a client mint a fresh rate-limit bucket per
// request just by changing the header, so it's ignored entirely and only
// the actual connection's ctx.RemoteIP() is used.
func ClientIP(ctx *fasthttp.RequestCtx, trustProxyHeaders bool) string {
	if trustProxyHeaders {
		xff := string(ctx.Request.Header.Peek("X-Forwarded-For"))
		if xff != "" {
			parts := strings.Split(xff, ",")
			if last := strings.TrimSpace(parts[len(parts)-1]); last != "" {
				return last
			}
		}
	}
	return ctx.RemoteIP().String()
}
