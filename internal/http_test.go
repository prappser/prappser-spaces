package internal

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// noopUserRepository always reports "no such user" without touching a real
// database - enough for the rate-limit wiring test below, which only cares
// about status codes from the outer middleware, not endpoint business logic.
type noopUserRepository struct{}

func (noopUserRepository) CreateUser(u *user.User) error                           { return nil }
func (noopUserRepository) GetUserByPublicKey(publicKey string) (*user.User, error) { return nil, nil }
func (noopUserRepository) GetUserByUsername(username string) (*user.User, error)   { return nil, nil }
func (noopUserRepository) UpdateUserRole(publicKey, role string) error             { return nil }
func (noopUserRepository) UpdateAvatarStorageID(publicKey string, avatarStorageID *string) error {
	return nil
}
func (noopUserRepository) UpdateUsername(publicKey, username string) error { return nil }

// newTestRequestHandler builds the real NewRequestHandler with only
// userEndpoints wired for real; every other endpoint dependency is nil,
// which is safe here since none of the three auth routes under test touch
// them.
func newTestRequestHandler(t *testing.T) fasthttp.RequestHandler {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	userEndpoints := user.NewEndpoints(noopUserRepository{}, user.Config{ChallengeTTLSec: 300}, priv, pub, nil, nil)
	cfg := &Config{TrustProxyHeaders: true}
	return NewRequestHandler(cfg, userEndpoints, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
}

func newAuthRouteRequestCtx(path string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI(path)
	return ctx
}

// TestRateLimiting_SharesIPBudgetAcrossAuthRoutes checks that the per-IP
// limiter wired in NewRequestHandler is a single shared instance across
// /users/challenge, /users/auth, and /users/owners/register - not one budget
// per route - and that it actually trips.
func TestRateLimiting_SharesIPBudgetAcrossAuthRoutes(t *testing.T) {
	// given
	handler := newTestRequestHandler(t)
	routes := []string{
		"/users/challenge?publicKey=pk",
		"/users/auth",
		"/users/owners/register",
	}

	// when - 30 requests split evenly across the three routes, all from the
	// same (zero) RemoteIP, should all stay within the 30/min per-IP budget
	for i := 0; i < 30; i++ {
		ctx := newAuthRouteRequestCtx(routes[i%len(routes)])
		handler(ctx)
		assert.NotEqual(t, fasthttp.StatusTooManyRequests, ctx.Response.StatusCode(),
			"request %d (route %s) should not be rate limited yet", i+1, routes[i%len(routes)])
	}

	// then - the 31st request, on any of the three routes, trips the shared
	// per-IP budget
	ctx := newAuthRouteRequestCtx(routes[0])
	handler(ctx)
	assert.Equal(t, fasthttp.StatusTooManyRequests, ctx.Response.StatusCode())
	assert.NotEmpty(t, ctx.Response.Header.Peek("Retry-After"))
}
