package internal

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/prappser/prappser-spaces/internal/spaceprofile"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

func newSpaceProfileRouteHandler(t *testing.T, role string) (fasthttp.RequestHandler, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	u := roleTestUser(role)
	userService := user.NewUserService(guestUserRepository{u: u}, nil, user.Config{JWTExpirationHours: 24}, priv, pub)
	token, _, err := userService.GenerateJWT(u, u.PublicKey)
	assert.NoError(t, err)

	endpoints := spaceprofile.NewSpaceProfileEndpoints(nil, nil, nil)
	handler := NewRequestHandler(&Config{TrustProxyHeaders: true}, nil, nil, nil, userService, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, endpoints, nil, nil)
	return handler, token
}

func TestSpaceProfile_ShouldReturn403ForUser(t *testing.T) {
	// given
	handler, token := newSpaceProfileRouteHandler(t, user.RoleUser)
	ctx := newBearerRequestCtx("PUT", "/space/profile", token)

	// when
	handler(ctx)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
}

func TestSpaceProfile_ShouldReachTheHandlerForOwner(t *testing.T) {
	// given
	handler, token := newSpaceProfileRouteHandler(t, user.RoleOwner)
	ctx := newBearerRequestCtx("PUT", "/space/profile", token)
	ctx.Request.SetBodyString("not json")

	// when
	handler(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestSpaceProfile_ShouldRejectOtherMethods(t *testing.T) {
	// given
	handler, token := newSpaceProfileRouteHandler(t, user.RoleOwner)
	ctx := newBearerRequestCtx("GET", "/space/profile", token)

	// when
	handler(ctx)

	// then
	assert.Equal(t, fasthttp.StatusMethodNotAllowed, ctx.Response.StatusCode())
}
