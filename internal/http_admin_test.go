package internal

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"testing"
	"time"

	"github.com/prappser/prappser-spaces/internal/admin"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// newRoleTestRequestHandler resolves the DB user to dbUser while minting the
// JWT from jwtUser, so a test can forge a role claim the DB disagrees with.
func newRoleTestRequestHandler(t *testing.T, dbUser, jwtUser *user.User, adminEndpoints *admin.AdminEndpoints) (fasthttp.RequestHandler, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	userService := user.NewUserService(guestUserRepository{u: dbUser}, nil, user.Config{JWTExpirationHours: 24}, priv, pub)
	token, _, err := userService.GenerateJWT(jwtUser, dbUser.PublicKey)
	assert.NoError(t, err)

	handler := NewRequestHandler(&Config{TrustProxyHeaders: true}, nil, nil, nil, userService, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, adminEndpoints)
	return handler, token
}

func roleTestUser(role string) *user.User {
	return &user.User{PublicKey: "role-pk", Username: "role-user", Role: role, CreatedAt: time.Now().Unix(), Issuer: "role-pk"}
}

func TestSpaceAccounts_ShouldReturn401WithoutToken(t *testing.T) {
	// given
	handler, _ := newRoleTestRequestHandler(t, roleTestUser(user.RoleOwner), roleTestUser(user.RoleOwner), nil)
	ctx := newAuthRouteRequestCtxWithMethod("GET", "/space/accounts")

	// when
	handler(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}

func TestSpaceAccounts_ShouldReturn403ForUser(t *testing.T) {
	// given
	handler, token := newRoleTestRequestHandler(t, roleTestUser(user.RoleUser), roleTestUser(user.RoleUser), nil)
	ctx := newBearerRequestCtx("GET", "/space/accounts", token)

	// when
	handler(ctx)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
}

func TestSpaceAccounts_ShouldReturn403ForGuest(t *testing.T) {
	// given
	handler, token := newRoleTestRequestHandler(t, roleTestUser(user.RoleGuest), roleTestUser(user.RoleGuest), nil)
	ctx := newBearerRequestCtx("GET", "/space/accounts", token)

	// when
	handler(ctx)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
}

func TestSpaceAccounts_ShouldReturn403ForForgedOwnerClaim(t *testing.T) {
	// given
	handler, token := newRoleTestRequestHandler(t, roleTestUser(user.RoleUser), roleTestUser(user.RoleOwner), nil)
	ctx := newBearerRequestCtx("GET", "/space/accounts", token)

	// when
	handler(ctx)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
}

func TestSpaceAccounts_ShouldReturn405ForPost(t *testing.T) {
	// given
	handler, token := newRoleTestRequestHandler(t, roleTestUser(user.RoleOwner), roleTestUser(user.RoleOwner), nil)
	ctx := newBearerRequestCtx("POST", "/space/accounts", token)

	// when
	handler(ctx)

	// then
	assert.Equal(t, fasthttp.StatusMethodNotAllowed, ctx.Response.StatusCode())
}

func TestSpaceAccounts_ShouldReachHandlerForOwner(t *testing.T) {
	// given
	db, err := sql.Open("postgres", "host=/nonexistent-prappser-test dbname=x sslmode=disable")
	assert.NoError(t, err)
	defer db.Close()
	endpoints := admin.NewAdminEndpoints(admin.NewRepository(db), admin.Limits{})
	handler, token := newRoleTestRequestHandler(t, roleTestUser(user.RoleOwner), roleTestUser(user.RoleOwner), endpoints)
	ctx := newBearerRequestCtx("GET", "/space/accounts", token)

	// when
	handler(ctx)

	// then
	assert.Equal(t, fasthttp.StatusInternalServerError, ctx.Response.StatusCode())
}
