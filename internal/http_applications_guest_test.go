package internal

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// guestUserRepository resolves ValidateJWT to a fixed guest user with an
// active (non-revoked) device, so RequireRole's role check exercises the
// real "guest" role coming out of the repository rather than the JWT claim
// alone (#138).
type guestUserRepository struct {
	noopUserRepository
	u *user.User
}

func (r guestUserRepository) GetUserByPublicKey(publicKey string) (*user.User, error) {
	return r.u, nil
}

func (r guestUserRepository) GetDevice(devicePublicKey string) (*user.Device, error) {
	return &user.Device{DevicePublicKey: devicePublicKey, UserPublicKey: r.u.PublicKey, CreatedAt: time.Now().Unix()}, nil
}

// newGuestTestRequestHandler wires a real userService (so JWT signing/
// validation and role resolution run for real) and a real appEndpoints
// backed by application.NewMemoryRepository, seeded with one application and
// a membership row for guestPublicKey - mirroring
// invitation.newEndpointTestService. Returns the handler plus a valid JWT for
// the guest.
func newGuestTestRequestHandler(t *testing.T, guestPublicKey, appID string) (fasthttp.RequestHandler, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	guestUser := &user.User{PublicKey: guestPublicKey, Username: "guest-user", Role: user.RoleGuest, CreatedAt: time.Now().Unix(), Issuer: guestPublicKey}
	userService := user.NewUserService(guestUserRepository{u: guestUser}, nil, user.Config{JWTExpirationHours: 24}, priv, pub)

	token, _, err := userService.GenerateJWT(guestUser, guestPublicKey)
	assert.NoError(t, err)

	appRepo := application.NewMemoryRepository()
	assert.NoError(t, appRepo.CreateApplication(&application.Application{ID: appID, Name: "Test App"}))
	assert.NoError(t, appRepo.CreateMember(&application.Member{ID: "member-" + guestPublicKey, ApplicationID: appID, PublicKey: guestPublicKey, Role: application.MemberRoleMember}))
	appEndpoints := application.NewApplicationEndpoints(application.NewApplicationService(appRepo), "space-pk")

	cfg := &Config{TrustProxyHeaders: true}
	handler := NewRequestHandler(cfg, nil, nil, nil, userService, appEndpoints, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	return handler, token
}

func newBearerRequestCtx(method, path, token string) *fasthttp.RequestCtx {
	ctx := newAuthRouteRequestCtxWithMethod(method, path)
	ctx.Request.Header.Set("Authorization", "Bearer "+token)
	return ctx
}

// TestListApplications_ShouldReturn200ForGuest pins #138: a device restored
// after an invite join has account role "guest", and must still be able to
// re-discover applications it is already a member of. ListApplications is
// scoped to the caller's own memberships
// (repository.GetApplicationsByMemberPublicKey), so widening the route gate
// to include RoleGuest cannot leak other accounts' applications.
func TestListApplications_ShouldReturn200ForGuest(t *testing.T) {
	// given
	handler, token := newGuestTestRequestHandler(t, "guest-pk", "app-1")
	ctx := newBearerRequestCtx("GET", "/applications", token)

	// when
	handler(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Contains(t, string(ctx.Response.Body()), "app-1")
}

// TestListApplications_ShouldReturn403ForGuestOnRegister is the negative
// control for #138: widening the /applications gate must not widen any
// other route - guests still cannot register new applications.
func TestListApplications_ShouldReturn403ForGuestOnRegister(t *testing.T) {
	// given
	handler, token := newGuestTestRequestHandler(t, "guest-pk", "app-1")
	ctx := newBearerRequestCtx("POST", "/applications/register", token)

	// when
	handler(ctx)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
}
