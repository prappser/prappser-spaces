package invitation

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// newEndpointTestService wires a real application.MemoryRepository seeded
// with one application and, if role != "", a single member of that role for
// memberPublicKey - mirroring newAuthzTestService in
// invitation_service_test.go, but also returning the fakeInvitationRepo so
// callers can seed an invite (RevokeInvite needs one to exist) (#125).
func newEndpointTestService(t *testing.T, appID, memberPublicKey string, role application.MemberRole, invite *Invitation) *InvitationService {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	appRepo := application.NewMemoryRepository()
	assert.NoError(t, appRepo.CreateApplication(&application.Application{ID: appID, Name: "Test App"}))
	if role != "" {
		assert.NoError(t, appRepo.CreateMember(&application.Member{ID: "member-" + memberPublicKey, ApplicationID: appID, PublicKey: memberPublicKey, Role: role}))
	}

	return NewInvitationService(&fakeInvitationRepo{invite: invite}, priv, pub, appRepo, nil, &fakeUserRepo{}, fakeEventService{}, "space-key")
}

// newAuthzTestCtx builds a bare fasthttp.RequestCtx with the authenticated
// user, path params, and body an endpoint handler expects (#125).
func newAuthzTestCtx(method, callerPublicKey, appID, inviteID string, body []byte) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(method)
	ctx.SetUserValue("user", &user.User{PublicKey: callerPublicKey})
	if appID != "" {
		ctx.SetUserValue("appID", appID)
	}
	if inviteID != "" {
		ctx.SetUserValue("inviteID", inviteID)
	}
	if body != nil {
		ctx.Request.SetBody(body)
	}
	return ctx
}

// erroringAppRepo wraps a real MemoryRepository and overrides
// GetMemberByPublicKey to return an arbitrary (non-"member not found") error,
// for exercising AuthorizeAppRole's 500 path cheaply without hand-writing a
// full application.ApplicationRepository fake (#125).
type erroringAppRepo struct {
	*application.MemoryRepository
	err error
}

func (r *erroringAppRepo) GetMemberByPublicKey(appID, publicKey string) (*application.Member, error) {
	return nil, r.err
}

// ---- CreateInvite ----

func TestCreateInvite_ShouldReturn403WhenCallerNotAuthorized(t *testing.T) {
	// given: caller has no member row in the application at all
	svc := newEndpointTestService(t, "app-1", "owner-pk", application.MemberRoleOwner, nil)
	ep := &InvitationEndpoints{invitationService: svc}
	ctx := newAuthzTestCtx("POST", "non-member-pk", "app-1", "", []byte("{}"))

	// when
	ep.CreateInvite(ctx)

	// then: #125 - a non-member cannot create invites
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
}

func TestCreateInvite_ShouldReturn201WhenCallerIsOwner(t *testing.T) {
	// given
	svc := newEndpointTestService(t, "app-1", "owner-pk", application.MemberRoleOwner, nil)
	ep := &InvitationEndpoints{invitationService: svc}
	ctx := newAuthzTestCtx("POST", "owner-pk", "app-1", "", []byte("{}"))

	// when
	ep.CreateInvite(ctx)

	// then
	assert.Equal(t, fasthttp.StatusCreated, ctx.Response.StatusCode())
}

func TestCreateInvite_ShouldReturn500WhenAuthorizationLookupFails(t *testing.T) {
	// given: the membership lookup itself fails with a real (non-not-found) error
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	appRepo := &erroringAppRepo{MemoryRepository: application.NewMemoryRepository(), err: errors.New("db connection lost")}
	svc := NewInvitationService(&fakeInvitationRepo{}, priv, pub, appRepo, nil, &fakeUserRepo{}, fakeEventService{}, "space-key")
	ep := &InvitationEndpoints{invitationService: svc}
	ctx := newAuthzTestCtx("POST", "someone-pk", "app-1", "", []byte("{}"))

	// when
	ep.CreateInvite(ctx)

	// then: a real DB error must surface as 500, not be silently treated as unauthorized
	assert.Equal(t, fasthttp.StatusInternalServerError, ctx.Response.StatusCode())
}

// ---- RevokeInvite ----

func TestRevokeInvite_ShouldReturn403WhenCallerNotAuthorized(t *testing.T) {
	// given
	invite := &Invitation{ID: "invite-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix()}
	svc := newEndpointTestService(t, "app-1", "owner-pk", application.MemberRoleOwner, invite)
	ep := &InvitationEndpoints{invitationService: svc}
	ctx := newAuthzTestCtx("DELETE", "non-member-pk", "app-1", "invite-1", nil)

	// when
	ep.RevokeInvite(ctx)

	// then: #125 - a non-member cannot revoke invites
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
}

func TestRevokeInvite_ShouldReturn204WhenCallerIsOwner(t *testing.T) {
	// given
	invite := &Invitation{ID: "invite-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix()}
	svc := newEndpointTestService(t, "app-1", "owner-pk", application.MemberRoleOwner, invite)
	ep := &InvitationEndpoints{invitationService: svc}
	ctx := newAuthzTestCtx("DELETE", "owner-pk", "app-1", "invite-1", nil)

	// when
	ep.RevokeInvite(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNoContent, ctx.Response.StatusCode())
}

// ---- ListInvites ----

func TestListInvites_ShouldReturn403WhenCallerNotAuthorized(t *testing.T) {
	// given: caller is a plain member, not owner or admin
	svc := newEndpointTestService(t, "app-1", "member-pk", application.MemberRoleMember, nil)
	ep := &InvitationEndpoints{invitationService: svc}
	ctx := newAuthzTestCtx("GET", "member-pk", "app-1", "", nil)

	// when
	ep.ListInvites(ctx)

	// then: #125 - a plain member cannot list invites
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
}

func TestListInvites_ShouldReturn200WhenCallerIsOwner(t *testing.T) {
	// given
	svc := newEndpointTestService(t, "app-1", "owner-pk", application.MemberRoleOwner, nil)
	ep := &InvitationEndpoints{invitationService: svc}
	ctx := newAuthzTestCtx("GET", "owner-pk", "app-1", "", nil)

	// when
	ep.ListInvites(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
}

func TestListInvites_ShouldReturn200WhenCallerIsAdmin(t *testing.T) {
	// given: admin is also allowed, unlike owner-only CreateInvite/RevokeInvite
	svc := newEndpointTestService(t, "app-1", "admin-pk", application.MemberRoleAdmin, nil)
	ep := &InvitationEndpoints{invitationService: svc}
	ctx := newAuthzTestCtx("GET", "admin-pk", "app-1", "", nil)

	// when
	ep.ListInvites(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
}
