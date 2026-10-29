//go:build integration

package invitation

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/testdb"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

const (
	boundAppID   = "bound-app"
	boundOwnerPK = "bound-owner-pk"
)

type boundFixture struct {
	t       *testing.T
	db      *sql.DB
	svc     *InvitationService
	repo    InvitationRepository
	appRepo *application.Repository
	users   user.UserRepository
	ep      *InvitationEndpoints
}

func newBoundFixture(t *testing.T) *boundFixture {
	t.Helper()
	db := testdb.Connect(t, "invitation")
	t.Cleanup(func() { db.Close() })

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	spacePK := base64.StdEncoding.EncodeToString(pub)

	testdb.InsertTestUser(t, db, boundOwnerPK)
	appRepo := application.NewRepository(db)
	now := time.Now().Unix()
	require.NoError(t, appRepo.CreateApplication(&application.Application{ID: boundAppID, Name: "bound", CreatedAt: now, UpdatedAt: now}))
	require.NoError(t, appRepo.CreateMember(&application.Member{ID: "m-owner", ApplicationID: boundAppID, Role: application.MemberRoleOwner, PublicKey: boundOwnerPK}))

	userRepo := user.NewUserRepository(db)
	repo := NewInvitationRepository(db)
	eventService := event.NewEventService(event.NewEventRepository(db), appRepo, nil, nil)
	svc := NewInvitationService(repo, priv, pub, appRepo, db, userRepo, eventService, spacePK)
	return &boundFixture{t: t, db: db, svc: svc, repo: repo, appRepo: appRepo, users: userRepo, ep: NewInvitationEndpoints(svc, nil, "")}
}

func (f *boundFixture) invite(opts CreateInvitationOptions) (*InvitationResponse, error) {
	opts.ApplicationID = boundAppID
	opts.CreatedByPublicKey = boundOwnerPK
	return f.svc.CreateInvitation(opts)
}

func (f *boundFixture) join(token string, priv ed25519.PrivateKey, keyB64, inviteID string) *fasthttp.RequestCtx {
	f.t.Helper()
	proof := buildJoinProof(f.t, priv, keyB64, keyB64, "joiner", inviteID, time.Now().Unix())
	body, err := json.Marshal(map[string]string{"proof": proof})
	require.NoError(f.t, err)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetBody(body)
	ctx.SetUserValue("token", token)
	f.ep.JoinApplication(ctx)
	return ctx
}

func TestCreateInvitation_ShouldBindMembersAndForceMaxUses(t *testing.T) {
	// given
	f := newBoundFixture(t)
	_, _, keyA := generateDeviceKey(t)
	_, _, keyB := generateDeviceKey(t)
	hours := 720

	// when
	resp, err := f.invite(CreateInvitationOptions{MemberPublicKeys: []string{keyA, keyB}, ExpiresInHours: &hours})

	// then
	require.NoError(t, err)
	stored, err := f.repo.GetByID(resp.ID)
	require.NoError(t, err)
	require.NotNil(t, stored.MaxUses)
	assert.Equal(t, 2, *stored.MaxUses)
	assert.Equal(t, []string{keyA, keyB}, stored.MemberPublicKeys)
}

func TestCreateInvitation_ShouldRejectLongExpiryBeyondCaps(t *testing.T) {
	// given
	f := newBoundFixture(t)
	_, _, keyA := generateDeviceKey(t)
	tooLongBound := 721
	longUnbound := 49

	// when
	_, boundErr := f.invite(CreateInvitationOptions{MemberPublicKeys: []string{keyA}, ExpiresInHours: &tooLongBound})
	_, unboundErr := f.invite(CreateInvitationOptions{ExpiresInHours: &longUnbound})

	// then
	assert.Error(t, boundErr)
	assert.Error(t, unboundErr)
}

func TestJoin_ShouldRejectKeyNotOnMemberList(t *testing.T) {
	// given
	f := newBoundFixture(t)
	_, _, listed := generateDeviceKey(t)
	_, strangerPriv, stranger := generateDeviceKey(t)
	resp, err := f.invite(CreateInvitationOptions{MemberPublicKeys: []string{listed}})
	require.NoError(t, err)

	// when
	ctx := f.join(resp.Token, strangerPriv, stranger, resp.ID)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	var body map[string]any
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &body))
	assert.Equal(t, "invite_not_for_member", body["code"])
	u, err := f.users.GetUserByPublicKey(stranger)
	require.NoError(t, err)
	assert.Nil(t, u)
}

func TestJoin_ShouldAdmitListedNewAccountUnderSingleUseSignup(t *testing.T) {
	// given
	f := newBoundFixture(t)
	f.svc.SingleUseSignup = true
	_, listedPriv, listed := generateDeviceKey(t)
	_, _, other := generateDeviceKey(t)
	resp, err := f.invite(CreateInvitationOptions{MemberPublicKeys: []string{listed, other}})
	require.NoError(t, err)

	// when
	ctx := f.join(resp.Token, listedPriv, listed, resp.ID)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	u, err := f.users.GetUserByPublicKey(listed)
	require.NoError(t, err)
	require.NotNil(t, u)
	assert.Equal(t, user.RoleGuest, u.Role)
	isMember, err := f.appRepo.IsMember(boundAppID, listed)
	require.NoError(t, err)
	assert.True(t, isMember)
}

func TestJoin_ShouldRejectWithConflictWhileApplicationMoving(t *testing.T) {
	// given
	f := newBoundFixture(t)
	_, joinerPriv, joiner := generateDeviceKey(t)
	resp, err := f.invite(CreateInvitationOptions{})
	require.NoError(t, err)
	_, err = f.db.Exec(`UPDATE applications SET moved_to_url = 'https://b.example' WHERE id = $1`, boundAppID)
	require.NoError(t, err)

	// when
	ctx := f.join(resp.Token, joinerPriv, joiner, resp.ID)

	// then
	assert.Equal(t, fasthttp.StatusConflict, ctx.Response.StatusCode())
	var body map[string]any
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &body))
	assert.Equal(t, "application_moving", body["code"])
}
