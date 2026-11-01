//go:build integration

package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

func (f *moveFixture) makeGuest(pk string) {
	f.t.Helper()
	_, err := f.db.Exec(`UPDATE users SET role='guest' WHERE public_key=$1`, pk)
	require.NoError(f.t, err)
}

func (f *moveFixture) setUpGuest(appRole string) {
	f.t.Helper()
	f.setUp()
	f.makeGuest(moveMemberPK)
	f.setMemberRole(moveMemberPK, appRole)
}

func (f *moveFixture) inviteID() string {
	f.t.Helper()
	ctx := f.createInvite(moveOwnerPK)
	require.Equal(f.t, fasthttp.StatusCreated, ctx.Response.StatusCode())
	id, _ := responseBody(f.t, ctx)["id"].(string)
	require.NotEmpty(f.t, id)
	return id
}

func TestCreateInvite_ShouldReturn201ForGuestAppAdmin(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUpGuest("admin")

	// when
	ctx := f.createInvite(moveMemberPK)

	// then
	assert.Equal(t, fasthttp.StatusCreated, ctx.Response.StatusCode(), string(ctx.Response.Body()))
}

func TestListInvites_ShouldReturn200ForGuestAppAdmin(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUpGuest("admin")
	id := f.inviteID()

	// when
	ctx := f.doJSON("GET", "/applications/"+moveAppID+"/invites", moveMemberPK, nil)

	// then
	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	assert.Contains(t, string(ctx.Response.Body()), id)
}

func TestRevokeInvite_ShouldReturn204ForGuestAppAdmin(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUpGuest("admin")
	id := f.inviteID()

	// when
	ctx := f.doJSON("DELETE", "/applications/"+moveAppID+"/invites/"+id, moveMemberPK, nil)

	// then
	assert.Equal(t, fasthttp.StatusNoContent, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	assert.Equal(t, 0, f.count("SELECT COUNT(*) FROM invitations WHERE application_id = $1"))
}

func TestCreateInvite_ShouldReturn403ForGuestAppMember(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUpGuest("member")

	// when
	ctx := f.createInvite(moveMemberPK)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	assert.Equal(t, "forbidden", string(ctx.Response.Body()))
}

func TestListInvites_ShouldReturn403ForGuestAppMember(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUpGuest("member")

	// when
	ctx := f.doJSON("GET", "/applications/"+moveAppID+"/invites", moveMemberPK, nil)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	assert.Equal(t, "forbidden", string(ctx.Response.Body()))
}

func TestRevokeInvite_ShouldReturn403ForGuestAppMember(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUpGuest("member")
	id := f.inviteID()

	// when
	ctx := f.doJSON("DELETE", "/applications/"+moveAppID+"/invites/"+id, moveMemberPK, nil)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	assert.Equal(t, "forbidden", string(ctx.Response.Body()))
	assert.Equal(t, 1, f.count("SELECT COUNT(*) FROM invitations WHERE application_id = $1"))
}

func TestCreateInvite_ShouldReturn403ForGuestAppAdminGrantingSpaceUse(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUpGuest("admin")

	// when
	ctx := f.doJSON("POST", "/applications/"+moveAppID+"/invites", moveMemberPK, map[string]any{"role": "member", "grantsSpaceUse": true})

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	assert.Equal(t, "only the space owner can grant space use", string(ctx.Response.Body()))
}

func TestCreateInvite_ShouldReturn403ForGuestNonMember(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUp()
	f.makeGuest(moveOutsidePK)

	// when
	ctx := f.createInvite(moveOutsidePK)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	assert.Equal(t, "forbidden", string(ctx.Response.Body()))
}

func TestCreateInvite_ShouldReturn403AfterGuestAppAdminDemoted(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUpGuest("admin")
	require.Equal(t, fasthttp.StatusCreated, f.createInvite(moveMemberPK).Response.StatusCode())

	// when
	f.setMemberRole(moveMemberPK, "member")
	ctx := f.createInvite(moveMemberPK)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
}
