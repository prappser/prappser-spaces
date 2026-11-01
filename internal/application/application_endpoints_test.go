package application

import (
	"testing"

	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

func newAgentReadCtx(caller *user.User, body string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("PUT")
	ctx.SetUserValue("user", caller)
	ctx.SetUserValue("appID", "app-1")
	ctx.Request.SetBody([]byte(body))
	return ctx
}

func newAgentReadEndpoints(t *testing.T) (*ApplicationEndpoints, *user.User, *user.User) {
	t.Helper()
	owner := createTestUser()
	member := createRegularUser()
	appService := NewApplicationService(NewMemoryRepository(), 0, "space-key")
	app := createBasicApplication(owner, "App", "app-1")
	app.Members = append(app.Members, Member{ID: "m2", Role: MemberRoleAdmin, PublicKey: member.PublicKey})
	_, err := appService.RegisterApplication(owner, app)
	assert.NoError(t, err)
	return NewApplicationEndpoints(appService), owner, member
}

func TestSetAgentRead_ShouldReturn200ForOwner(t *testing.T) {
	// given
	ep, owner, _ := newAgentReadEndpoints(t)
	ctx := newAgentReadCtx(owner, `{"enabled": false}`)

	// when
	ep.SetAgentRead(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.JSONEq(t, `{"agentReadEnabled": false}`, string(ctx.Response.Body()))
}

func TestSetAgentRead_ShouldReturn403ForNonOwner(t *testing.T) {
	// given
	ep, _, member := newAgentReadEndpoints(t)
	ctx := newAgentReadCtx(member, `{"enabled": false}`)

	// when
	ep.SetAgentRead(ctx)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
}

func TestSetAgentRead_ShouldReturn400ForBadBody(t *testing.T) {
	// given
	ep, owner, _ := newAgentReadEndpoints(t)

	for _, body := range []string{``, `not json`, `{}`} {
		ctx := newAgentReadCtx(owner, body)

		// when
		ep.SetAgentRead(ctx)

		// then
		assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode(), body)
	}
}
