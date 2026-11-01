//go:build integration

package event

import (
	"testing"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

func TestSubmitEvent_ShouldReturn422ForUnappliableEvent(t *testing.T) {
	// given: the event targets an application this space doesn't have
	db := connectApply(t)
	endpoints := NewEventEndpoints(NewEventService(NewEventRepository(db), application.NewMemoryRepository(), nil, nil))
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue("user", &user.User{PublicKey: "member-pk"})
	ctx.Request.SetBody([]byte(`{"event":{"id":"endpoint-422-evt","type":"component_data_changed","creatorPublicKey":"member-pk","version":1,` +
		`"data":{"applicationId":"no-such-app","componentId":"c-1","changedFields":{}}}}`))

	// when
	endpoints.SubmitEvent(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnprocessableEntity, ctx.Response.StatusCode())
	assert.Contains(t, string(ctx.Response.Body()), `"reason":"validation_failed"`)
}

func TestSubmitEvent_ShouldReturn422ForExecuteTimeValidationFailure(t *testing.T) {
	// given: component_data_changed without componentId passes ValidateEvent but fails in execute
	db := connectApply(t)
	prefix := "endpoint-exec-422-"
	appRepo := seedRoleApp(t, db, prefix)
	endpoints := NewEventEndpoints(NewEventService(NewEventRepository(db), appRepo, nil, nil))
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue("user", &user.User{PublicKey: prefix + "member"})
	ctx.Request.SetBody([]byte(`{"event":{"id":"` + prefix + `evt","type":"component_data_changed","creatorPublicKey":"` + prefix + `member","version":1,` +
		`"data":{"applicationId":"` + prefix + `app","changedFields":{}}}}`))

	// when
	endpoints.SubmitEvent(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnprocessableEntity, ctx.Response.StatusCode())
	assert.Contains(t, string(ctx.Response.Body()), `"reason":"validation_failed"`)
}
