package push

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

func TestValidateEndpoint_ShouldRejectNonHTTPS(t *testing.T) {
	// given
	bad := []string{
		"http://push.example/x",
		"https:///x",
		"https://u:p@push.example/x",
		"https://user@push.example/x",
		"ftp://push.example",
		"not a url",
		"",
		"%zz",
	}
	good := []string{
		"https://fcm.googleapis.com/fcm/send/abc",
		"https://ntfy.example.com:8443/topic?up=1",
		"HTTPS://push.example/x",
		"https://[2606:4700::1]/x",
	}

	// when / then
	for _, raw := range bad {
		assert.ErrorIs(t, validateEndpoint(raw), ErrInvalidEndpoint, raw)
	}
	for _, raw := range good {
		assert.NoError(t, validateEndpoint(raw), raw)
	}
}

func TestCreateSubscription_ShouldReturn400WhenEndpointNotHTTPS(t *testing.T) {
	// given
	ep, repo := newTestEndpoints()
	ctx := newTestRequestCtx("POST", `{"endpoint":"http://push.example.com/1","p256dh":"p256","auth":"auth123"}`)
	setAuthUser(ctx, testUser("user-pk-1"))

	// when
	ep.CreateSubscription(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	assert.Empty(t, repo.subscriptions)
}

func TestUpdateSubscription_ShouldReturn400WhenEndpointNotHTTPS(t *testing.T) {
	// given
	ep, repo := newTestEndpoints()
	repo.subscriptions["sub-1"] = &Subscription{
		ID:                  "sub-1",
		DevicePublicKey:     "user-pk-1",
		Endpoint:            "https://push.example.com/old",
		P256dh:              "old-p256",
		Auth:                "old-auth",
		MutedApplicationIDs: []string{"keep"},
	}
	ctx := newTestRequestCtx("PATCH", `{"endpoint":"http://127.0.0.1/x","mutedApplicationIds":["changed"]}`)
	ctx.SetUserValue("subscriptionId", "sub-1")
	setAuthUser(ctx, testUser("user-pk-1"))

	// when
	ep.UpdateSubscription(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	assert.Equal(t, "https://push.example.com/old", repo.subscriptions["sub-1"].Endpoint)
	assert.Equal(t, []string{"keep"}, repo.subscriptions["sub-1"].MutedApplicationIDs)
}
