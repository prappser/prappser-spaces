package push

import (
	"testing"

	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// stubPushService satisfies the service dependency for endpoint tests.
// Endpoints only call repo methods directly, so a nil service is acceptable for most tests.
// We pass a real PushService backed by the mock repo for completeness.

// newTestRequestCtx builds a minimal fasthttp.RequestCtx suitable for unit tests.
func newTestRequestCtx(method, body string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(method)
	ctx.Request.SetBody([]byte(body))
	return ctx
}

// setAuthUser injects a *user.User into the context as the "user" value.
func setAuthUser(ctx *fasthttp.RequestCtx, u *user.User) {
	ctx.SetUserValue("user", u)
}

func testUser(publicKey string) *user.User {
	return &user.User{PublicKey: publicKey, Username: "testuser", Role: "user"}
}

// newTestEndpoints wires a mock repo and mock VAPID service into PushEndpoints.
func newTestEndpoints() (*PushEndpoints, *mockPushRepository) {
	repo := newMockPushRepository()
	vapidSvc := newMockSpaceVapidService("test-pub-key", "test-priv-key")
	svc := NewPushService(repo, newMockWebpushSender(SendResult{StatusCode: 201}), vapidSvc)
	ep := NewPushEndpoints(svc, repo, vapidSvc)
	return ep, repo
}

// ---- GetVapidPublicKey ----

func TestGetVapidPublicKey_ShouldReturn200WithPublicKey(t *testing.T) {
	// given
	ep, _ := newTestEndpoints()
	ctx := newTestRequestCtx("GET", "")

	// when
	ep.GetVapidPublicKey(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	var resp map[string]string
	err := json.Unmarshal(ctx.Response.Body(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "test-pub-key", resp["publicKey"])
}

func TestGetVapidPublicKey_ShouldNotRequireAuth(t *testing.T) {
	// given
	ep, _ := newTestEndpoints()
	ctx := newTestRequestCtx("GET", "")
	// no user injected — unauthenticated request

	// when
	ep.GetVapidPublicKey(ctx)

	// then: 200 OK without any auth header
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
}

// ---- CreateSubscription ----

func TestCreateSubscription_ShouldReturn201WithMutedApplicationIDs(t *testing.T) {
	// given
	ep, repo := newTestEndpoints()
	body := `{"endpoint":"https://push.example.com/1","p256dh":"p256","auth":"auth123","mutedApplicationIds":["app-x"]}`
	ctx := newTestRequestCtx("POST", body)
	setAuthUser(ctx, testUser("user-pk-1"))

	// when
	ep.CreateSubscription(ctx)

	// then
	assert.Equal(t, fasthttp.StatusCreated, ctx.Response.StatusCode())

	var resp map[string]string
	err := json.Unmarshal(ctx.Response.Body(), &resp)
	assert.NoError(t, err)
	id := resp["id"]
	assert.NotEmpty(t, id)
	assert.NotNil(t, repo.subscriptions[id])
	assert.Equal(t, []string{"app-x"}, repo.subscriptions[id].MutedApplicationIDs)
}

func TestCreateSubscription_ShouldDefaultMutedApplicationIDsToEmptySlice(t *testing.T) {
	// given
	ep, repo := newTestEndpoints()
	body := `{"endpoint":"https://push.example.com/2","p256dh":"p256","auth":"auth123"}`
	ctx := newTestRequestCtx("POST", body)
	setAuthUser(ctx, testUser("user-pk-1"))

	// when
	ep.CreateSubscription(ctx)

	// then
	assert.Equal(t, fasthttp.StatusCreated, ctx.Response.StatusCode())

	var resp map[string]string
	err := json.Unmarshal(ctx.Response.Body(), &resp)
	assert.NoError(t, err)
	id := resp["id"]
	assert.NotEmpty(t, id)
	assert.Equal(t, []string{}, repo.subscriptions[id].MutedApplicationIDs)
}

func TestCreateSubscription_ShouldReturn400WhenEndpointMissing(t *testing.T) {
	// given
	ep, _ := newTestEndpoints()
	body := `{"p256dh":"p256","auth":"auth123"}`
	ctx := newTestRequestCtx("POST", body)
	setAuthUser(ctx, testUser("user-pk-1"))

	// when
	ep.CreateSubscription(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestCreateSubscription_ShouldReturn401WhenNoUser(t *testing.T) {
	// given
	ep, _ := newTestEndpoints()
	body := `{"endpoint":"https://push.example.com/1","p256dh":"p256","auth":"auth123"}`
	ctx := newTestRequestCtx("POST", body)
	// no user injected

	// when
	ep.CreateSubscription(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}

// ---- UpdateSubscription ----

func TestUpdateSubscription_ShouldReturn200WithMutedApplicationIDs(t *testing.T) {
	// given
	ep, repo := newTestEndpoints()
	repo.subscriptions["sub-1"] = &Subscription{
		ID:                  "sub-1",
		UserPublicKey:       "user-pk-1",
		Endpoint:            "https://push.example.com/old",
		P256dh:              "old-p256",
		Auth:                "old-auth",
		MutedApplicationIDs: []string{},
	}

	body := `{"endpoint":"https://push.example.com/new","mutedApplicationIds":["app-y"]}`
	ctx := newTestRequestCtx("PATCH", body)
	ctx.SetUserValue("subscriptionId", "sub-1")
	setAuthUser(ctx, testUser("user-pk-1"))

	// when
	ep.UpdateSubscription(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Equal(t, "https://push.example.com/new", repo.subscriptions["sub-1"].Endpoint)
	assert.Equal(t, []string{"app-y"}, repo.subscriptions["sub-1"].MutedApplicationIDs)
}

func TestUpdateSubscription_ShouldReturn404WhenNotOwned(t *testing.T) {
	// given
	ep, repo := newTestEndpoints()
	repo.subscriptions["sub-1"] = &Subscription{
		ID:            "sub-1",
		UserPublicKey: "other-user",
		Endpoint:      "https://push.example.com/1",
		P256dh:        "p256",
		Auth:          "auth",
	}

	ctx := newTestRequestCtx("PATCH", `{}`)
	ctx.SetUserValue("subscriptionId", "sub-1")
	setAuthUser(ctx, testUser("user-pk-1")) // different user

	// when
	ep.UpdateSubscription(ctx)

	// then: 404 because GetSubscriptionByID scopes by user
	assert.Equal(t, fasthttp.StatusNotFound, ctx.Response.StatusCode())
}

// ---- DeleteSubscription ----

func TestDeleteSubscription_ShouldReturn204(t *testing.T) {
	// given
	ep, repo := newTestEndpoints()
	repo.subscriptions["sub-1"] = &Subscription{
		ID:            "sub-1",
		UserPublicKey: "user-pk-1",
		Endpoint:      "https://push.example.com/1",
		P256dh:        "p256",
		Auth:          "auth",
	}

	ctx := newTestRequestCtx("DELETE", "")
	ctx.SetUserValue("subscriptionId", "sub-1")
	setAuthUser(ctx, testUser("user-pk-1"))

	// when
	ep.DeleteSubscription(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNoContent, ctx.Response.StatusCode())
}

func TestDeleteSubscription_ShouldReturn404WhenNotFound(t *testing.T) {
	// given
	ep, _ := newTestEndpoints()
	ctx := newTestRequestCtx("DELETE", "")
	ctx.SetUserValue("subscriptionId", "nonexistent")
	setAuthUser(ctx, testUser("user-pk-1"))

	// when
	ep.DeleteSubscription(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNotFound, ctx.Response.StatusCode())
}

func TestDeleteSubscription_ShouldReturn401WhenNoUser(t *testing.T) {
	// given
	ep, _ := newTestEndpoints()
	ctx := newTestRequestCtx("DELETE", "")
	ctx.SetUserValue("subscriptionId", "sub-1")
	// no user injected

	// when
	ep.DeleteSubscription(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}
