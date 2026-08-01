package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// newIssueAssertionRequestCtx marshals body as the POST /identity/assertion
// request and sets the authenticated user in context the way RequireAuth
// would - IssueAssertion is tested directly, bypassing the middleware.
func newIssueAssertionRequestCtx(t *testing.T, authenticatedUser *User, body issueAssertionRequest) *fasthttp.RequestCtx {
	t.Helper()
	b, err := json.Marshal(body)
	assert.NoError(t, err)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.SetBody(b)
	if authenticatedUser != nil {
		ctx.SetUserValue("user", authenticatedUser)
	}
	return ctx
}

func TestIssueAssertion_ShouldMintTokenBoundToDeviceAndAudience(t *testing.T) {
	// given
	spacePub, spacePriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	spacePublicKeyB64 := base64.StdEncoding.EncodeToString(spacePub)
	ae := NewAssertionEndpoints(nil, spacePriv, spacePublicKeyB64)

	audiencePub, _, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	audienceB64 := base64.StdEncoding.EncodeToString(audiencePub)

	authenticatedUser := &User{PublicKey: "account-1", Username: "alice", DevicePublicKey: "device-1"}
	ctx := newIssueAssertionRequestCtx(t, authenticatedUser, issueAssertionRequest{Audience: audienceB64})

	// when
	ae.IssueAssertion(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	var resp issueAssertionResponse
	assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	assert.NotEmpty(t, resp.Assertion)

	claims, err := VerifyAssertion(resp.Assertion, audienceB64, "device-1", time.Now())
	assert.NoError(t, err)
	assert.Equal(t, spacePublicKeyB64, claims.Issuer)
	assert.Equal(t, "account-1", claims.UserID)
	assert.Equal(t, "alice", claims.Username)
	assert.Equal(t, "device-1", claims.DevicePublicKey)
	assert.Equal(t, resp.ExpiresAt, claims.ExpiresAt)
}

func TestIssueAssertion_ShouldReturn401WhenUnauthenticated(t *testing.T) {
	// given
	_, spacePriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	ae := NewAssertionEndpoints(nil, spacePriv, "space-key")

	audiencePub, _, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	ctx := newIssueAssertionRequestCtx(t, nil, issueAssertionRequest{Audience: base64.StdEncoding.EncodeToString(audiencePub)})

	// when
	ae.IssueAssertion(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}

func TestIssueAssertion_ShouldReturn400WhenAudienceMissing(t *testing.T) {
	// given
	_, spacePriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	ae := NewAssertionEndpoints(nil, spacePriv, "space-key")
	authenticatedUser := &User{PublicKey: "account-1", Username: "alice", DevicePublicKey: "device-1"}
	ctx := newIssueAssertionRequestCtx(t, authenticatedUser, issueAssertionRequest{})

	// when
	ae.IssueAssertion(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestIssueAssertion_ShouldReturn400WhenAudienceMalformed(t *testing.T) {
	// given
	_, spacePriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	ae := NewAssertionEndpoints(nil, spacePriv, "space-key")
	authenticatedUser := &User{PublicKey: "account-1", Username: "alice", DevicePublicKey: "device-1"}
	ctx := newIssueAssertionRequestCtx(t, authenticatedUser, issueAssertionRequest{Audience: "not-valid-base64-!!!"})

	// when
	ae.IssueAssertion(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestIssueAssertion_ShouldReturn400WhenAudienceEqualsOwnKey(t *testing.T) {
	// given
	spacePub, spacePriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	spacePublicKeyB64 := base64.StdEncoding.EncodeToString(spacePub)
	ae := NewAssertionEndpoints(nil, spacePriv, spacePublicKeyB64)
	authenticatedUser := &User{PublicKey: "account-1", Username: "alice", DevicePublicKey: "device-1"}
	ctx := newIssueAssertionRequestCtx(t, authenticatedUser, issueAssertionRequest{Audience: spacePublicKeyB64})

	// when
	ae.IssueAssertion(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}
