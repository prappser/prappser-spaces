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
	repo := &bindingTestRepo{escrow: "blob"}
	ae := NewAssertionEndpoints(repo, spacePriv, spacePublicKeyB64, NewBindings(repo, spacePublicKeyB64))

	audiencePub, _, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	audienceB64 := base64.StdEncoding.EncodeToString(audiencePub)

	authenticatedUser := &User{PublicKey: "account-1", Username: "alice", DevicePublicKey: "device-1", StoredBinding: "stored-jws"}
	ctx := newIssueAssertionRequestCtx(t, authenticatedUser, issueAssertionRequest{Audience: audienceB64})

	// when
	ae.IssueAssertion(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	var resp issueAssertionResponse
	assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	assert.NotEmpty(t, resp.Assertion)

	claims, err := VerifyAssertion(resp.Assertion, audienceB64, "device-1", spacePublicKeyB64, time.Now())
	assert.NoError(t, err)
	assert.Equal(t, spacePublicKeyB64, claims.Issuer)
	assert.Equal(t, "account-1", claims.UserID)
	assert.Equal(t, "alice", claims.Username)
	assert.Equal(t, "device-1", claims.DevicePublicKey)
	assert.Equal(t, resp.ExpiresAt, claims.ExpiresAt)
	assert.Equal(t, "stored-jws", resp.Binding)
}

func TestIssueAssertion_ShouldReturn401WhenUnauthenticated(t *testing.T) {
	// given
	_, spacePriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	ae := newTestAssertionEndpoints(spacePriv, "space-key")

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
	ae := newTestAssertionEndpoints(spacePriv, "space-key")
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
	ae := newTestAssertionEndpoints(spacePriv, "space-key")
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
	ae := newTestAssertionEndpoints(spacePriv, spacePublicKeyB64)
	authenticatedUser := &User{PublicKey: "account-1", Username: "alice", DevicePublicKey: "device-1"}
	ctx := newIssueAssertionRequestCtx(t, authenticatedUser, issueAssertionRequest{Audience: spacePublicKeyB64})

	// when
	ae.IssueAssertion(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func newTestAssertionEndpoints(spacePriv ed25519.PrivateKey, spaceKey string) *AssertionEndpoints {
	repo := &bindingTestRepo{escrow: "blob"}
	return NewAssertionEndpoints(repo, spacePriv, spaceKey, NewBindings(repo, spaceKey))
}

func TestIssueAssertion_ShouldReturn409NotIdentitySpaceWithBindingWhenForeignBindingStored(t *testing.T) {
	// given
	spacePub, spacePriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	spaceKey := base64.StdEncoding.EncodeToString(spacePub)
	repo := &bindingTestRepo{escrow: "blob"}
	ae := NewAssertionEndpoints(repo, spacePriv, spaceKey, NewBindings(repo, spaceKey))
	acctPriv, acct := newTestKey(t)
	_, foreign := newTestKey(t)
	jws := buildBindingJWS(t, acctPriv, bindingTyp, acct, foreign, time.Now().Unix())
	_, _, err = ae.bindings.Accept(acct, jws, &bindingClaims{Issuer: acct, Subject: foreign, IssuedAt: time.Now().Unix()})
	assert.NoError(t, err)
	audPub, _, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	ctx := newIssueAssertionRequestCtx(t, &User{PublicKey: acct, BindingSub: foreign, StoredBinding: jws}, issueAssertionRequest{Audience: base64.StdEncoding.EncodeToString(audPub)})

	// when
	ae.IssueAssertion(ctx)

	// then
	assert.Equal(t, fasthttp.StatusConflict, ctx.Response.StatusCode())
	var resp bindingResponse
	assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	assert.Equal(t, "not_identity_space", resp.Code)
	assert.Equal(t, jws, resp.Binding)
}

func TestIssueAssertion_ShouldOmitBindingWhenNoneStored(t *testing.T) {
	// given
	spacePub, spacePriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	ae := newTestAssertionEndpoints(spacePriv, base64.StdEncoding.EncodeToString(spacePub))
	audPub, _, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	ctx := newIssueAssertionRequestCtx(t, &User{PublicKey: "account-1", Username: "alice", DevicePublicKey: "device-1"}, issueAssertionRequest{Audience: base64.StdEncoding.EncodeToString(audPub)})

	// when
	ae.IssueAssertion(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.NotContains(t, string(ctx.Response.Body()), `"binding"`)
}
