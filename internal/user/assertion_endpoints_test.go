package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
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

// rebindTestRepo is a minimal UserRepository stub for RebindIssuer tests -
// only SetUserIssuer is exercised (and recorded, so tests can assert it was
// NOT called on the idempotent path); every other method is an unused
// no-op.
type rebindTestRepo struct {
	setIssuerCalls []struct {
		publicKey string
		issuer    string
	}
}

func (r *rebindTestRepo) SetUserIssuer(publicKey, issuer string) error {
	r.setIssuerCalls = append(r.setIssuerCalls, struct {
		publicKey string
		issuer    string
	}{publicKey, issuer})
	return nil
}

func (r *rebindTestRepo) CreateUser(u *User) error                           { return nil }
func (r *rebindTestRepo) GetUserByPublicKey(publicKey string) (*User, error) { return nil, nil }
func (r *rebindTestRepo) UpdateUserRole(publicKey, role string) error        { return nil }
func (r *rebindTestRepo) UpdateAvatarStorageID(publicKey string, avatarStorageID *string) error {
	return nil
}
func (r *rebindTestRepo) UpdateUsername(publicKey, username string) error { return nil }
func (r *rebindTestRepo) UpdateUserIssuer(publicKey, issuer string) error { return nil }
func (r *rebindTestRepo) EnsureDevice(devicePublicKey, userPublicKey string, deviceName *string, createdAt int64) error {
	return nil
}
func (r *rebindTestRepo) GetDevice(devicePublicKey string) (*Device, error)   { return nil, nil }
func (r *rebindTestRepo) ListDevices(userPublicKey string) ([]*Device, error) { return nil, nil }
func (r *rebindTestRepo) RevokeDevice(devicePublicKey string, ts int64) error { return nil }
func (r *rebindTestRepo) RenameDevice(devicePublicKey, deviceName string) error {
	return nil
}
func (r *rebindTestRepo) TouchDeviceLastSeen(devicePublicKey string, ts int64) error { return nil }
func (r *rebindTestRepo) SetPasswordCredentials(publicKey, passwordVerifier, handle, accountKeyBlob, userState string) error {
	return nil
}
func (r *rebindTestRepo) GetPasswordCredential(username string) (string, string, error) {
	return "", "", nil
}
func (r *rebindTestRepo) GetPasswordHandle(username string) (string, error) { return "", nil }
func (r *rebindTestRepo) GetEscrow(publicKey string) (string, string, error) {
	return "", "", nil
}
func (r *rebindTestRepo) UpdateUserState(publicKey, userState string) error { return nil }
func (r *rebindTestRepo) ClaimOwner(publicKey, username, passwordVerifier, handle, accountKeyBlob, userState string, deviceName *string, createdAt int64) error {
	return nil
}
func (r *rebindTestRepo) HasClaim() (bool, error) { return false, nil }

// newRebindRequestCtx marshals the POST /identity/rebind request and sets
// the authenticated user in context the way RequireAuth would - RebindIssuer
// is tested directly, bypassing the middleware (mirrors
// newIssueAssertionRequestCtx above).
func newRebindRequestCtx(t *testing.T, authenticatedUser *User, rebind string) *fasthttp.RequestCtx {
	t.Helper()
	body, err := json.Marshal(rebindIssuerRequest{Rebind: rebind})
	assert.NoError(t, err)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.SetBody(body)
	if authenticatedUser != nil {
		ctx.SetUserValue("user", authenticatedUser)
	}
	return ctx
}

func TestRebindIssuer_ShouldReturn401WhenUnauthenticated(t *testing.T) {
	// given
	_, spacePriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	ae := NewAssertionEndpoints(&rebindTestRepo{}, spacePriv, "space-key")
	ctx := newRebindRequestCtx(t, nil, "irrelevant")

	// when
	ae.RebindIssuer(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}

func TestRebindIssuer_ShouldReturn401WhenVerificationFails(t *testing.T) {
	// given
	spacePub, spacePriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	spaceB64 := base64.StdEncoding.EncodeToString(spacePub)
	repo := &rebindTestRepo{}
	ae := NewAssertionEndpoints(repo, spacePriv, spaceB64)
	authenticatedUser := &User{PublicKey: "account-1", Issuer: "account-1"}
	ctx := newRebindRequestCtx(t, authenticatedUser, "not-a-valid-jws")

	// when
	ae.RebindIssuer(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
	assert.Empty(t, repo.setIssuerCalls)
}

func TestRebindIssuer_ShouldReturn401WhenAuthenticatedUserDoesNotMatchUserID(t *testing.T) {
	// given
	spacePub, spacePriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	spaceB64 := base64.StdEncoding.EncodeToString(spacePub)
	accountPub, accountPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	accountB64 := base64.StdEncoding.EncodeToString(accountPub)
	repo := &rebindTestRepo{}
	ae := NewAssertionEndpoints(repo, spacePriv, spaceB64)

	now := time.Now().Unix()
	jws := buildRebindJWS(t, jwt.SigningMethodEdDSA, accountPriv, accountB64, accountB64, spaceB64, "new-issuer", "jti-mismatch", now, now+120)
	// authenticated as a DIFFERENT account than the one the JWS names
	wrongUser := &User{PublicKey: "someone-else", Issuer: "someone-else"}
	ctx := newRebindRequestCtx(t, wrongUser, jws)

	// when: submitted under the wrong session
	ae.RebindIssuer(ctx)

	// then: rejected, and the jti must NOT be burned
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
	assert.Empty(t, repo.setIssuerCalls)

	// and: the same JWS still succeeds afterward under the right user -
	// proof the mismatch above never consumed the jti (finding: a valid
	// rebind submitted under the wrong session must not burn its jti).
	rightUser := &User{PublicKey: accountB64, Issuer: accountB64}
	ctx2 := newRebindRequestCtx(t, rightUser, jws)
	ae.RebindIssuer(ctx2)
	assert.Equal(t, fasthttp.StatusNoContent, ctx2.Response.StatusCode())
	if assert.Len(t, repo.setIssuerCalls, 1) {
		assert.Equal(t, accountB64, repo.setIssuerCalls[0].publicKey)
		assert.Equal(t, "new-issuer", repo.setIssuerCalls[0].issuer)
	}
}

func TestRebindIssuer_ShouldReturn204WithNoWriteWhenAlreadyAtTargetIssuer(t *testing.T) {
	// given
	spacePub, spacePriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	spaceB64 := base64.StdEncoding.EncodeToString(spacePub)
	accountPub, accountPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	accountB64 := base64.StdEncoding.EncodeToString(accountPub)
	repo := &rebindTestRepo{}
	ae := NewAssertionEndpoints(repo, spacePriv, spaceB64)

	now := time.Now().Unix()
	jws := buildRebindJWS(t, jwt.SigningMethodEdDSA, accountPriv, accountB64, accountB64, spaceB64, "already-current-issuer", "jti-idempotent", now, now+120)
	authenticatedUser := &User{PublicKey: accountB64, Issuer: "already-current-issuer"}
	ctx := newRebindRequestCtx(t, authenticatedUser, jws)

	// when
	ae.RebindIssuer(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNoContent, ctx.Response.StatusCode())
	assert.Empty(t, repo.setIssuerCalls, "idempotent rebind must not write to the repository")
}

func TestRebindIssuer_ShouldUpdateIssuerAndReturn204(t *testing.T) {
	// given
	spacePub, spacePriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	spaceB64 := base64.StdEncoding.EncodeToString(spacePub)
	accountPub, accountPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	accountB64 := base64.StdEncoding.EncodeToString(accountPub)
	repo := &rebindTestRepo{}
	ae := NewAssertionEndpoints(repo, spacePriv, spaceB64)

	now := time.Now().Unix()
	jws := buildRebindJWS(t, jwt.SigningMethodEdDSA, accountPriv, accountB64, accountB64, spaceB64, "new-issuer-key", "jti-write", now, now+120)
	authenticatedUser := &User{PublicKey: accountB64, Issuer: accountB64}
	ctx := newRebindRequestCtx(t, authenticatedUser, jws)

	// when
	ae.RebindIssuer(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNoContent, ctx.Response.StatusCode())
	if assert.Len(t, repo.setIssuerCalls, 1) {
		assert.Equal(t, accountB64, repo.setIssuerCalls[0].publicKey)
		assert.Equal(t, "new-issuer-key", repo.setIssuerCalls[0].issuer)
	}
}
