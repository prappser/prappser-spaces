//go:build integration

package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// TestRebindIssuer_ShouldRoundTripAndBeVisibleViaGetProfile_Integration
// covers the #116 Phase 5 rebind endpoint end to end against a real
// Postgres-backed UserRepository: RebindIssuer writes the new issuer, and
// the account-key-signed transition is then visible through
// UserEndpoints.GetProfile - the real handler behind GET /users/me.
// RebindIssuer and GetProfile are called directly (bypassing RequireAuth,
// as assertion_endpoints_test.go's IssueAssertion tests do) since
// middleware wiring isn't what this test is verifying.
func TestRebindIssuer_ShouldRoundTripAndBeVisibleViaGetProfile_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	spacePub, spacePriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	spaceB64 := base64.StdEncoding.EncodeToString(spacePub)

	accountPub, accountPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	accountB64 := base64.StdEncoding.EncodeToString(accountPub)

	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at, issuer) VALUES ($1,$2,$3,$4,$1)",
		accountB64, "alice", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}

	ae := NewAssertionEndpoints(repo, spacePriv, spaceB64)
	ue := NewEndpoints(repo, Config{ChallengeTTLSec: 300}, spacePriv, spacePub, nil, nil)

	authenticatedUser, err := repo.GetUserByPublicKey(accountB64)
	assert.NoError(t, err)
	authenticatedUser.DevicePublicKey = accountB64

	now := time.Now().Unix()
	rebindJWS := buildRebindJWS(t, jwt.SigningMethodEdDSA, accountPriv, accountB64, accountB64, spaceB64, "vouching-space-key", "jti-integration-1", now, now+120)

	// when - rebind self-pinned -> vouched
	rebindCtx := &fasthttp.RequestCtx{}
	rebindCtx.Request.Header.SetMethod("POST")
	rebindCtx.Request.SetBody([]byte(`{"rebind":"` + rebindJWS + `"}`))
	rebindCtx.SetUserValue("user", authenticatedUser)
	ae.RebindIssuer(rebindCtx)

	// then
	assert.Equal(t, fasthttp.StatusNoContent, rebindCtx.Response.StatusCode())

	updatedUser, err := repo.GetUserByPublicKey(accountB64)
	assert.NoError(t, err)
	assert.Equal(t, "vouching-space-key", updatedUser.Issuer)

	// and - GET /users/me's real handler reflects the new issuer
	updatedUser.DevicePublicKey = accountB64
	profileCtx := &fasthttp.RequestCtx{}
	profileCtx.SetUserValue("user", updatedUser)
	ue.GetProfile(profileCtx)

	assert.Equal(t, fasthttp.StatusOK, profileCtx.Response.StatusCode())
	assert.Contains(t, string(profileCtx.Response.Body()), `"issuer":"vouching-space-key"`)

	// and - a second rebind to the SAME issuer is idempotent: 204, no error,
	// and the issuer is unchanged (VerifyRebind's jti replay guard would
	// reject reusing rebindJWS, so mint a fresh one carrying the same
	// new_issuer to exercise the idempotent no-write path honestly).
	idempotentJWS := buildRebindJWS(t, jwt.SigningMethodEdDSA, accountPriv, accountB64, accountB64, spaceB64, "vouching-space-key", "jti-integration-2", now, now+120)
	idempotentCtx := &fasthttp.RequestCtx{}
	idempotentCtx.Request.Header.SetMethod("POST")
	idempotentCtx.Request.SetBody([]byte(`{"rebind":"` + idempotentJWS + `"}`))
	idempotentCtx.SetUserValue("user", updatedUser)
	ae.RebindIssuer(idempotentCtx)

	assert.Equal(t, fasthttp.StatusNoContent, idempotentCtx.Response.StatusCode())
	stillUser, err := repo.GetUserByPublicKey(accountB64)
	assert.NoError(t, err)
	assert.Equal(t, "vouching-space-key", stillUser.Issuer)
}
