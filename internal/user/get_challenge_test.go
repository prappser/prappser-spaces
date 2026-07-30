package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// getChallengeTestRepo is a UserRepository stub whose GetUserByPublicKey
// mirrors the real userRepository's contract: nil, nil for a missing user,
// an error only for genuine DB failures. mockUserRepository (above, in
// user_test.go) returns an error for a missing user instead, which doesn't
// match production behavior and would mask the enumeration-oracle fix below.
type getChallengeTestRepo struct {
	users    map[string]*User
	failWith error
}

func (r *getChallengeTestRepo) CreateUser(u *User) error { return nil }

func (r *getChallengeTestRepo) GetUserByPublicKey(publicKey string) (*User, error) {
	if r.failWith != nil {
		return nil, r.failWith
	}
	return r.users[publicKey], nil
}

func (r *getChallengeTestRepo) GetUserByUsername(username string) (*User, error) { return nil, nil }
func (r *getChallengeTestRepo) UpdateUserRole(publicKey, role string) error      { return nil }
func (r *getChallengeTestRepo) UpdateAvatarStorageID(publicKey string, avatarStorageID *string) error {
	return nil
}
func (r *getChallengeTestRepo) UpdateUsername(publicKey, username string) error { return nil }

func newGetChallengeTestEndpoints(repo UserRepository) *UserEndpoints {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return NewEndpoints(repo, Config{ChallengeTTLSec: 300}, priv, pub, nil, nil)
}

func newChallengeRequestCtx(publicKey string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI(fmt.Sprintf("/users/challenge?publicKey=%s", publicKey))
	return ctx
}

func TestGetChallenge_ShouldReturnAndStoreChallengeForExistingUser(t *testing.T) {
	// given
	repo := &getChallengeTestRepo{users: map[string]*User{
		"pk-1": {PublicKey: "pk-1", Username: "alice", Role: RoleUser},
	}}
	ep := newGetChallengeTestEndpoints(repo)
	ctx := newChallengeRequestCtx("pk-1")

	// when
	ep.GetChallenge(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	var resp ChallengeResponse
	assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	assert.NotEmpty(t, resp.Challenge)
	assert.NotZero(t, resp.ExpiresAt)
	assert.NotEmpty(t, resp.SpacePublicKey)

	stored, ok := ep.challenges.get("pk-1")
	assert.True(t, ok)
	assert.Equal(t, resp.Challenge, stored.challenge)
}

func TestGetChallenge_ShouldReturnDecoyChallengeForUnknownUserWithoutStoringIt(t *testing.T) {
	// given - no users in the repo
	repo := &getChallengeTestRepo{users: map[string]*User{}}
	ep := newGetChallengeTestEndpoints(repo)
	ctx := newChallengeRequestCtx("does-not-exist")

	// when
	ep.GetChallenge(ctx)

	// then - same response shape as the found case (200, real expiresAt/spacePublicKey)
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	var resp ChallengeResponse
	assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	assert.NotEmpty(t, resp.Challenge)
	assert.NotZero(t, resp.ExpiresAt)
	assert.NotEmpty(t, resp.SpacePublicKey)

	// but the decoy challenge is never stored, so it can never authenticate
	_, ok := ep.challenges.get("does-not-exist")
	assert.False(t, ok)
}

func TestGetChallenge_ShouldReturn500OnRepositoryError(t *testing.T) {
	// given
	repo := &getChallengeTestRepo{failWith: fmt.Errorf("db unavailable")}
	ep := newGetChallengeTestEndpoints(repo)
	ctx := newChallengeRequestCtx("pk-1")

	// when
	ep.GetChallenge(ctx)

	// then
	assert.Equal(t, fasthttp.StatusInternalServerError, ctx.Response.StatusCode())
}
