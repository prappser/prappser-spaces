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
	// revoked marks a device (keyed by its public key, same key space as
	// users here) as revoked in GetDevice.
	revoked map[string]bool
}

func (r *getChallengeTestRepo) CreateUser(u *User) error { return nil }

func (r *getChallengeTestRepo) GetUserByPublicKey(publicKey string) (*User, error) {
	if r.failWith != nil {
		return nil, r.failWith
	}
	return r.users[publicKey], nil
}

func (r *getChallengeTestRepo) UpdateUserRole(publicKey, role string) error { return nil }
func (r *getChallengeTestRepo) UpdateAvatarStorageID(publicKey string, avatarStorageID *string) error {
	return nil
}
func (r *getChallengeTestRepo) UpdateUsername(publicKey, username string) error { return nil }
func (r *getChallengeTestRepo) UpdateUserIssuer(publicKey, issuer string) error { return nil }

func (r *getChallengeTestRepo) EnsureDevice(devicePublicKey, userPublicKey string, deviceName *string, createdAt int64) error {
	return nil
}
func (r *getChallengeTestRepo) GetDevice(devicePublicKey string) (*Device, error) {
	if r.failWith != nil {
		return nil, r.failWith
	}
	u, ok := r.users[devicePublicKey]
	if !ok {
		return nil, nil
	}
	d := &Device{DevicePublicKey: devicePublicKey, UserPublicKey: u.PublicKey}
	if r.revoked[devicePublicKey] {
		revokedAt := int64(1)
		d.RevokedAt = &revokedAt
	}
	return d, nil
}
func (r *getChallengeTestRepo) ListDevices(userPublicKey string) ([]*Device, error)   { return nil, nil }
func (r *getChallengeTestRepo) RevokeDevice(devicePublicKey string, ts int64) error   { return nil }
func (r *getChallengeTestRepo) RenameDevice(devicePublicKey, deviceName string) error { return nil }
func (r *getChallengeTestRepo) TouchDeviceLastSeen(devicePublicKey string, ts int64) error {
	return nil
}
func (r *getChallengeTestRepo) SetPasswordCredentials(publicKey, passwordVerifier, handle, accountKeyBlob, userState string) error {
	return nil
}
func (r *getChallengeTestRepo) GetPasswordCredential(username string) (string, string, error) {
	return "", "", nil
}
func (r *getChallengeTestRepo) GetPasswordHandle(username string) (string, error) {
	return "", nil
}
func (r *getChallengeTestRepo) GetEscrow(publicKey string) (string, string, error) {
	return "", "", nil
}

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

// TestGetChallenge_ShouldReturn404ForUnknownDeviceWithoutStoringChallenge
// covers the plan-directed behavior change from the pre-device-roster
// decoy-response design: publicKey now names a DEVICE key rather than an
// account key, and device keys are server-generated random 32-byte values,
// not guessable identifiers like usernames - so returning 404 for an unknown
// one doesn't reopen the account-enumeration oracle the old decoy avoided.
func TestGetChallenge_ShouldReturn404ForUnknownDeviceWithoutStoringChallenge(t *testing.T) {
	// given - no devices in the repo
	repo := &getChallengeTestRepo{users: map[string]*User{}}
	ep := newGetChallengeTestEndpoints(repo)
	ctx := newChallengeRequestCtx("does-not-exist")

	// when
	ep.GetChallenge(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNotFound, ctx.Response.StatusCode())

	_, ok := ep.challenges.get("does-not-exist")
	assert.False(t, ok)
}

func TestGetChallenge_ShouldReturn404ForRevokedDevice(t *testing.T) {
	// given
	repo := &getChallengeTestRepo{
		users:   map[string]*User{"pk-1": {PublicKey: "pk-1", Username: "alice", Role: RoleUser}},
		revoked: map[string]bool{"pk-1": true},
	}
	ep := newGetChallengeTestEndpoints(repo)
	ctx := newChallengeRequestCtx("pk-1")

	// when
	ep.GetChallenge(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNotFound, ctx.Response.StatusCode())
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
