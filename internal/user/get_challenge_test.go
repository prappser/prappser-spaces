package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/url"
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
func (r *getChallengeTestRepo) UpdateLocale(string, string) error               { return nil }
func (r *getChallengeTestRepo) UpdateNotifyMode(string, string) error           { return nil }
func (r *getChallengeTestRepo) UpdateUsername(publicKey, username string) error { return nil }
func (r *getChallengeTestRepo) AcceptBinding(_, _ string, _ int64, _, _ string) (string, string, bool, error) {
	return "", "", false, nil
}

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
func (r *getChallengeTestRepo) ListDevices(userPublicKey string, includeRevoked bool) ([]*Device, error) {
	return nil, nil
}
func (r *getChallengeTestRepo) RevokeDevice(devicePublicKey string, ts int64) error   { return nil }
func (r *getChallengeTestRepo) RenameDevice(devicePublicKey, deviceName string) error { return nil }
func (r *getChallengeTestRepo) TouchDeviceLastSeen(devicePublicKey string, ts int64) error {
	return nil
}
func (r *getChallengeTestRepo) SetPasswordCredentials(publicKey, passwordVerifier, handle, accountKeyBlob, userState, ownKey string) error {
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
func (r *getChallengeTestRepo) UpdateUserState(publicKey, userState string) error { return nil }
func (r *getChallengeTestRepo) ClearEscrow(publicKey, ownKey string) error        { return nil }
func (r *getChallengeTestRepo) ClaimOwner(publicKey, username, passwordVerifier, handle, accountKeyBlob, userState, devicePublicKey string, deviceName *string, createdAt int64) error {
	return nil
}
func (r *getChallengeTestRepo) HasClaim() (bool, error) { return false, nil }
func (r *getChallengeTestRepo) RegisterUser(publicKey, username, passwordVerifier, handle, accountKeyBlob, userState, devicePublicKey string, deviceName *string, createdAt int64) error {
	return nil
}
func (r *getChallengeTestRepo) CountUsers() (int, error) { return 0, nil }

func newGetChallengeTestEndpoints(repo UserRepository) *UserEndpoints {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return NewEndpoints(repo, Config{ChallengeTTLSec: 300}, priv, pub, nil, nil)
}

func newChallengeRequestCtx(publicKey string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/users/challenge?publicKey=" + url.QueryEscape(publicKey))
	return ctx
}

func TestGetChallenge_ShouldReturnAndStoreChallengeForWellFormedKey(t *testing.T) {
	// given
	_, key := newTestKey(t)
	ep := newGetChallengeTestEndpoints(&getChallengeTestRepo{})
	ctx := newChallengeRequestCtx(key)

	// when
	ep.GetChallenge(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	var resp ChallengeResponse
	assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	assert.NotEmpty(t, resp.Challenge)
	assert.NotZero(t, resp.ExpiresAt)
	assert.NotEmpty(t, resp.SpacePublicKey)

	assert.NoError(t, ep.challenges.consume(resp.Challenge, key))
}

func TestGetChallenge_ShouldReturn400ForMalformedKeyWithoutStoringChallenge(t *testing.T) {
	// given
	ep := newGetChallengeTestEndpoints(&getChallengeTestRepo{})
	ctx := newChallengeRequestCtx("does-not-exist")

	// when
	ep.GetChallenge(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	assert.Empty(t, ep.challenges.data)
}

func (r *getChallengeTestRepo) ReviveDevice(_, _ string, _ int64) (bool, error) {
	return false, nil
}
