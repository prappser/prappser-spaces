package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// ownerClaimTestRepo is a UserRepository stub for the owner-claim endpoint
// tests. claimed mirrors the real space_owner_claim table's single row
// (see migration 000024) - HasClaim reports whether it is set, and
// ClaimOwner enforces the same two guards the real transaction does, in the
// same order (existing claim first, THEN a username collision against any
// OTHER password-enabled account) - see user_repository.go's ClaimOwner for
// the SQL this mirrors.
type ownerClaimTestRepo struct {
	accounts  map[string]*User                                      // keyed by public key
	verifiers map[string]string                                     // keyed by public key
	handles   map[string]string                                     // keyed by public key
	escrow    map[string]struct{ accountKeyBlob, userState string } // keyed by public key
	devices   map[string]*Device                                    // keyed by device public key
	claimed   bool
}

func newOwnerClaimTestRepo() *ownerClaimTestRepo {
	return &ownerClaimTestRepo{
		accounts:  map[string]*User{},
		verifiers: map[string]string{},
		handles:   map[string]string{},
		escrow:    map[string]struct{ accountKeyBlob, userState string }{},
		devices:   map[string]*Device{},
	}
}

func (r *ownerClaimTestRepo) CreateUser(u *User) error {
	r.accounts[u.PublicKey] = u
	return nil
}
func (r *ownerClaimTestRepo) GetUserByPublicKey(publicKey string) (*User, error) {
	return r.accounts[publicKey], nil
}
func (r *ownerClaimTestRepo) UpdateUserRole(publicKey, role string) error { return nil }
func (r *ownerClaimTestRepo) UpdateAvatarStorageID(publicKey string, avatarStorageID *string) error {
	return nil
}
func (r *ownerClaimTestRepo) UpdateUsername(publicKey, username string) error { return nil }
func (r *ownerClaimTestRepo) UpdateUserIssuer(publicKey, issuer string) error { return nil }
func (r *ownerClaimTestRepo) SetUserIssuer(publicKey, issuer string) error    { return nil }
func (r *ownerClaimTestRepo) EnsureDevice(devicePublicKey, userPublicKey string, deviceName *string, createdAt int64) error {
	return nil
}
func (r *ownerClaimTestRepo) GetDevice(devicePublicKey string) (*Device, error) {
	return r.devices[devicePublicKey], nil
}
func (r *ownerClaimTestRepo) ListDevices(userPublicKey string) ([]*Device, error) { return nil, nil }
func (r *ownerClaimTestRepo) RevokeDevice(devicePublicKey string, ts int64) error { return nil }
func (r *ownerClaimTestRepo) RenameDevice(devicePublicKey, deviceName string) error {
	return nil
}
func (r *ownerClaimTestRepo) TouchDeviceLastSeen(devicePublicKey string, ts int64) error { return nil }

func (r *ownerClaimTestRepo) SetPasswordCredentials(publicKey, passwordVerifier, handle, accountKeyBlob, userState string) error {
	r.verifiers[publicKey] = passwordVerifier
	if _, exists := r.handles[publicKey]; !exists {
		r.handles[publicKey] = handle
	}
	r.escrow[publicKey] = struct{ accountKeyBlob, userState string }{accountKeyBlob, userState}
	return nil
}
func (r *ownerClaimTestRepo) GetPasswordCredential(username string) (string, string, error) {
	for pk, account := range r.accounts {
		if r.verifiers[pk] != "" && strings.EqualFold(account.Username, username) {
			return pk, r.verifiers[pk], nil
		}
	}
	return "", "", nil
}
func (r *ownerClaimTestRepo) GetPasswordHandle(username string) (string, error) {
	for pk, account := range r.accounts {
		if r.verifiers[pk] != "" && strings.EqualFold(account.Username, username) {
			return r.handles[pk], nil
		}
	}
	return "", nil
}
func (r *ownerClaimTestRepo) GetEscrow(publicKey string) (string, string, error) {
	escrow := r.escrow[publicKey]
	return escrow.accountKeyBlob, escrow.userState, nil
}
func (r *ownerClaimTestRepo) UpdateUserState(publicKey, userState string) error {
	escrow := r.escrow[publicKey]
	escrow.userState = userState
	r.escrow[publicKey] = escrow
	return nil
}
func (r *ownerClaimTestRepo) ClearEscrow(publicKey string) error {
	delete(r.escrow, publicKey)
	delete(r.verifiers, publicKey)
	return nil
}

// ClaimOwner mirrors user_repository.go's ClaimOwner: the users row and
// device row are written unconditionally (no WHERE-NOT-EXISTS guard), and
// the claim-row check - the real authoritative guard - is what wins for an
// already-claimed space, checked before the username-collision guard, which
// in turn is checked before the device-key-collision guard, exactly like the
// real transaction's own ordering of concerns (users INSERT, then
// user_devices INSERT, then space_owner_claim INSERT).
func (r *ownerClaimTestRepo) ClaimOwner(publicKey, username, passwordVerifier, handle, accountKeyBlob, userState, devicePublicKey string, deviceName *string, createdAt int64) error {
	if r.claimed {
		return ErrSpaceAlreadyClaimed
	}
	for pk, account := range r.accounts {
		if pk == publicKey {
			continue
		}
		if r.verifiers[pk] != "" && strings.EqualFold(account.Username, username) {
			return ErrUsernameTaken
		}
	}
	if _, exists := r.devices[devicePublicKey]; exists {
		return ErrDeviceKeyTaken
	}
	r.accounts[publicKey] = &User{PublicKey: publicKey, Username: username, Role: RoleOwner, Issuer: publicKey, CreatedAt: createdAt}
	r.verifiers[publicKey] = passwordVerifier
	r.handles[publicKey] = handle
	r.escrow[publicKey] = struct{ accountKeyBlob, userState string }{accountKeyBlob, userState}
	// devicePublicKey defaults to the account key when the caller doesn't
	// send one - same convention as the real ClaimOwner's second INSERT.
	r.devices[devicePublicKey] = &Device{DevicePublicKey: devicePublicKey, UserPublicKey: publicKey, DeviceName: deviceName, CreatedAt: createdAt}
	r.claimed = true
	return nil
}

func (r *ownerClaimTestRepo) HasClaim() (bool, error) { return r.claimed, nil }

// validClaimRequest builds a well-formed claimOwnerRequest that passes every
// validation step and successfully claims as username.
func validClaimRequest(t *testing.T, username string) claimOwnerRequest {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	secretBytes := make([]byte, 32)
	_, err = rand.Read(secretBytes)
	assert.NoError(t, err)
	return claimOwnerRequest{
		Username:   username,
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		AuthSecret: base64.StdEncoding.EncodeToString(secretBytes),
	}
}

// newOpenWindowEndpoints builds endpoints whose claim window is open.
func newOpenWindowEndpoints(repo UserRepository) *OwnerClaimEndpoints {
	return NewOwnerClaimEndpoints(repo, []byte("verifier-key"), time.Now(), nil)
}

// newClosedWindowEndpoints builds endpoints whose claim window has expired.
func newClosedWindowEndpoints(repo UserRepository) *OwnerClaimEndpoints {
	return NewOwnerClaimEndpoints(repo, []byte("verifier-key"), time.Now().Add(-ownerClaimWindow-time.Minute), nil)
}

func newClaimRequestCtx(t *testing.T, body claimOwnerRequest) *fasthttp.RequestCtx {
	t.Helper()
	b, err := json.Marshal(body)
	assert.NoError(t, err)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.SetBody(b)
	return ctx
}

// TestClaim_ShouldReturn201AndPersistFullOwnerRecordOnEmptySpace covers the
// happy path end to end: every field the repo receives must match the
// request - role, self-pinned issuer, device #1 keyed by the account key,
// the HMAC password verifier, the lowercased handle, and both escrow blobs.
func TestClaim_ShouldReturn201AndPersistFullOwnerRecordOnEmptySpace(t *testing.T) {
	// given
	verifierKey := []byte("verifier-key")
	repo := newOwnerClaimTestRepo()
	oe := NewOwnerClaimEndpoints(repo, verifierKey, time.Now(), nil)
	req := validClaimRequest(t, "Alice")
	accountKeyBlob := base64.StdEncoding.EncodeToString([]byte("sealed-account-key"))
	userState := base64.StdEncoding.EncodeToString([]byte("sealed-user-state"))
	req.AccountKeyBlob = accountKeyBlob
	req.UserState = userState
	ctx := newClaimRequestCtx(t, req)

	// when
	oe.Claim(ctx)

	// then - response
	assert.Equal(t, fasthttp.StatusCreated, ctx.Response.StatusCode())
	var resp claimOwnerResponse
	assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	assert.Equal(t, req.PublicKey, resp.UserPublicKey)
	assert.Equal(t, "Alice", resp.Username)
	assert.Equal(t, RoleOwner, resp.Role)

	// then - everything the repo received
	account, ok := repo.accounts[req.PublicKey]
	assert.True(t, ok)
	assert.Equal(t, RoleOwner, account.Role)
	assert.Equal(t, req.PublicKey, account.Issuer, "issuer must be self-pinned to the new owner's own public key")
	assert.Equal(t, "Alice", account.Username)

	device, ok := repo.devices[req.PublicKey]
	assert.True(t, ok)
	assert.Equal(t, req.PublicKey, device.DevicePublicKey, "device #1's key must equal the account key")
	assert.Equal(t, req.PublicKey, device.UserPublicKey)

	assert.True(t, verifyAuthSecret(verifierKey, repo.verifiers[req.PublicKey], req.AuthSecret))
	assert.Equal(t, strings.ToLower("Alice"), repo.handles[req.PublicKey])
	gotAccountKeyBlob, gotUserState := repo.escrow[req.PublicKey].accountKeyBlob, repo.escrow[req.PublicKey].userState
	assert.Equal(t, accountKeyBlob, gotAccountKeyBlob)
	assert.Equal(t, userState, gotUserState)
}

// TestClaim_ShouldReturn409OnSecondClaimAndLeaveFirstOwnerUnchanged covers
// the one-shot contract: a second claim against an already-claimed space is
// rejected, and the first owner's stored record is untouched by the attempt.
func TestClaim_ShouldReturn409OnSecondClaimAndLeaveFirstOwnerUnchanged(t *testing.T) {
	// given
	repo := newOwnerClaimTestRepo()
	oe := newOpenWindowEndpoints(repo)
	firstReq := validClaimRequest(t, "alice")
	firstCtx := newClaimRequestCtx(t, firstReq)
	oe.Claim(firstCtx)
	assert.Equal(t, fasthttp.StatusCreated, firstCtx.Response.StatusCode())

	firstAccountBefore := *repo.accounts[firstReq.PublicKey]
	firstVerifierBefore := repo.verifiers[firstReq.PublicKey]
	firstHandleBefore := repo.handles[firstReq.PublicKey]

	// when - a second, different claimant tries to claim the same space
	secondReq := validClaimRequest(t, "bob")
	secondCtx := newClaimRequestCtx(t, secondReq)
	oe.Claim(secondCtx)

	// then
	assert.Equal(t, fasthttp.StatusConflict, secondCtx.Response.StatusCode())
	assert.Equal(t, firstAccountBefore, *repo.accounts[firstReq.PublicKey])
	assert.Equal(t, firstVerifierBefore, repo.verifiers[firstReq.PublicKey])
	assert.Equal(t, firstHandleBefore, repo.handles[firstReq.PublicKey])
	_, secondAccountCreated := repo.accounts[secondReq.PublicKey]
	assert.False(t, secondAccountCreated)
}

// TestClaim_ShouldReturn409AndLeaveSpaceUnclaimedWhenDevicePublicKeyAlreadyRegistered
// is the regression guard for the ClaimOwner device-key collision: since
// devicePublicKey is client-controlled and globally unique, a claimant who
// reuses a devicePublicKey already registered on this space must be rejected
// outright, not silently no-op the device row and still claim the space -
// that would leave the "owner" with zero device rows, unable to ever
// authenticate, and the space permanently unclaimable.
func TestClaim_ShouldReturn409AndLeaveSpaceUnclaimedWhenDevicePublicKeyAlreadyRegistered(t *testing.T) {
	// given - a device key already registered on this space (e.g. via a
	// prior EnsureDevice call), but the space itself is not yet claimed
	repo := newOwnerClaimTestRepo()
	existingDevicePub, _, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	existingDeviceKey := base64.StdEncoding.EncodeToString(existingDevicePub)
	repo.devices[existingDeviceKey] = &Device{DevicePublicKey: existingDeviceKey, UserPublicKey: "someone-else"}
	oe := newOpenWindowEndpoints(repo)
	req := validClaimRequest(t, "alice")
	req.DevicePublicKey = existingDeviceKey
	ctx := newClaimRequestCtx(t, req)

	// when
	oe.Claim(ctx)

	// then
	assert.Equal(t, fasthttp.StatusConflict, ctx.Response.StatusCode())
	_, accountCreated := repo.accounts[req.PublicKey]
	assert.False(t, accountCreated, "a rejected claim must not leave a stray account behind")
	claimed, err := repo.HasClaim()
	assert.NoError(t, err)
	assert.False(t, claimed, "the space must remain unclaimed after a rejected claim")
}

// TestClaim_ShouldSucceedWithoutAuthSecretAndReportNoPasswordViaGetProfile is
// the regression guard for the NULLIF fix in ClaimOwner: without it, an
// empty-string verifier would satisfy GetPasswordCredential's
// "verifier != ''" check and every passwordless claim would report a
// phantom password.
func TestClaim_ShouldSucceedWithoutAuthSecretAndReportNoPasswordViaGetProfile(t *testing.T) {
	// given
	repo := newOwnerClaimTestRepo()
	oe := newOpenWindowEndpoints(repo)
	req := validClaimRequest(t, "alice")
	req.AuthSecret = ""
	ctx := newClaimRequestCtx(t, req)

	// when
	oe.Claim(ctx)

	// then - claim succeeds, and the stored verifier is empty (SQL NULL in
	// the real repository), not the placeholder that would report a phantom
	// password
	assert.Equal(t, fasthttp.StatusCreated, ctx.Response.StatusCode())
	assert.Empty(t, repo.verifiers[req.PublicKey])

	ue := UserEndpoints{userRepository: repo}
	profileCtx := &fasthttp.RequestCtx{}
	profileCtx.SetUserValue("user", &User{PublicKey: req.PublicKey, DevicePublicKey: req.PublicKey, Username: "alice"})
	ue.GetProfile(profileCtx)
	var profile User
	assert.NoError(t, json.Unmarshal(profileCtx.Response.Body(), &profile))
	assert.False(t, profile.HasPassword)
}

func TestClaim_ShouldReturn400ForPublicKeyOfWrongLength(t *testing.T) {
	// given
	repo := newOwnerClaimTestRepo()
	oe := newOpenWindowEndpoints(repo)
	req := validClaimRequest(t, "alice")
	req.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 16)) // not ed25519.PublicKeySize (32)
	ctx := newClaimRequestCtx(t, req)

	// when
	oe.Claim(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

// TestClaim_ShouldReturn409WhenUsernameAlreadyUsedForPasswordLogin covers the
// repo's OTHER rejection: even on an unclaimed space, a username already held
// by a different password-enabled (but non-owner) account collides with
// ClaimOwner's partial-unique-index write, exactly as
// TestSetPassword_ShouldReturn409WhenUsernameAlreadyTakenForPasswordLogin
// covers for SetPasswordCredentials.
func TestClaim_ShouldReturn409WhenUsernameAlreadyUsedForPasswordLogin(t *testing.T) {
	// given
	repo := newOwnerClaimTestRepo()
	repo.accounts["existing-account"] = &User{PublicKey: "existing-account", Username: "alice", Role: RoleUser}
	repo.verifiers["existing-account"] = "hmac-sha256$AAAA"
	oe := newOpenWindowEndpoints(repo)
	req := validClaimRequest(t, "alice")
	ctx := newClaimRequestCtx(t, req)

	// when
	oe.Claim(ctx)

	// then
	assert.Equal(t, fasthttp.StatusConflict, ctx.Response.StatusCode())
}

func TestClaim_ShouldReturn201WhenWindowIsOpen(t *testing.T) {
	// given
	repo := newOwnerClaimTestRepo()
	oe := newOpenWindowEndpoints(repo)
	ctx := newClaimRequestCtx(t, validClaimRequest(t, "alice"))

	// when
	oe.Claim(ctx)

	// then
	assert.Equal(t, fasthttp.StatusCreated, ctx.Response.StatusCode())
}

func TestClaim_ShouldReturn403AndWriteNothingWhenWindowIsClosed(t *testing.T) {
	// given
	repo := newOwnerClaimTestRepo()
	oe := newClosedWindowEndpoints(repo)
	ctx := newClaimRequestCtx(t, validClaimRequest(t, "alice"))

	// when
	oe.Claim(ctx)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	assert.False(t, repo.claimed)
	assert.Empty(t, repo.accounts)
}

func TestClaim_ShouldReturn409WhenSpaceClaimedAndWindowIsClosed(t *testing.T) {
	// given
	repo := newOwnerClaimTestRepo()
	repo.claimed = true
	oe := newClosedWindowEndpoints(repo)
	ctx := newClaimRequestCtx(t, validClaimRequest(t, "alice"))

	// when
	oe.Claim(ctx)

	// then
	assert.Equal(t, fasthttp.StatusConflict, ctx.Response.StatusCode())
}

func TestClaim_ShouldIgnoreLegacyMasterPasswordKeysInBody(t *testing.T) {
	// given
	repo := newOwnerClaimTestRepo()
	oe := newOpenWindowEndpoints(repo)
	req := validClaimRequest(t, "alice")
	body, err := json.Marshal(map[string]string{
		"username":            req.Username,
		"publicKey":           req.PublicKey,
		"authSecret":          req.AuthSecret,
		"masterPasswordSalt":  "ignored",
		"masterPasswordProof": "ignored",
	})
	assert.NoError(t, err)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.SetBody(body)

	// when
	oe.Claim(ctx)

	// then
	assert.Equal(t, fasthttp.StatusCreated, ctx.Response.StatusCode())
}
