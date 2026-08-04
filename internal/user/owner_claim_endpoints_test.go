package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/keys"
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

// ClaimOwner mirrors user_repository.go's ClaimOwner: the users row and
// device row are written unconditionally (no WHERE-NOT-EXISTS guard), and
// the claim-row check - the real authoritative guard - is what wins for an
// already-claimed space, checked before the username-collision guard,
// exactly like the real transaction's own ordering of concerns.
func (r *ownerClaimTestRepo) ClaimOwner(publicKey, username, passwordVerifier, handle, accountKeyBlob, userState string, deviceName *string, createdAt int64) error {
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
	r.accounts[publicKey] = &User{PublicKey: publicKey, Username: username, Role: RoleOwner, Issuer: publicKey, CreatedAt: createdAt}
	r.verifiers[publicKey] = passwordVerifier
	r.handles[publicKey] = handle
	r.escrow[publicKey] = struct{ accountKeyBlob, userState string }{accountKeyBlob, userState}
	// Device #1's key equals the account key, same convention as the real
	// ClaimOwner's second INSERT.
	r.devices[publicKey] = &Device{DevicePublicKey: publicKey, UserPublicKey: publicKey, DeviceName: deviceName, CreatedAt: createdAt}
	r.claimed = true
	return nil
}

func (r *ownerClaimTestRepo) HasClaim() (bool, error) { return r.claimed, nil }

// validClaimRequest builds a well-formed claimOwnerRequest that passes every
// validation step and successfully claims as username, proving knowledge of
// masterPassword via a genuine Argon2id proof. A caller wanting to exercise a
// WRONG proof passes a different masterPassword here than what the
// OwnerClaimEndpoints instance under test was constructed with.
func validClaimRequest(t *testing.T, masterPassword, username string) claimOwnerRequest {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	salt := make([]byte, keys.SaltSize)
	_, err = rand.Read(salt)
	assert.NoError(t, err)
	proof := keys.DeriveKey(masterPassword, salt)
	secretBytes := make([]byte, 32)
	_, err = rand.Read(secretBytes)
	assert.NoError(t, err)
	return claimOwnerRequest{
		Username:            username,
		PublicKey:           base64.StdEncoding.EncodeToString(pub),
		MasterPasswordSalt:  base64.StdEncoding.EncodeToString(salt),
		MasterPasswordProof: base64.StdEncoding.EncodeToString(proof),
		AuthSecret:          base64.StdEncoding.EncodeToString(secretBytes),
	}
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
	masterPassword := "space-master-password"
	verifierKey := []byte("verifier-key")
	repo := newOwnerClaimTestRepo()
	oe := NewOwnerClaimEndpoints(repo, verifierKey, masterPassword, nil)
	req := validClaimRequest(t, masterPassword, "Alice")
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
	masterPassword := "space-master-password"
	repo := newOwnerClaimTestRepo()
	oe := NewOwnerClaimEndpoints(repo, []byte("verifier-key"), masterPassword, nil)
	firstReq := validClaimRequest(t, masterPassword, "alice")
	firstCtx := newClaimRequestCtx(t, firstReq)
	oe.Claim(firstCtx)
	assert.Equal(t, fasthttp.StatusCreated, firstCtx.Response.StatusCode())

	firstAccountBefore := *repo.accounts[firstReq.PublicKey]
	firstVerifierBefore := repo.verifiers[firstReq.PublicKey]
	firstHandleBefore := repo.handles[firstReq.PublicKey]

	// when - a second, different claimant tries to claim the same space
	secondReq := validClaimRequest(t, masterPassword, "bob")
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

func TestClaim_ShouldReturn401ForWrongMasterPasswordProof(t *testing.T) {
	// given
	repo := newOwnerClaimTestRepo()
	oe := NewOwnerClaimEndpoints(repo, []byte("verifier-key"), "correct-master-password", nil)
	req := validClaimRequest(t, "wrong-master-password", "alice")
	ctx := newClaimRequestCtx(t, req)

	// when
	oe.Claim(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}

func TestClaim_ShouldReturn400ForMasterPasswordSaltOfWrongLength(t *testing.T) {
	// given
	masterPassword := "space-master-password"
	repo := newOwnerClaimTestRepo()
	oe := NewOwnerClaimEndpoints(repo, []byte("verifier-key"), masterPassword, nil)
	req := validClaimRequest(t, masterPassword, "alice")
	req.MasterPasswordSalt = base64.StdEncoding.EncodeToString(make([]byte, 16)) // not keys.SaltSize (32)
	ctx := newClaimRequestCtx(t, req)

	// when
	oe.Claim(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

// TestClaim_ShouldReturn400ForNonBase64MasterPasswordProof documents the
// implementation's actual behavior for a malformed (not valid base64) proof:
// it fails to decode and is rejected as a 400, distinct from a
// correctly-encoded-but-wrong proof, which is a 401 (see
// TestClaim_ShouldReturn401ForWrongMasterPasswordProof above).
func TestClaim_ShouldReturn400ForNonBase64MasterPasswordProof(t *testing.T) {
	// given
	masterPassword := "space-master-password"
	repo := newOwnerClaimTestRepo()
	oe := NewOwnerClaimEndpoints(repo, []byte("verifier-key"), masterPassword, nil)
	req := validClaimRequest(t, masterPassword, "alice")
	req.MasterPasswordProof = "not-valid-base64!!"
	ctx := newClaimRequestCtx(t, req)

	// when
	oe.Claim(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestClaim_ShouldReturn400ForMissingAuthSecret(t *testing.T) {
	// given
	masterPassword := "space-master-password"
	repo := newOwnerClaimTestRepo()
	oe := NewOwnerClaimEndpoints(repo, []byte("verifier-key"), masterPassword, nil)
	req := validClaimRequest(t, masterPassword, "alice")
	req.AuthSecret = ""
	ctx := newClaimRequestCtx(t, req)

	// when
	oe.Claim(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestClaim_ShouldReturn400ForPublicKeyOfWrongLength(t *testing.T) {
	// given
	masterPassword := "space-master-password"
	repo := newOwnerClaimTestRepo()
	oe := NewOwnerClaimEndpoints(repo, []byte("verifier-key"), masterPassword, nil)
	req := validClaimRequest(t, masterPassword, "alice")
	req.PublicKey = base64.StdEncoding.EncodeToString(make([]byte, 16)) // not ed25519.PublicKeySize (32)
	ctx := newClaimRequestCtx(t, req)

	// when
	oe.Claim(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

// TestClaim_ShouldReturn409NotUnauthorizedWhenSpaceAlreadyClaimed_EvenWithBogusProof
// pins the memory-exhaustion mitigation described in Claim's doc comment:
// HasClaim() must reject an already-claimed space at cheap DB-lookup cost
// BEFORE the handler ever pays for Argon2id (keys.DeriveKey). A request
// carrying a proof that does NOT match the master password must still come
// back 409 (not 401) once a space is claimed - if HasClaim() ran after the
// KDF instead of before it, this same request would produce a 401, handing
// an attacker a free way to force expensive Argon2id work against a space
// that has nothing left to claim.
func TestClaim_ShouldReturn409NotUnauthorizedWhenSpaceAlreadyClaimed_EvenWithBogusProof(t *testing.T) {
	// given - the space is already claimed (seeded directly, no need to go
	// through Claim to get there)
	masterPassword := "space-master-password"
	repo := newOwnerClaimTestRepo()
	repo.claimed = true
	oe := NewOwnerClaimEndpoints(repo, []byte("verifier-key"), masterPassword, nil)
	// deliberately wrong master password: if HasClaim() did NOT short-circuit
	// before the proof check, this would produce 401, not 409.
	req := validClaimRequest(t, "totally-wrong-password", "someone-else")
	ctx := newClaimRequestCtx(t, req)

	// when
	oe.Claim(ctx)

	// then
	assert.Equal(t, fasthttp.StatusConflict, ctx.Response.StatusCode())
}

// TestClaim_ShouldReturn409WhenUsernameAlreadyUsedForPasswordLogin covers the
// repo's OTHER rejection: even on an unclaimed space, a username already held
// by a different password-enabled (but non-owner) account collides with
// ClaimOwner's partial-unique-index write, exactly as
// TestSetPassword_ShouldReturn409WhenUsernameAlreadyTakenForPasswordLogin
// covers for SetPasswordCredentials.
func TestClaim_ShouldReturn409WhenUsernameAlreadyUsedForPasswordLogin(t *testing.T) {
	// given
	masterPassword := "space-master-password"
	repo := newOwnerClaimTestRepo()
	repo.accounts["existing-account"] = &User{PublicKey: "existing-account", Username: "alice", Role: RoleUser}
	repo.verifiers["existing-account"] = "hmac-sha256$AAAA"
	oe := NewOwnerClaimEndpoints(repo, []byte("verifier-key"), masterPassword, nil)
	req := validClaimRequest(t, masterPassword, "alice")
	ctx := newClaimRequestCtx(t, req)

	// when
	oe.Claim(ctx)

	// then
	assert.Equal(t, fasthttp.StatusConflict, ctx.Response.StatusCode())
}
