package invitation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lib/pq"
	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
)

// fakeInvitationRepo minimally satisfies InvitationRepository for the tests
// below. Join tests drive Join down the already-a-member path (see
// newJoinTestService), so only GetByID is ever actually called there;
// CreateInvitation tests use Create and read back createdInvite.
type fakeInvitationRepo struct {
	invite        *Invitation
	createdInvite *Invitation
}

func (r *fakeInvitationRepo) Create(invite *Invitation) error {
	r.createdInvite = invite
	return nil
}
func (r *fakeInvitationRepo) GetByID(id string) (*Invitation, error) { return r.invite, nil }
func (r *fakeInvitationRepo) Delete(id string) error                 { return nil }
func (r *fakeInvitationRepo) IncrementUseCount(id string) error      { return nil }
func (r *fakeInvitationRepo) RecordUse(inviteID, userPublicKey, useID string) error {
	return nil
}
func (r *fakeInvitationRepo) GetByApplicationID(appID string) ([]*Invitation, error) {
	return nil, nil
}
func (r *fakeInvitationRepo) HasBeenUsedBy(inviteID, userPublicKey string) (bool, error) {
	return false, nil
}

// fakeUserRepo is a minimal user.UserRepository fake that records
// EnsureDevice/UpdateUserIssuer calls so tests can assert exactly which
// device key Join registers and how it re-pins issuer, and lets tests
// control whether the account already exists, its device roster, and
// whether CreateUser fails (to simulate the #111 create-race path).
type fakeUserRepo struct {
	existingUser *user.User
	devices      map[string]*user.Device
	// createUserErr, when set, is returned by CreateUser instead of
	// succeeding - used to simulate a concurrent create race (#111 G9).
	// raceWinner, if also set, is what a concurrent writer is presumed to
	// have already committed, and becomes visible via GetUserByPublicKey
	// from that point on (mirroring a real unique-violation: the row that
	// won the race is already there to be re-read).
	createUserErr     error
	raceWinner        *user.User
	ensureDeviceCalls []struct {
		devicePublicKey string
		userPublicKey   string
	}
	updateIssuerCalls []struct {
		publicKey string
		issuer    string
	}
}

func (r *fakeUserRepo) CreateUser(u *user.User) error {
	if r.createUserErr != nil {
		if r.raceWinner != nil {
			r.existingUser = r.raceWinner
		}
		return r.createUserErr
	}
	r.existingUser = u
	return nil
}
func (r *fakeUserRepo) GetUserByPublicKey(publicKey string) (*user.User, error) {
	return r.existingUser, nil
}
func (r *fakeUserRepo) UpdateUserRole(publicKey, role string) error { return nil }
func (r *fakeUserRepo) UpdateAvatarStorageID(publicKey string, avatarStorageID *string) error {
	return nil
}
func (r *fakeUserRepo) UpdateUsername(publicKey, username string) error { return nil }

// UpdateUserIssuer mirrors the real repository's SQL guard (WHERE issuer =
// public_key): it only actually moves issuer when the account is currently
// self-pinned.
func (r *fakeUserRepo) UpdateUserIssuer(publicKey, issuer string) error {
	r.updateIssuerCalls = append(r.updateIssuerCalls, struct {
		publicKey string
		issuer    string
	}{publicKey, issuer})
	if r.existingUser != nil && r.existingUser.PublicKey == publicKey && r.existingUser.Issuer == r.existingUser.PublicKey {
		r.existingUser.Issuer = issuer
	}
	return nil
}
func (r *fakeUserRepo) EnsureDevice(devicePublicKey, userPublicKey string, deviceName *string, createdAt int64) error {
	r.ensureDeviceCalls = append(r.ensureDeviceCalls, struct {
		devicePublicKey string
		userPublicKey   string
	}{devicePublicKey, userPublicKey})
	if r.devices == nil {
		r.devices = map[string]*user.Device{}
	}
	if _, exists := r.devices[devicePublicKey]; !exists {
		r.devices[devicePublicKey] = &user.Device{DevicePublicKey: devicePublicKey, UserPublicKey: userPublicKey, DeviceName: deviceName, CreatedAt: createdAt}
	}
	return nil
}
func (r *fakeUserRepo) GetDevice(devicePublicKey string) (*user.Device, error) {
	return r.devices[devicePublicKey], nil
}
func (r *fakeUserRepo) ListDevices(userPublicKey string) ([]*user.Device, error) {
	var out []*user.Device
	for _, d := range r.devices {
		if d.UserPublicKey == userPublicKey && d.RevokedAt == nil {
			out = append(out, d)
		}
	}
	return out, nil
}
func (r *fakeUserRepo) RevokeDevice(devicePublicKey string, ts int64) error        { return nil }
func (r *fakeUserRepo) RenameDevice(devicePublicKey, deviceName string) error      { return nil }
func (r *fakeUserRepo) TouchDeviceLastSeen(devicePublicKey string, ts int64) error { return nil }
func (r *fakeUserRepo) SetPasswordCredentials(publicKey, passwordVerifier, handle, accountKeyBlob, userState string) error {
	return nil
}
func (r *fakeUserRepo) GetPasswordCredential(username string) (string, string, error) {
	return "", "", nil
}
func (r *fakeUserRepo) GetPasswordHandle(username string) (string, error) {
	return "", nil
}
func (r *fakeUserRepo) GetEscrow(publicKey string) (string, string, error) {
	return "", "", nil
}
func (r *fakeUserRepo) UpdateUserState(publicKey, userState string) error { return nil }
func (r *fakeUserRepo) ClaimOwner(publicKey, username, passwordVerifier, handle, accountKeyBlob, userState string, deviceName *string, createdAt int64) error {
	return nil
}
func (r *fakeUserRepo) HasClaim() (bool, error) { return false, nil }

// buildAssertionJWS signs an identity-assertion JWT with signerPriv, matching
// the frozen wire format VerifyAssertion expects (iss, user_id, aud,
// username, dpk, iat, exp). An empty string arg omits that claim entirely,
// to exercise the required-claim checks.
func buildAssertionJWS(t *testing.T, signerPriv ed25519.PrivateKey, iss, userID, aud, username, dpk string, iat, exp int64) string {
	t.Helper()
	claims := jwt.MapClaims{"iat": iat, "exp": exp}
	if iss != "" {
		claims["iss"] = iss
	}
	if userID != "" {
		claims["user_id"] = userID
	}
	if aud != "" {
		claims["aud"] = aud
	}
	if username != "" {
		claims["username"] = username
	}
	if dpk != "" {
		claims["dpk"] = dpk
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(signerPriv)
	assert.NoError(t, err)
	return signed
}

// buildJoinProof signs a join-proof JWS with signerPriv - the enrolling
// device's own private key, matching the frozen wire format verifyJoinProof
// expects (publicKey, devicePublicKey, username, inviteId, iat). An empty
// string arg omits that claim entirely, to exercise the required-claim
// checks in join_proof_test.go. signerPriv must be the private half of
// whatever base64 key is passed as devicePublicKey - verifyJoinProof
// verifies the signature against that claim directly.
func buildJoinProof(t *testing.T, signerPriv ed25519.PrivateKey, publicKey, devicePublicKey, username, inviteID string, iat int64) string {
	t.Helper()
	claims := jwt.MapClaims{"iat": iat}
	if publicKey != "" {
		claims["publicKey"] = publicKey
	}
	if devicePublicKey != "" {
		claims["devicePublicKey"] = devicePublicKey
	}
	if username != "" {
		claims["username"] = username
	}
	if inviteID != "" {
		claims["inviteId"] = inviteID
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(signerPriv)
	assert.NoError(t, err)
	return signed
}

// fakeEventService is never invoked on the already-a-member Join path these
// tests take, but InvitationService's EventService field requires it.
type fakeEventService struct{}

func (fakeEventService) AcceptEvent(ctx context.Context, e *event.Event, submitter *user.User) (*event.Event, error) {
	return e, nil
}
func (fakeEventService) ProduceEvent(ctx context.Context, e *event.Event) (*event.Event, error) {
	return e, nil
}

// newJoinTestService wires a real application.MemoryRepository. Every test
// below seeds a Member row for the joining account so Join takes the
// already-a-member short-circuit and returns right after the
// device-registration/issuer-pinning steps under test, never touching s.db
// or the event service - which is why a nil *sql.DB is safe to pass here.
// The returned spacePublicKeyB64 is this (relying) space's own key - the
// audience an assertion built for these tests must carry.
func newJoinTestService(t *testing.T, invite *Invitation, userRepo *fakeUserRepo, memberPublicKey string) (svc *InvitationService, token string, spacePublicKeyB64 string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	spacePublicKeyB64 = base64.StdEncoding.EncodeToString(pub)

	appRepo := application.NewMemoryRepository()
	assert.NoError(t, appRepo.CreateApplication(&application.Application{ID: invite.ApplicationID, Name: "Test App"}))
	assert.NoError(t, appRepo.CreateMember(&application.Member{ID: "member-" + memberPublicKey, ApplicationID: invite.ApplicationID, PublicKey: memberPublicKey}))

	invRepo := &fakeInvitationRepo{invite: invite}
	svc = NewInvitationService(invRepo, priv, pub, appRepo, nil, userRepo, fakeEventService{}, spacePublicKeyB64)

	token, err = svc.GenerateToken(invite.ID, "https://space.example", nil)
	assert.NoError(t, err)

	return svc, token, spacePublicKeyB64
}

// generateDeviceKey is a small helper to cut boilerplate: every join-proof
// below needs a real, signable Ed25519 keypair for its devicePublicKey claim
// - verifyJoinProof always decodes and signature-verifies it, regardless of
// whether the scenario under test cares about the device key's value.
func generateDeviceKey(t *testing.T) (pub ed25519.PublicKey, priv ed25519.PrivateKey, b64 string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	return pub, priv, base64.StdEncoding.EncodeToString(pub)
}

func TestJoin_ExistingAccount_ForeignDevicePublicKey_RejectedAsUnproven(t *testing.T) {
	// given: an existing, self-registered account (victim) presented with a
	// device key that was never enrolled to this account and no assertion
	// vouching for it. The #110 PoP gate (G2) rejects this before any write
	// - flipped from the pre-#110 behaviour where an attacker's own device
	// key silently got attached to the victim's account.
	invite := &Invitation{ID: "invite-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix(), GrantsMembership: true}
	userRepo := &fakeUserRepo{existingUser: &user.User{PublicKey: "victim-pk", Username: "victim", Issuer: "victim-pk"}}
	svc, token, _ := newJoinTestService(t, invite, userRepo, "victim-pk")

	_, attackerDevicePriv, attackerDeviceB64 := generateDeviceKey(t)
	proof := buildJoinProof(t, attackerDevicePriv, "victim-pk", attackerDeviceB64, "victim", invite.ID, time.Now().Unix())

	// when: caller presents the victim's account key plus an attacker-controlled device key
	_, err := svc.Join(token, proof, "", "")

	// then: rejected outright - no device row is ever touched
	assert.ErrorIs(t, err, ErrAccountKeyNotProven)
	assert.Empty(t, userRepo.ensureDeviceCalls)
}

func TestJoin_NewAccount_ForeignDevicePublicKey_RejectedAsUnproven(t *testing.T) {
	// given: no existing account for this public key, and a device key that
	// differs from it with no assertion vouching (D5/G2) - proving
	// possession of an unrelated device key is not proof of possession of
	// the account key being claimed.
	invite := &Invitation{ID: "invite-2", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix(), GrantsMembership: true, GrantsIdentity: true}
	userRepo := &fakeUserRepo{}
	svc, token, _ := newJoinTestService(t, invite, userRepo, "new-pk")

	_, devicePriv, deviceB64 := generateDeviceKey(t)
	proof := buildJoinProof(t, devicePriv, "new-pk", deviceB64, "newuser", invite.ID, time.Now().Unix())

	// when
	_, err := svc.Join(token, proof, "", "")

	// then
	assert.ErrorIs(t, err, ErrAccountKeyNotProven)
	assert.Empty(t, userRepo.ensureDeviceCalls)
}

func TestJoin_NewAccount_DevicePublicKeyEqualsAccountKey_Succeeds(t *testing.T) {
	// given: a brand-new account whose join proof names its own key as the
	// device key too (device #1 == account key) - the only device key a
	// non-assertion new-account join can ever present under the #110 PoP
	// gate. The old "empty devicePublicKey defaults to publicKey" request
	// field is gone entirely - a join proof always carries an explicit
	// devicePublicKey claim.
	acctPub, acctPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	acctB64 := base64.StdEncoding.EncodeToString(acctPub)

	invite := &Invitation{ID: "invite-3", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix(), GrantsMembership: true, GrantsIdentity: true}
	userRepo := &fakeUserRepo{}
	svc, token, _ := newJoinTestService(t, invite, userRepo, acctB64)

	proof := buildJoinProof(t, acctPriv, acctB64, acctB64, "newuser2", invite.ID, time.Now().Unix())

	// when
	_, err = svc.Join(token, proof, "", "")

	// then: device #1 == the account's own key
	assert.NoError(t, err)
	assert.Len(t, userRepo.ensureDeviceCalls, 1)
	assert.Equal(t, acctB64, userRepo.ensureDeviceCalls[0].devicePublicKey)
	assert.Equal(t, acctB64, userRepo.ensureDeviceCalls[0].userPublicKey)
}

// TestJoin_NewAccount_WithDeviceName_StoresNormalizedName covers #127: a
// deviceName presented on Join is normalized (trimmed) and stored on the
// new-account device row.
func TestJoin_NewAccount_WithDeviceName_StoresNormalizedName(t *testing.T) {
	acctPub, acctPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	acctB64 := base64.StdEncoding.EncodeToString(acctPub)

	invite := &Invitation{ID: "invite-devname-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix(), GrantsMembership: true, GrantsIdentity: true}
	userRepo := &fakeUserRepo{}
	svc, token, _ := newJoinTestService(t, invite, userRepo, acctB64)

	proof := buildJoinProof(t, acctPriv, acctB64, acctB64, "newuser3", invite.ID, time.Now().Unix())

	// when
	_, err = svc.Join(token, proof, "", "  My Laptop  ")

	// then
	assert.NoError(t, err)
	if assert.NotNil(t, userRepo.devices[acctB64].DeviceName) {
		assert.Equal(t, "My Laptop", *userRepo.devices[acctB64].DeviceName)
	}
}

// TestJoin_NewAccount_WithoutDeviceName_StoresNilName covers #127's lenient
// side: an empty deviceName never fails the join, it just means no name.
func TestJoin_NewAccount_WithoutDeviceName_StoresNilName(t *testing.T) {
	acctPub, acctPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	acctB64 := base64.StdEncoding.EncodeToString(acctPub)

	invite := &Invitation{ID: "invite-devname-2", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix(), GrantsMembership: true, GrantsIdentity: true}
	userRepo := &fakeUserRepo{}
	svc, token, _ := newJoinTestService(t, invite, userRepo, acctB64)

	proof := buildJoinProof(t, acctPriv, acctB64, acctB64, "newuser4", invite.ID, time.Now().Unix())

	// when
	_, err = svc.Join(token, proof, "", "")

	// then
	assert.NoError(t, err)
	assert.Nil(t, userRepo.devices[acctB64].DeviceName)
}

// ---- #111: cross-space identity assertions on Join ----

func TestJoin_FirstContact_WithAssertion_CreatesUserWithIssuerAndEnrollsDevice(t *testing.T) {
	// given: no existing account, and a valid assertion from a vouching
	// space (issuer) naming this account and device.
	invite := &Invitation{ID: "invite-first-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix(), GrantsMembership: true}
	userRepo := &fakeUserRepo{}
	svc, token, spaceKeyB64 := newJoinTestService(t, invite, userRepo, "new-account-pk")

	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	issuerB64 := base64.StdEncoding.EncodeToString(issuerPub)
	_, devicePriv, deviceB64 := generateDeviceKey(t)
	now := time.Now().Unix()
	assertion := buildAssertionJWS(t, issuerPriv, issuerB64, "new-account-pk", spaceKeyB64, "newbie", deviceB64, now, now+120)
	proof := buildJoinProof(t, devicePriv, "new-account-pk", deviceB64, "newbie", invite.ID, now)

	// when
	_, err = svc.Join(token, proof, assertion, "")

	// then: the new account is pinned to the vouching space, and the
	// presented device is enrolled.
	assert.NoError(t, err)
	assert.Equal(t, issuerB64, userRepo.existingUser.Issuer)
	assert.Len(t, userRepo.ensureDeviceCalls, 1)
	assert.Equal(t, deviceB64, userRepo.ensureDeviceCalls[0].devicePublicKey)
	assert.Equal(t, "new-account-pk", userRepo.ensureDeviceCalls[0].userPublicKey)
}

func TestJoin_FirstContact_SelfSignedAssertion_PinsOwnKey(t *testing.T) {
	// given: a self-anchored account (#112 D9) - iss == user_id == the
	// account's own key, signed with its own private key, no anchor space
	// involved.
	invite := &Invitation{ID: "invite-self-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix(), GrantsMembership: true}
	accountPub, accountPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	accountB64 := base64.StdEncoding.EncodeToString(accountPub)

	userRepo := &fakeUserRepo{}
	svc, token, spaceKeyB64 := newJoinTestService(t, invite, userRepo, accountB64)

	now := time.Now().Unix()
	assertion := buildAssertionJWS(t, accountPriv, accountB64, accountB64, spaceKeyB64, "selfanchored", accountB64, now, now+120)
	proof := buildJoinProof(t, accountPriv, accountB64, accountB64, "selfanchored", invite.ID, now)

	// when
	_, err = svc.Join(token, proof, assertion, "")

	// then: issuer is pinned to the account's own key, indistinguishable
	// from a plain self-registration.
	assert.NoError(t, err)
	assert.Equal(t, accountB64, userRepo.existingUser.Issuer)
}

func TestJoin_WithAssertion_UserIDMismatch_Returns401(t *testing.T) {
	// given: the assertion vouches for a DIFFERENT account than the one
	// presented in the join proof.
	invite := &Invitation{ID: "invite-mismatch-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix(), GrantsMembership: true}
	userRepo := &fakeUserRepo{}
	svc, token, spaceKeyB64 := newJoinTestService(t, invite, userRepo, "victim-pk-2")

	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	issuerB64 := base64.StdEncoding.EncodeToString(issuerPub)
	_, devicePriv, deviceB64 := generateDeviceKey(t)
	now := time.Now().Unix()
	assertion := buildAssertionJWS(t, issuerPriv, issuerB64, "someone-else-pk", spaceKeyB64, "victim", deviceB64, now, now+120)
	proof := buildJoinProof(t, devicePriv, "victim-pk-2", deviceB64, "victim", invite.ID, now)

	// when
	_, err = svc.Join(token, proof, assertion, "")

	// then
	assert.ErrorIs(t, err, user.ErrInvalidAssertion)
}

func TestJoin_FirstContact_WithAssertion_DeviceOwnedByDifferentAccount_Returns409(t *testing.T) {
	// given: the presented device key is already registered to a DIFFERENT
	// account (#111 G6).
	_, devicePriv, deviceB64 := generateDeviceKey(t)
	invite := &Invitation{ID: "invite-conflict-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix(), GrantsMembership: true}
	userRepo := &fakeUserRepo{devices: map[string]*user.Device{
		deviceB64: {DevicePublicKey: deviceB64, UserPublicKey: "someone-else"},
	}}
	svc, token, spaceKeyB64 := newJoinTestService(t, invite, userRepo, "new-conflict-pk")

	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	issuerB64 := base64.StdEncoding.EncodeToString(issuerPub)
	now := time.Now().Unix()
	assertion := buildAssertionJWS(t, issuerPriv, issuerB64, "new-conflict-pk", spaceKeyB64, "newbie", deviceB64, now, now+120)
	proof := buildJoinProof(t, devicePriv, "new-conflict-pk", deviceB64, "newbie", invite.ID, now)

	// when
	_, err = svc.Join(token, proof, assertion, "")

	// then
	assert.ErrorIs(t, err, ErrDeviceConflict)
}

func TestJoin_FirstContact_WithAssertion_RevokedDevice_Returns409(t *testing.T) {
	// given: the presented device key belongs to THIS account already, but
	// has been revoked.
	_, devicePriv, deviceB64 := generateDeviceKey(t)
	revokedAt := time.Now().Unix()
	invite := &Invitation{ID: "invite-revoked-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix(), GrantsMembership: true}
	userRepo := &fakeUserRepo{devices: map[string]*user.Device{
		deviceB64: {DevicePublicKey: deviceB64, UserPublicKey: "new-revoked-pk", RevokedAt: &revokedAt},
	}}
	svc, token, spaceKeyB64 := newJoinTestService(t, invite, userRepo, "new-revoked-pk")

	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	issuerB64 := base64.StdEncoding.EncodeToString(issuerPub)
	now := time.Now().Unix()
	assertion := buildAssertionJWS(t, issuerPriv, issuerB64, "new-revoked-pk", spaceKeyB64, "newbie", deviceB64, now, now+120)
	proof := buildJoinProof(t, devicePriv, "new-revoked-pk", deviceB64, "newbie", invite.ID, now)

	// when
	_, err = svc.Join(token, proof, assertion, "")

	// then
	assert.ErrorIs(t, err, ErrDeviceConflict)
}

func TestJoin_FirstContact_WithAssertion_CreateRaceConverges(t *testing.T) {
	// given: CreateUser loses a concurrent create race (unique violation) -
	// the row that won is now visible on re-read (#111 G9).
	invite := &Invitation{ID: "invite-race-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix(), GrantsMembership: true}

	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	issuerB64 := base64.StdEncoding.EncodeToString(issuerPub)

	userRepo := &fakeUserRepo{
		createUserErr: &pq.Error{Code: pqUniqueViolation},
		raceWinner:    &user.User{PublicKey: "race-pk", Username: "racer", Issuer: issuerB64, Role: user.RoleGuest},
	}
	svc, token, spaceKeyB64 := newJoinTestService(t, invite, userRepo, "race-pk")

	_, devicePriv, deviceB64 := generateDeviceKey(t)
	now := time.Now().Unix()
	assertion := buildAssertionJWS(t, issuerPriv, issuerB64, "race-pk", spaceKeyB64, "racer", deviceB64, now, now+120)
	proof := buildJoinProof(t, devicePriv, "race-pk", deviceB64, "racer", invite.ID, now)

	// when
	result, err := svc.Join(token, proof, assertion, "")

	// then: the race is not surfaced as an error - Join converges on the row
	// that won
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestJoin_KnownAccount_WithAssertion_AddsNoDevice(t *testing.T) {
	// given: a known account already vouched by the SAME issuer presenting
	// the assertion (so neither re-pin nor warn fires) - isolating the
	// load-bearing claim that an assertion never adds a device to an
	// already-known account (D5).
	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	issuerB64 := base64.StdEncoding.EncodeToString(issuerPub)

	invite := &Invitation{ID: "invite-known-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix(), GrantsMembership: true}
	userRepo := &fakeUserRepo{existingUser: &user.User{PublicKey: "known-pk", Username: "known", Issuer: issuerB64}}
	svc, token, spaceKeyB64 := newJoinTestService(t, invite, userRepo, "known-pk")

	_, devicePriv, deviceB64 := generateDeviceKey(t)
	now := time.Now().Unix()
	assertion := buildAssertionJWS(t, issuerPriv, issuerB64, "known-pk", spaceKeyB64, "known", deviceB64, now, now+120)
	proof := buildJoinProof(t, devicePriv, "known-pk", deviceB64, "known", invite.ID, now)

	// when
	_, err = svc.Join(token, proof, assertion, "")

	// then
	assert.NoError(t, err)
	assert.Empty(t, userRepo.ensureDeviceCalls)
}

func TestJoin_KnownAccount_SelfPinned_WithAssertion_RepinsAndAddsNoDevice(t *testing.T) {
	// given: a self-pinned account presented with a valid assertion from a
	// DIFFERENT issuer - the one-way self->vouched re-pin (D5) should fire,
	// and no device should ever be added on this path.
	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	issuerB64 := base64.StdEncoding.EncodeToString(issuerPub)

	invite := &Invitation{ID: "invite-repin-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix(), GrantsMembership: true}
	userRepo := &fakeUserRepo{existingUser: &user.User{PublicKey: "self-pk", Username: "self", Issuer: "self-pk"}}
	svc, token, spaceKeyB64 := newJoinTestService(t, invite, userRepo, "self-pk")

	_, devicePriv, deviceB64 := generateDeviceKey(t)
	now := time.Now().Unix()
	assertion := buildAssertionJWS(t, issuerPriv, issuerB64, "self-pk", spaceKeyB64, "self", deviceB64, now, now+120)
	proof := buildJoinProof(t, devicePriv, "self-pk", deviceB64, "self", invite.ID, now)

	// when
	_, err = svc.Join(token, proof, assertion, "")

	// then
	assert.NoError(t, err)
	assert.Equal(t, issuerB64, userRepo.existingUser.Issuer)
	assert.Len(t, userRepo.updateIssuerCalls, 1)
	assert.Empty(t, userRepo.ensureDeviceCalls)
}

func TestJoin_KnownAccount_Vouched_DifferentIssuer_PinUnchangedJoinSucceeds(t *testing.T) {
	// given: an already-vouched account presented with an assertion from
	// yet ANOTHER issuer - the pin never moves once vouched, join still
	// succeeds.
	otherIssuerPub, otherIssuerPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	otherIssuerB64 := base64.StdEncoding.EncodeToString(otherIssuerPub)

	invite := &Invitation{ID: "invite-vouch-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix(), GrantsMembership: true}
	userRepo := &fakeUserRepo{existingUser: &user.User{PublicKey: "vouched-pk", Username: "vouched", Issuer: "original-issuer-key"}}
	svc, token, spaceKeyB64 := newJoinTestService(t, invite, userRepo, "vouched-pk")

	_, devicePriv, deviceB64 := generateDeviceKey(t)
	now := time.Now().Unix()
	assertion := buildAssertionJWS(t, otherIssuerPriv, otherIssuerB64, "vouched-pk", spaceKeyB64, "vouched", deviceB64, now, now+120)
	proof := buildJoinProof(t, devicePriv, "vouched-pk", deviceB64, "vouched", invite.ID, now)

	// when
	_, err = svc.Join(token, proof, assertion, "")

	// then
	assert.NoError(t, err)
	assert.Equal(t, "original-issuer-key", userRepo.existingUser.Issuer)
	assert.Empty(t, userRepo.updateIssuerCalls)
	assert.Empty(t, userRepo.ensureDeviceCalls)
}

func TestJoin_LegacyBackfill_VouchedAccountWithEmptyRoster_DoesNotBackfill(t *testing.T) {
	// given: a vouched (non-self-pinned) account with an empty device
	// roster, joining without an assertion at all (#111 G3) - the legacy
	// account-key backfill must never touch a vouched account, even though
	// it still applies to a self-registered one (see
	// TestJoin_ExistingAccount_ForeignDevicePublicKey_RejectedAsUnproven above).
	acctPub, acctPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	acctB64 := base64.StdEncoding.EncodeToString(acctPub)

	invite := &Invitation{ID: "invite-g3-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix(), GrantsMembership: true}
	userRepo := &fakeUserRepo{existingUser: &user.User{PublicKey: acctB64, Username: "vouched2", Issuer: "some-space-key"}}
	svc, token, _ := newJoinTestService(t, invite, userRepo, acctB64)

	// when - plain join, no assertion, device key equals account key (the
	// proof always carries an explicit devicePublicKey claim now, so this
	// is the closest equivalent to the old "empty devicePublicKey" input)
	proof := buildJoinProof(t, acctPriv, acctB64, acctB64, "vouched2", invite.ID, time.Now().Unix())
	_, err = svc.Join(token, proof, "", "")

	// then
	assert.NoError(t, err)
	assert.Empty(t, userRepo.ensureDeviceCalls)
}

// ---- #110: grants_identity / grants_membership gates on Join ----

func TestJoin_ShouldRejectNewAccountWhenIdentityNotGranted(t *testing.T) {
	// given: a brand-new account (no existing user) with no assertion,
	// joining an invite configured not to anchor new identities
	// (grants_identity=false, D6) - the gate must fire before any user or
	// device write.
	invite := &Invitation{ID: "invite-identity-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix(), GrantsMembership: true, GrantsIdentity: false}
	userRepo := &fakeUserRepo{}
	svc, token, _ := newJoinTestService(t, invite, userRepo, "new-noidentity-pk")

	_, devicePriv, deviceB64 := generateDeviceKey(t)
	proof := buildJoinProof(t, devicePriv, "new-noidentity-pk", deviceB64, "newbie", invite.ID, time.Now().Unix())

	// when: no assertion presented
	_, err := svc.Join(token, proof, "", "")

	// then: rejected before any user/device write
	assert.ErrorIs(t, err, ErrIdentityNotGranted)
	assert.Empty(t, userRepo.ensureDeviceCalls)
}

func TestJoin_ShouldAllowAssertionBackedAccountWhenIdentityNotGranted(t *testing.T) {
	// given: a brand-new account presented with a valid assertion, joining
	// the same grants_identity=false invite (D6) - an assertion-backed join
	// is not a bare identity mint, so the gate must not fire. Member row is
	// pre-seeded (via newJoinTestService) so Join takes the already-a-member
	// short-circuit right after device registration, same as the other
	// assertion tests above.
	invite := &Invitation{ID: "invite-identity-2", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix(), GrantsMembership: true, GrantsIdentity: false}
	userRepo := &fakeUserRepo{}
	svc, token, spaceKeyB64 := newJoinTestService(t, invite, userRepo, "new-identity-assert-pk")

	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	issuerB64 := base64.StdEncoding.EncodeToString(issuerPub)
	_, devicePriv, deviceB64 := generateDeviceKey(t)
	now := time.Now().Unix()
	assertion := buildAssertionJWS(t, issuerPriv, issuerB64, "new-identity-assert-pk", spaceKeyB64, "newbie", deviceB64, now, now+120)
	proof := buildJoinProof(t, devicePriv, "new-identity-assert-pk", deviceB64, "newbie", invite.ID, now)

	// when
	_, err = svc.Join(token, proof, assertion, "")

	// then: identity gate does not fire for an assertion-backed join
	assert.NoError(t, err)
}

func TestJoin_ShouldRejectWhenMembershipNotGranted(t *testing.T) {
	// given: a preview-only invite (grants_membership=false, D7) - Join must
	// reject before any user/device write, regardless of assertion state.
	invite := &Invitation{ID: "invite-membership-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix(), GrantsMembership: false}
	userRepo := &fakeUserRepo{}
	svc, token, _ := newJoinTestService(t, invite, userRepo, "preview-pk")

	_, devicePriv, deviceB64 := generateDeviceKey(t)
	proof := buildJoinProof(t, devicePriv, "preview-pk", deviceB64, "previewer", invite.ID, time.Now().Unix())

	// when
	_, err := svc.Join(token, proof, "", "")

	// then: rejected before any user/device write
	assert.ErrorIs(t, err, ErrMembershipNotGranted)
	assert.Empty(t, userRepo.ensureDeviceCalls)
}

// ---- #110: grants_membership / grants_identity gates on CreateInvitation ----

func TestCreateInvitation_ShouldDefaultToSingleUseWhenGrantsIdentity(t *testing.T) {
	// given
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	repo := &fakeInvitationRepo{}
	svc := NewInvitationService(repo, priv, pub, application.NewMemoryRepository(), nil, &fakeUserRepo{}, fakeEventService{}, "space-key")
	grantsIdentity := true

	// when
	_, err = svc.CreateInvitation(CreateInvitationOptions{
		ApplicationID:      "app-1",
		CreatedByPublicKey: "creator-pk",
		GrantsIdentity:     &grantsIdentity,
		SpaceURL:           "https://space.example",
	})

	// then: D9 - an identity-granting invite with no explicit maxUses
	// defaults to single-use.
	assert.NoError(t, err)
	assert.NotNil(t, repo.createdInvite.MaxUses)
	assert.Equal(t, 1, *repo.createdInvite.MaxUses)
}

func TestCreateInvitation_ShouldNotDefaultMaxUsesWhenIdentityNotGranted(t *testing.T) {
	// given
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	repo := &fakeInvitationRepo{}
	svc := NewInvitationService(repo, priv, pub, application.NewMemoryRepository(), nil, &fakeUserRepo{}, fakeEventService{}, "space-key")
	grantsIdentity := false

	// when
	_, err = svc.CreateInvitation(CreateInvitationOptions{
		ApplicationID:      "app-1",
		CreatedByPublicKey: "creator-pk",
		GrantsIdentity:     &grantsIdentity,
		SpaceURL:           "https://space.example",
	})

	// then: the D9 single-use default only applies to identity-granting invites
	assert.NoError(t, err)
	assert.Nil(t, repo.createdInvite.MaxUses)
}

func TestCreateInvitation_ShouldForceIdentityOffWhenMembershipOff(t *testing.T) {
	// given
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	repo := &fakeInvitationRepo{}
	svc := NewInvitationService(repo, priv, pub, application.NewMemoryRepository(), nil, &fakeUserRepo{}, fakeEventService{}, "space-key")
	grantsMembership := false

	// when
	_, err = svc.CreateInvitation(CreateInvitationOptions{
		ApplicationID:      "app-1",
		CreatedByPublicKey: "creator-pk",
		GrantsMembership:   &grantsMembership,
		SpaceURL:           "https://space.example",
	})

	// then: D8 - a preview-only invite can never mint identities, and
	// therefore never gets the D9 single-use default either.
	assert.NoError(t, err)
	assert.False(t, repo.createdInvite.GrantsMembership)
	assert.False(t, repo.createdInvite.GrantsIdentity)
	assert.Nil(t, repo.createdInvite.MaxUses)
}

// newAuthzTestService wires a real application.MemoryRepository seeded with
// one application and, if role != "", a single member of that role for
// memberPublicKey - the caller under test in the AuthorizeAppRole tests
// below (#125).
func newAuthzTestService(t *testing.T, appID, memberPublicKey string, role application.MemberRole) *InvitationService {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	appRepo := application.NewMemoryRepository()
	assert.NoError(t, appRepo.CreateApplication(&application.Application{ID: appID, Name: "Test App"}))
	if role != "" {
		assert.NoError(t, appRepo.CreateMember(&application.Member{ID: "member-" + memberPublicKey, ApplicationID: appID, PublicKey: memberPublicKey, Role: role}))
	}

	return NewInvitationService(&fakeInvitationRepo{}, priv, pub, appRepo, nil, &fakeUserRepo{}, fakeEventService{}, "space-key")
}

func TestAuthorizeAppRole_NonMember_Rejected(t *testing.T) {
	// given: caller has no member row at all in the application
	svc := newAuthzTestService(t, "app-1", "someone-else-pk", application.MemberRoleOwner)

	// when
	err := svc.AuthorizeAppRole("app-1", "non-member-pk", application.MemberRoleOwner)

	// then: #125 - a non-member is rejected, not silently allowed
	assert.ErrorIs(t, err, ErrNotAppAuthorized)
}

func TestAuthorizeAppRole_PlainMember_RejectedForOwnerOnlyCheck(t *testing.T) {
	// given: caller is a member, but only holds the "member" role
	svc := newAuthzTestService(t, "app-1", "member-pk", application.MemberRoleMember)

	// when
	err := svc.AuthorizeAppRole("app-1", "member-pk", application.MemberRoleOwner)

	// then: #125 - membership alone is not enough, the role must be allowed
	assert.ErrorIs(t, err, ErrNotAppAuthorized)
}

func TestAuthorizeAppRole_Owner_Allowed(t *testing.T) {
	// given: caller is the application owner
	svc := newAuthzTestService(t, "app-1", "owner-pk", application.MemberRoleOwner)

	// when
	err := svc.AuthorizeAppRole("app-1", "owner-pk", application.MemberRoleOwner)

	// then
	assert.NoError(t, err)
}

func TestAuthorizeAppRole_Admin_AllowedAmongMultipleRoles(t *testing.T) {
	// given: caller is an admin, checked against ListInvites' owner-or-admin set
	svc := newAuthzTestService(t, "app-1", "admin-pk", application.MemberRoleAdmin)

	// when
	err := svc.AuthorizeAppRole("app-1", "admin-pk", application.MemberRoleOwner, application.MemberRoleAdmin)

	// then
	assert.NoError(t, err)
}

func TestAuthorizeAppRole_PlainMember_RejectedForOwnerOrAdminCheck(t *testing.T) {
	// given: caller is a plain member, checked against ListInvites' owner-or-admin set
	svc := newAuthzTestService(t, "app-1", "member-pk", application.MemberRoleMember)

	// when
	err := svc.AuthorizeAppRole("app-1", "member-pk", application.MemberRoleOwner, application.MemberRoleAdmin)

	// then
	assert.ErrorIs(t, err, ErrNotAppAuthorized)
}

// capturingEventService records the last event passed to ProduceEvent, for
// TestRevokeInvitation_ProducesInviteRevokedEvent (#125) to assert on.
type capturingEventService struct {
	produced *event.Event
}

func (c *capturingEventService) AcceptEvent(ctx context.Context, e *event.Event, submitter *user.User) (*event.Event, error) {
	return e, nil
}
func (c *capturingEventService) ProduceEvent(ctx context.Context, e *event.Event) (*event.Event, error) {
	c.produced = e
	return e, nil
}

func TestRevokeInvitation_ProducesInviteRevokedEvent(t *testing.T) {
	// given
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	invite := &Invitation{ID: "invite-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix()}
	repo := &fakeInvitationRepo{invite: invite}
	events := &capturingEventService{}
	svc := NewInvitationService(repo, priv, pub, application.NewMemoryRepository(), nil, &fakeUserRepo{}, events, "space-key")

	// when
	err = svc.RevokeInvitation(invite, "owner-pk")

	// then: the invite_revoked event carries the revoking caller as creator
	// and the invite's applicationId/inviteId (#125)
	assert.NoError(t, err)
	assert.NotNil(t, events.produced)
	assert.Equal(t, event.EventTypeInviteRevoked, events.produced.Type)
	assert.Equal(t, "owner-pk", events.produced.CreatorPublicKey)
	assert.Equal(t, "app-1", events.produced.Data["applicationId"])
	assert.Equal(t, "invite-1", events.produced.Data["inviteId"])
}
