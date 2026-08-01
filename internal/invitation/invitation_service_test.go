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

// fakeInvitationRepo minimally satisfies InvitationRepository for Join
// tests below. Every test here drives Join down the already-a-member path
// (see newJoinTestService), so only GetByID is ever actually called.
type fakeInvitationRepo struct {
	invite *Invitation
}

func (r *fakeInvitationRepo) Create(invite *Invitation) error        { return nil }
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
func (r *fakeUserRepo) GetUserByUsername(username string) (*user.User, error) { return nil, nil }
func (r *fakeUserRepo) UpdateUserRole(publicKey, role string) error           { return nil }
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
		r.devices[devicePublicKey] = &user.Device{DevicePublicKey: devicePublicKey, UserPublicKey: userPublicKey, CreatedAt: createdAt}
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
func (r *fakeUserRepo) TouchDeviceLastSeen(devicePublicKey string, ts int64) error { return nil }
func (r *fakeUserRepo) SetPasswordCredentials(publicKey, identifier, passwordVerifier, accountKeyBlob, userState string) error {
	return nil
}
func (r *fakeUserRepo) GetPasswordCredential(identifier string) (string, string, error) {
	return "", "", nil
}
func (r *fakeUserRepo) GetEscrow(publicKey string) (string, string, error) {
	return "", "", nil
}

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

func TestJoin_ExistingAccount_ForeignDevicePublicKey_DoesNotCreateDeviceRowForIt(t *testing.T) {
	// given: an existing, self-registered account (victim) with an empty
	// device roster, already a member so Join short-circuits right after
	// the device-registration step under test.
	invite := &Invitation{ID: "invite-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix()}
	userRepo := &fakeUserRepo{existingUser: &user.User{PublicKey: "victim-pk", Username: "victim", Issuer: "victim-pk"}}
	svc, token, _ := newJoinTestService(t, invite, userRepo, "victim-pk")

	// when: caller presents the victim's account key plus an attacker-controlled device key
	_, err := svc.Join(token, "victim-pk", "victim", "attacker-device-pk", "")

	// then: the attacker-supplied device key is never registered; only
	// device #1 (the account's own key) is ensured via the legacy roster
	// backfill, exactly as an already-known, self-registered account with an
	// empty roster would be on any other join.
	assert.NoError(t, err)
	assert.Len(t, userRepo.ensureDeviceCalls, 1)
	assert.Equal(t, "victim-pk", userRepo.ensureDeviceCalls[0].devicePublicKey)
	assert.Equal(t, "victim-pk", userRepo.ensureDeviceCalls[0].userPublicKey)
}

func TestJoin_NewAccount_DevicePublicKey_CreatesThatDevice(t *testing.T) {
	// given: no existing account for this public key - a brand-new account,
	// where the caller necessarily controls both keys together.
	invite := &Invitation{ID: "invite-2", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix()}
	userRepo := &fakeUserRepo{}
	svc, token, _ := newJoinTestService(t, invite, userRepo, "new-pk")

	// when
	_, err := svc.Join(token, "new-pk", "newuser", "new-device-pk", "")

	// then: the supplied device key is honored for a brand-new account
	assert.NoError(t, err)
	assert.Len(t, userRepo.ensureDeviceCalls, 1)
	assert.Equal(t, "new-device-pk", userRepo.ensureDeviceCalls[0].devicePublicKey)
	assert.Equal(t, "new-pk", userRepo.ensureDeviceCalls[0].userPublicKey)
}

func TestJoin_NewAccount_EmptyDevicePublicKey_DefaultsToPublicKey(t *testing.T) {
	// given
	invite := &Invitation{ID: "invite-3", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix()}
	userRepo := &fakeUserRepo{}
	svc, token, _ := newJoinTestService(t, invite, userRepo, "new-pk-2")

	// when: no devicePublicKey supplied at all
	_, err := svc.Join(token, "new-pk-2", "newuser2", "", "")

	// then: defaults to device #1 == the account's own key
	assert.NoError(t, err)
	assert.Len(t, userRepo.ensureDeviceCalls, 1)
	assert.Equal(t, "new-pk-2", userRepo.ensureDeviceCalls[0].devicePublicKey)
	assert.Equal(t, "new-pk-2", userRepo.ensureDeviceCalls[0].userPublicKey)
}

// ---- #111: cross-space identity assertions on Join ----

func TestJoin_FirstContact_WithAssertion_CreatesUserWithIssuerAndEnrollsDevice(t *testing.T) {
	// given: no existing account, and a valid assertion from a vouching
	// space (issuer) naming this account and device.
	invite := &Invitation{ID: "invite-first-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix()}
	userRepo := &fakeUserRepo{}
	svc, token, spaceKeyB64 := newJoinTestService(t, invite, userRepo, "new-account-pk")

	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	issuerB64 := base64.StdEncoding.EncodeToString(issuerPub)
	now := time.Now().Unix()
	assertion := buildAssertionJWS(t, issuerPriv, issuerB64, "new-account-pk", spaceKeyB64, "newbie", "new-device-key", now, now+120)

	// when
	_, err = svc.Join(token, "new-account-pk", "newbie", "new-device-key", assertion)

	// then: the new account is pinned to the vouching space, and the
	// presented device is enrolled.
	assert.NoError(t, err)
	assert.Equal(t, issuerB64, userRepo.existingUser.Issuer)
	assert.Len(t, userRepo.ensureDeviceCalls, 1)
	assert.Equal(t, "new-device-key", userRepo.ensureDeviceCalls[0].devicePublicKey)
	assert.Equal(t, "new-account-pk", userRepo.ensureDeviceCalls[0].userPublicKey)
}

func TestJoin_FirstContact_SelfSignedAssertion_PinsOwnKey(t *testing.T) {
	// given: a self-anchored account (#112 D9) - iss == user_id == the
	// account's own key, signed with its own private key, no anchor space
	// involved.
	invite := &Invitation{ID: "invite-self-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix()}
	accountPub, accountPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	accountB64 := base64.StdEncoding.EncodeToString(accountPub)

	userRepo := &fakeUserRepo{}
	svc, token, spaceKeyB64 := newJoinTestService(t, invite, userRepo, accountB64)

	now := time.Now().Unix()
	assertion := buildAssertionJWS(t, accountPriv, accountB64, accountB64, spaceKeyB64, "selfanchored", accountB64, now, now+120)

	// when
	_, err = svc.Join(token, accountB64, "selfanchored", accountB64, assertion)

	// then: issuer is pinned to the account's own key, indistinguishable
	// from a plain self-registration.
	assert.NoError(t, err)
	assert.Equal(t, accountB64, userRepo.existingUser.Issuer)
}

func TestJoin_WithAssertion_UserIDMismatch_Returns401(t *testing.T) {
	// given: the assertion vouches for a DIFFERENT account than the one
	// presented in the join request.
	invite := &Invitation{ID: "invite-mismatch-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix()}
	userRepo := &fakeUserRepo{}
	svc, token, spaceKeyB64 := newJoinTestService(t, invite, userRepo, "victim-pk-2")

	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	issuerB64 := base64.StdEncoding.EncodeToString(issuerPub)
	now := time.Now().Unix()
	assertion := buildAssertionJWS(t, issuerPriv, issuerB64, "someone-else-pk", spaceKeyB64, "victim", "device-key", now, now+120)

	// when
	_, err = svc.Join(token, "victim-pk-2", "victim", "device-key", assertion)

	// then
	assert.ErrorIs(t, err, user.ErrInvalidAssertion)
}

func TestJoin_FirstContact_WithAssertion_DeviceOwnedByDifferentAccount_Returns409(t *testing.T) {
	// given: the presented device key is already registered to a DIFFERENT
	// account (#111 G6).
	invite := &Invitation{ID: "invite-conflict-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix()}
	userRepo := &fakeUserRepo{devices: map[string]*user.Device{
		"conflict-device": {DevicePublicKey: "conflict-device", UserPublicKey: "someone-else"},
	}}
	svc, token, spaceKeyB64 := newJoinTestService(t, invite, userRepo, "new-conflict-pk")

	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	issuerB64 := base64.StdEncoding.EncodeToString(issuerPub)
	now := time.Now().Unix()
	assertion := buildAssertionJWS(t, issuerPriv, issuerB64, "new-conflict-pk", spaceKeyB64, "newbie", "conflict-device", now, now+120)

	// when
	_, err = svc.Join(token, "new-conflict-pk", "newbie", "conflict-device", assertion)

	// then
	assert.ErrorIs(t, err, ErrDeviceConflict)
}

func TestJoin_FirstContact_WithAssertion_RevokedDevice_Returns409(t *testing.T) {
	// given: the presented device key belongs to THIS account already, but
	// has been revoked.
	revokedAt := time.Now().Unix()
	invite := &Invitation{ID: "invite-revoked-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix()}
	userRepo := &fakeUserRepo{devices: map[string]*user.Device{
		"revoked-device": {DevicePublicKey: "revoked-device", UserPublicKey: "new-revoked-pk", RevokedAt: &revokedAt},
	}}
	svc, token, spaceKeyB64 := newJoinTestService(t, invite, userRepo, "new-revoked-pk")

	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	issuerB64 := base64.StdEncoding.EncodeToString(issuerPub)
	now := time.Now().Unix()
	assertion := buildAssertionJWS(t, issuerPriv, issuerB64, "new-revoked-pk", spaceKeyB64, "newbie", "revoked-device", now, now+120)

	// when
	_, err = svc.Join(token, "new-revoked-pk", "newbie", "revoked-device", assertion)

	// then
	assert.ErrorIs(t, err, ErrDeviceConflict)
}

func TestJoin_FirstContact_WithAssertion_CreateRaceConverges(t *testing.T) {
	// given: CreateUser loses a concurrent create race (unique violation) -
	// the row that won is now visible on re-read (#111 G9).
	invite := &Invitation{ID: "invite-race-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix()}

	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	issuerB64 := base64.StdEncoding.EncodeToString(issuerPub)

	userRepo := &fakeUserRepo{
		createUserErr: &pq.Error{Code: pqUniqueViolation},
		raceWinner:    &user.User{PublicKey: "race-pk", Username: "racer", Issuer: issuerB64, Role: user.RoleGuest},
	}
	svc, token, spaceKeyB64 := newJoinTestService(t, invite, userRepo, "race-pk")

	now := time.Now().Unix()
	assertion := buildAssertionJWS(t, issuerPriv, issuerB64, "race-pk", spaceKeyB64, "racer", "race-device", now, now+120)

	// when
	result, err := svc.Join(token, "race-pk", "racer", "race-device", assertion)

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

	invite := &Invitation{ID: "invite-known-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix()}
	userRepo := &fakeUserRepo{existingUser: &user.User{PublicKey: "known-pk", Username: "known", Issuer: issuerB64}}
	svc, token, spaceKeyB64 := newJoinTestService(t, invite, userRepo, "known-pk")

	now := time.Now().Unix()
	assertion := buildAssertionJWS(t, issuerPriv, issuerB64, "known-pk", spaceKeyB64, "known", "some-new-device", now, now+120)

	// when
	_, err = svc.Join(token, "known-pk", "known", "some-new-device", assertion)

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

	invite := &Invitation{ID: "invite-repin-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix()}
	userRepo := &fakeUserRepo{existingUser: &user.User{PublicKey: "self-pk", Username: "self", Issuer: "self-pk"}}
	svc, token, spaceKeyB64 := newJoinTestService(t, invite, userRepo, "self-pk")

	now := time.Now().Unix()
	assertion := buildAssertionJWS(t, issuerPriv, issuerB64, "self-pk", spaceKeyB64, "self", "some-device", now, now+120)

	// when
	_, err = svc.Join(token, "self-pk", "self", "some-device", assertion)

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

	invite := &Invitation{ID: "invite-vouch-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix()}
	userRepo := &fakeUserRepo{existingUser: &user.User{PublicKey: "vouched-pk", Username: "vouched", Issuer: "original-issuer-key"}}
	svc, token, spaceKeyB64 := newJoinTestService(t, invite, userRepo, "vouched-pk")

	now := time.Now().Unix()
	assertion := buildAssertionJWS(t, otherIssuerPriv, otherIssuerB64, "vouched-pk", spaceKeyB64, "vouched", "some-device", now, now+120)

	// when
	_, err = svc.Join(token, "vouched-pk", "vouched", "some-device", assertion)

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
	// TestJoin_ExistingAccount_ForeignDevicePublicKey_DoesNotCreateDeviceRowForIt above).
	invite := &Invitation{ID: "invite-g3-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix()}
	userRepo := &fakeUserRepo{existingUser: &user.User{PublicKey: "vouched-pk-2", Username: "vouched2", Issuer: "some-space-key"}}
	svc, token, _ := newJoinTestService(t, invite, userRepo, "vouched-pk-2")

	// when - plain join, no assertion
	_, err := svc.Join(token, "vouched-pk-2", "vouched2", "", "")

	// then
	assert.NoError(t, err)
	assert.Empty(t, userRepo.ensureDeviceCalls)
}
