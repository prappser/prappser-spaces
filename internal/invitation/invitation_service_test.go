package invitation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

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
// EnsureDevice calls so tests can assert exactly which device key Join
// registers, and lets tests control whether the account already exists.
type fakeUserRepo struct {
	existingUser      *user.User
	ensureDeviceCalls []struct {
		devicePublicKey string
		userPublicKey   string
	}
}

func (r *fakeUserRepo) CreateUser(u *user.User) error {
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
func (r *fakeUserRepo) EnsureDevice(devicePublicKey, userPublicKey string, deviceName *string, createdAt int64) error {
	r.ensureDeviceCalls = append(r.ensureDeviceCalls, struct {
		devicePublicKey string
		userPublicKey   string
	}{devicePublicKey, userPublicKey})
	return nil
}
func (r *fakeUserRepo) GetDevice(devicePublicKey string) (*user.Device, error) { return nil, nil }
func (r *fakeUserRepo) ListDevices(userPublicKey string) ([]*user.Device, error) {
	return nil, nil
}
func (r *fakeUserRepo) RevokeDevice(devicePublicKey string, ts int64) error        { return nil }
func (r *fakeUserRepo) TouchDeviceLastSeen(devicePublicKey string, ts int64) error { return nil }
func (r *fakeUserRepo) SetPasswordCredentials(publicKey, identifier, passwordVerifier string) error {
	return nil
}
func (r *fakeUserRepo) GetPasswordCredential(identifier string) (string, string, error) {
	return "", "", nil
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
// device-registration step under test, never touching s.db or the event
// service - which is why a nil *sql.DB is safe to pass here.
func newJoinTestService(t *testing.T, invite *Invitation, userRepo *fakeUserRepo, memberPublicKey string) (*InvitationService, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	appRepo := application.NewMemoryRepository()
	assert.NoError(t, appRepo.CreateApplication(&application.Application{ID: invite.ApplicationID, Name: "Test App"}))
	assert.NoError(t, appRepo.CreateMember(&application.Member{ID: "member-" + memberPublicKey, ApplicationID: invite.ApplicationID, PublicKey: memberPublicKey}))

	invRepo := &fakeInvitationRepo{invite: invite}
	svc := NewInvitationService(invRepo, priv, pub, appRepo, nil, userRepo, fakeEventService{})

	token, err := svc.GenerateToken(invite.ID, "https://space.example", nil)
	assert.NoError(t, err)

	return svc, token
}

func TestJoin_ExistingAccount_ForeignDevicePublicKey_DoesNotCreateDeviceRowForIt(t *testing.T) {
	// given: an existing account (victim), already a member so Join
	// short-circuits right after the device-registration step under test.
	invite := &Invitation{ID: "invite-1", ApplicationID: "app-1", Role: "member", CreatedAt: time.Now().Unix()}
	userRepo := &fakeUserRepo{existingUser: &user.User{PublicKey: "victim-pk", Username: "victim"}}
	svc, token := newJoinTestService(t, invite, userRepo, "victim-pk")

	// when: caller presents the victim's account key plus an attacker-controlled device key
	_, err := svc.Join(token, "victim-pk", "victim", "attacker-device-pk")

	// then: the attacker-supplied device key is never registered; only
	// device #1 (the account's own key) is ensured, exactly as an
	// already-known account would be on any other join.
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
	svc, token := newJoinTestService(t, invite, userRepo, "new-pk")

	// when
	_, err := svc.Join(token, "new-pk", "newuser", "new-device-pk")

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
	svc, token := newJoinTestService(t, invite, userRepo, "new-pk-2")

	// when: no devicePublicKey supplied at all
	_, err := svc.Join(token, "new-pk-2", "newuser2", "")

	// then: defaults to device #1 == the account's own key
	assert.NoError(t, err)
	assert.Len(t, userRepo.ensureDeviceCalls, 1)
	assert.Equal(t, "new-pk-2", userRepo.ensureDeviceCalls[0].devicePublicKey)
	assert.Equal(t, "new-pk-2", userRepo.ensureDeviceCalls[0].userPublicKey)
}
