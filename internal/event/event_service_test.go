package event

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/prappser/prappser-spaces/internal/application"
)

// ---- #117: getInt64Ptr must handle both shapes membershipExpiresAt can
// arrive in - a real int64 on the produce path (InvitationService.Join
// builds the map directly), and a float64 on the replay/JSON path (events
// read back from storage, or received from another space, always decode
// numbers as float64). ----

func TestGetInt64Ptr_ProducePathInt64(t *testing.T) {
	data := map[string]interface{}{"membershipExpiresAt": int64(1234567890)}

	got := getInt64Ptr(data, "membershipExpiresAt")

	if got == nil || *got != 1234567890 {
		t.Fatalf("expected 1234567890, got %v", got)
	}
}

func TestGetInt64Ptr_ReplayPathFloat64(t *testing.T) {
	data := map[string]interface{}{"membershipExpiresAt": float64(1234567890)}

	got := getInt64Ptr(data, "membershipExpiresAt")

	if got == nil || *got != 1234567890 {
		t.Fatalf("expected 1234567890, got %v", got)
	}
}

func TestGetInt64Ptr_AbsentKey(t *testing.T) {
	data := map[string]interface{}{}

	got := getInt64Ptr(data, "membershipExpiresAt")

	if got != nil {
		t.Fatalf("expected nil, got %v", *got)
	}
}

func TestExecuteMemberAdded_ProducePath_SetsMembershipExpiresAt(t *testing.T) {
	// given
	appRepo := application.NewMemoryRepository()
	if err := appRepo.CreateApplication(&application.Application{ID: "app-1", Name: "Test App"}); err != nil {
		t.Fatalf("Failed to create application: %v", err)
	}
	svc := NewEventService(nil, appRepo, nil, nil)

	// Future timestamp - not just a distinctive placeholder value, GetMemberByPublicKey
	// below is filtered by #117's activeMemberPredicate/isMemberActive, so an expired one
	// would make the row invisible to that lookup.
	exp := time.Now().Add(time.Hour).Unix()
	evt := &Event{
		ID:   "evt-1",
		Type: EventTypeMemberAdded,
		Data: map[string]interface{}{
			"applicationId":       "app-1",
			"memberPublicKey":     "member-pk",
			"role":                "member",
			"membershipExpiresAt": exp,
		},
	}

	// when
	err := svc.executeMemberAdded(context.Background(), evt)

	// then
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	member, err := appRepo.GetMemberByPublicKey("app-1", "member-pk")
	if err != nil {
		t.Fatalf("Expected member to be created, got error: %v", err)
	}
	if member.MembershipExpiresAt == nil || *member.MembershipExpiresAt != exp {
		t.Fatalf("Expected MembershipExpiresAt %d, got %v", exp, member.MembershipExpiresAt)
	}
}

func TestExecuteMemberAdded_ReplayPath_SetsMembershipExpiresAt(t *testing.T) {
	// given: JSON-decoded event data yields float64 for numbers, not int64 -
	// distinct from the produce-path test above.
	appRepo := application.NewMemoryRepository()
	if err := appRepo.CreateApplication(&application.Application{ID: "app-2", Name: "Test App"}); err != nil {
		t.Fatalf("Failed to create application: %v", err)
	}
	svc := NewEventService(nil, appRepo, nil, nil)

	exp := time.Now().Add(time.Hour).Unix()
	evt := &Event{
		ID:   "evt-2",
		Type: EventTypeMemberAdded,
		Data: map[string]interface{}{
			"applicationId":       "app-2",
			"memberPublicKey":     "member-pk-2",
			"role":                "member",
			"membershipExpiresAt": float64(exp),
		},
	}

	// when
	err := svc.executeMemberAdded(context.Background(), evt)

	// then
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	member, err := appRepo.GetMemberByPublicKey("app-2", "member-pk-2")
	if err != nil {
		t.Fatalf("Expected member to be created, got error: %v", err)
	}
	if member.MembershipExpiresAt == nil || *member.MembershipExpiresAt != exp {
		t.Fatalf("Expected MembershipExpiresAt %d, got %v", exp, member.MembershipExpiresAt)
	}
}

func TestExecuteMemberAdded_NoExpiry_LeavesMembershipExpiresAtNil(t *testing.T) {
	// given: a member_added event with no membershipExpiresAt key at all -
	// matches an invite with no membership duration.
	appRepo := application.NewMemoryRepository()
	if err := appRepo.CreateApplication(&application.Application{ID: "app-3", Name: "Test App"}); err != nil {
		t.Fatalf("Failed to create application: %v", err)
	}
	svc := NewEventService(nil, appRepo, nil, nil)

	evt := &Event{
		ID:   "evt-3",
		Type: EventTypeMemberAdded,
		Data: map[string]interface{}{
			"applicationId":   "app-3",
			"memberPublicKey": "member-pk-3",
			"role":            "member",
		},
	}

	// when
	err := svc.executeMemberAdded(context.Background(), evt)

	// then
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	member, err := appRepo.GetMemberByPublicKey("app-3", "member-pk-3")
	if err != nil {
		t.Fatalf("Expected member to be created, got error: %v", err)
	}
	if member.MembershipExpiresAt != nil {
		t.Fatalf("Expected nil MembershipExpiresAt, got %v", *member.MembershipExpiresAt)
	}
}

// ---- #42: executeReminderChanged must be nil-safe (existing callers that
// construct an EventService without a reminder store must keep working),
// and must delegate to the injected ReminderStore otherwise. ----

type fakeReminderStore struct {
	applied *ReminderChangedData
	err     error
}

func (f *fakeReminderStore) ApplyRuleChange(ctx context.Context, data *ReminderChangedData) error {
	f.applied = data
	return f.err
}

func reminderChangedEventData() map[string]interface{} {
	return map[string]interface{}{
		"version":       1,
		"id":            "rule-1",
		"applicationId": "app-1",
		"componentId":   "comp-1",
		"targetKey":     "item:1",
		"title":         "Buy milk",
		"dueAt":         int64(1700000000),
		"tz":            "Europe/Warsaw",
		"offsets":       []string{"PT0S"},
		"recipients":    []string{"pk-1"},
		"state":         "pending",
		"rev":           int64(1),
	}
}

func TestExecuteReminderChanged_NilStore_NoOp(t *testing.T) {
	// given: no ReminderStore wired up - the default for an EventService
	// built like the tests above (NewEventService(nil, appRepo, nil, nil)).
	svc := NewEventService(nil, nil, nil, nil)
	evt := &Event{ID: "evt-1", Type: EventTypeReminderChanged, Data: reminderChangedEventData()}

	// when
	err := svc.executeReminderChanged(context.Background(), evt)

	// then
	if err != nil {
		t.Fatalf("Expected no error with nil reminder store, got: %v", err)
	}
}

func TestExecuteReminderChanged_DelegatesToStore(t *testing.T) {
	// given
	store := &fakeReminderStore{}
	svc := NewEventService(nil, nil, nil, nil)
	svc.SetReminderStore(store)
	evt := &Event{ID: "evt-2", Type: EventTypeReminderChanged, Data: reminderChangedEventData()}

	// when
	err := svc.executeReminderChanged(context.Background(), evt)

	// then
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if store.applied == nil {
		t.Fatal("Expected ApplyRuleChange to be called")
	}
	if store.applied.ID != "rule-1" || store.applied.Rev != 1 || store.applied.TZ != "Europe/Warsaw" {
		t.Fatalf("Expected unmarshaled data to match input, got %+v", store.applied)
	}
	if len(store.applied.Offsets) != 1 || store.applied.Offsets[0] != "PT0S" {
		t.Fatalf("Expected offsets [PT0S], got %v", store.applied.Offsets)
	}
}

func TestExecuteReminderChanged_PropagatesStoreError(t *testing.T) {
	// given
	store := &fakeReminderStore{err: fmt.Errorf("db exploded")}
	svc := NewEventService(nil, nil, nil, nil)
	svc.SetReminderStore(store)
	evt := &Event{ID: "evt-3", Type: EventTypeReminderChanged, Data: reminderChangedEventData()}

	// when
	err := svc.executeReminderChanged(context.Background(), evt)

	// then
	if err == nil {
		t.Fatal("Expected error to propagate from the reminder store")
	}
}

// ---- #42: extractRecipients backs broadcastEvent's explicit-recipient
// branch (reminder_fired must reach exactly the listed keys, not "all
// members except creator" - the creator is the space itself, which would
// otherwise leave the filter matching nobody and notifying everyone). ----

func TestExtractRecipients_JSONRoundTrippedSlice(t *testing.T) {
	// given: the shape MarshalData/JSON always produces - []interface{} of strings.
	data := map[string]interface{}{"recipients": []interface{}{"pk-1", "pk-2"}}

	got := extractRecipients(data)

	if len(got) != 2 || got[0] != "pk-1" || got[1] != "pk-2" {
		t.Fatalf("Expected [pk-1 pk-2], got %v", got)
	}
}

func TestExtractRecipients_NativeStringSlice(t *testing.T) {
	// given: a caller (e.g. a test, or a producer that skips the JSON round
	// trip) builds the map by hand with a real []string.
	data := map[string]interface{}{"recipients": []string{"pk-1"}}

	got := extractRecipients(data)

	if len(got) != 1 || got[0] != "pk-1" {
		t.Fatalf("Expected [pk-1], got %v", got)
	}
}

func TestExtractRecipients_AbsentKey(t *testing.T) {
	got := extractRecipients(map[string]interface{}{})

	if got != nil {
		t.Fatalf("Expected nil, got %v", got)
	}
}

// ---- #42: broadcastEvent must push to the explicit recipient list, not
// "all members except creator", when the event data carries one. ----

type fakeBroadcaster struct{}

func (f *fakeBroadcaster) BroadcastToApplication(applicationID string, event *Event) {}
func (f *fakeBroadcaster) BroadcastToUser(userPublicKey string, event *Event)        {}

type capturingPusher struct {
	recipients []string
}

func (p *capturingPusher) Push(event *Event, appName, creatorDisplayName string, recipientPublicKeys []string) {
	p.recipients = recipientPublicKeys
}

func TestBroadcastEvent_ExplicitRecipients_OverridesAllMembers(t *testing.T) {
	// given: three members, but the event only names one as a recipient -
	// and the creator (the space) isn't a member at all, so the default
	// "all members except creator" path would notify all three.
	appRepo := application.NewMemoryRepository()
	if err := appRepo.CreateApplication(&application.Application{ID: "app-4", Name: "Test App"}); err != nil {
		t.Fatalf("Failed to create application: %v", err)
	}
	for _, pk := range []string{"member-1", "member-2", "member-3"} {
		if err := appRepo.CreateMember(&application.Member{ID: pk, ApplicationID: "app-4", Role: application.MemberRoleMember, PublicKey: pk}); err != nil {
			t.Fatalf("Failed to create member %s: %v", pk, err)
		}
	}

	pusher := &capturingPusher{}
	svc := NewEventService(nil, appRepo, &fakeBroadcaster{}, pusher)

	evt := &Event{
		ID:               "evt-4",
		Type:             EventTypeReminderFired,
		ApplicationID:    "app-4",
		CreatorPublicKey: "space-own-public-key",
		Data: map[string]interface{}{
			"applicationId": "app-4",
			"recipients":    []interface{}{"member-2"},
		},
	}

	// when
	svc.broadcastEvent(evt)

	// then
	if len(pusher.recipients) != 1 || pusher.recipients[0] != "member-2" {
		t.Fatalf("Expected push to exactly [member-2], got %v", pusher.recipients)
	}
}

func TestBroadcastEvent_NoExplicitRecipients_FallsBackToAllMembersExceptCreator(t *testing.T) {
	// given: no recipients key in data (e.g. component_data_changed) -
	// existing behavior must be unchanged.
	appRepo := application.NewMemoryRepository()
	if err := appRepo.CreateApplication(&application.Application{ID: "app-5", Name: "Test App"}); err != nil {
		t.Fatalf("Failed to create application: %v", err)
	}
	for _, pk := range []string{"member-1", "member-2"} {
		if err := appRepo.CreateMember(&application.Member{ID: pk, ApplicationID: "app-5", Role: application.MemberRoleMember, PublicKey: pk}); err != nil {
			t.Fatalf("Failed to create member %s: %v", pk, err)
		}
	}

	pusher := &capturingPusher{}
	svc := NewEventService(nil, appRepo, &fakeBroadcaster{}, pusher)

	evt := &Event{
		ID:               "evt-5",
		Type:             EventTypeComponentDataChanged,
		ApplicationID:    "app-5",
		CreatorPublicKey: "member-1",
		Data: map[string]interface{}{
			"applicationId": "app-5",
		},
	}

	// when
	svc.broadcastEvent(evt)

	// then
	if len(pusher.recipients) != 1 || pusher.recipients[0] != "member-2" {
		t.Fatalf("Expected push to [member-2] (all members except creator), got %v", pusher.recipients)
	}
}

func TestBroadcastEvent_ForgedRecipientsOnNonAllowlistedType_IsIgnored(t *testing.T) {
	// given: a client-submitted component_data_changed (validateComponentDataChangedData
	// deliberately accepts unknown keys) carrying a forged "recipients" key -
	// this must NOT be honored as an explicit push list. If it were, any
	// member could suppress push to the real members or aim it at a public
	// key that isn't even a member of the app (GetSubscriptionsForUsers
	// doesn't check membership).
	appRepo := application.NewMemoryRepository()
	if err := appRepo.CreateApplication(&application.Application{ID: "app-6", Name: "Test App"}); err != nil {
		t.Fatalf("Failed to create application: %v", err)
	}
	for _, pk := range []string{"member-1", "member-2"} {
		if err := appRepo.CreateMember(&application.Member{ID: pk, ApplicationID: "app-6", Role: application.MemberRoleMember, PublicKey: pk}); err != nil {
			t.Fatalf("Failed to create member %s: %v", pk, err)
		}
	}

	pusher := &capturingPusher{}
	svc := NewEventService(nil, appRepo, &fakeBroadcaster{}, pusher)

	evt := &Event{
		ID:               "evt-6",
		Type:             EventTypeComponentDataChanged,
		ApplicationID:    "app-6",
		CreatorPublicKey: "member-1",
		Data: map[string]interface{}{
			"applicationId": "app-6",
			"recipients":    []interface{}{"attacker-controlled-key"},
		},
	}

	// when
	svc.broadcastEvent(evt)

	// then: falls back to all members except the creator, exactly as if no
	// recipients key had been present.
	if len(pusher.recipients) != 1 || pusher.recipients[0] != "member-2" {
		t.Fatalf("Expected the forged recipients key to be ignored and push to fall back to [member-2], got %v", pusher.recipients)
	}
}
