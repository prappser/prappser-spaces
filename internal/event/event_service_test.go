package event

import (
	"context"
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
