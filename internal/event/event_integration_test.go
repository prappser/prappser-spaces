//go:build integration

package event

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/testdb"
	"github.com/prappser/prappser-spaces/internal/user"
)

func templateChangedEventFor(publicKey, templateID string) *Event {
	data := validTemplateChangedData()
	data["userPublicKey"] = publicKey
	data["id"] = templateID
	return &Event{
		ID:               templateID + "-evt-" + publicKey,
		Type:             EventTypeTemplateChanged,
		CreatorPublicKey: publicKey,
		Version:          1,
		Data:             data,
	}
}

// TestAcceptEvent_TemplateChanged_BacklogReplayOnlyReturnsOwnAccount drives
// submission through AcceptEvent (not a raw INSERT INTO events), proving the
// full IsUserScoped -> validator -> authorizer -> persist wiring, then
// asserts a device with no cursor only ever gets its own account's
// template_changed backlog.
func TestAcceptEvent_TemplateChanged_BacklogReplayOnlyReturnsOwnAccount(t *testing.T) {
	db := testdb.Connect(t, "event")
	defer db.Close()

	repo := NewEventRepository(db)
	service := NewEventService(repo, nil, nil, nil)

	userA := "test-template-user-a"
	userB := "test-template-user-b"
	testdb.InsertTestUser(t, db, userA)
	testdb.InsertTestUser(t, db, userB)

	submitterA := &user.User{PublicKey: userA}
	submitterB := &user.User{PublicKey: userB}

	if _, err := service.AcceptEvent(context.Background(), templateChangedEventFor(userA, "tmpl-a-1"), submitterA); err != nil {
		t.Fatalf("unexpected error submitting first event for account A: %v", err)
	}
	if _, err := service.AcceptEvent(context.Background(), templateChangedEventFor(userA, "tmpl-a-2"), submitterA); err != nil {
		t.Fatalf("unexpected error submitting second event for account A: %v", err)
	}
	if _, err := service.AcceptEvent(context.Background(), templateChangedEventFor(userB, "tmpl-b-1"), submitterB); err != nil {
		t.Fatalf("unexpected error submitting event for account B: %v", err)
	}

	events, _, err := repo.GetSince(userA, "", 100)
	if err != nil {
		t.Fatalf("unexpected error calling GetSince: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected exactly 2 events for account A, got %d", len(events))
	}
	for _, e := range events {
		if e.CreatorPublicKey != userA {
			t.Fatalf("expected only account A's events, but got one from %q", e.CreatorPublicKey)
		}
	}
}

// TestAcceptEvent_TemplateChanged_ForeignUserPublicKeyRejectedAndNotPersisted
// submits with data.userPublicKey set to a different account than the
// submitter, and asserts both that AcceptEvent rejects it as unauthorized
// and that no row is persisted.
func TestAcceptEvent_TemplateChanged_ForeignUserPublicKeyRejectedAndNotPersisted(t *testing.T) {
	db := testdb.Connect(t, "event")
	defer db.Close()

	repo := NewEventRepository(db)
	service := NewEventService(repo, nil, nil, nil)

	userA := "test-template-user-c"
	userB := "test-template-user-d"
	testdb.InsertTestUser(t, db, userA)
	testdb.InsertTestUser(t, db, userB)

	submitterA := &user.User{PublicKey: userA}

	evt := templateChangedEventFor(userB, "tmpl-forged-1")
	// The submitter is A, but the envelope's CreatorPublicKey and the
	// data's userPublicKey both claim to be B.
	_, err := service.AcceptEvent(context.Background(), evt, submitterA)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got: %v", err)
	}

	events, _, err := repo.GetSince(userB, "", 100)
	if err != nil {
		t.Fatalf("unexpected error calling GetSince: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected no persisted event for account B, got %d", len(events))
	}
}

func seedRoleApp(t *testing.T, db *sql.DB, prefix string) *application.Repository {
	t.Helper()
	appRepo := application.NewRepository(db)
	appID := prefix + "app"
	members := []application.Member{}
	for _, m := range []struct {
		name string
		role application.MemberRole
	}{{"owner", application.MemberRoleOwner}, {"admin", application.MemberRoleAdmin}, {"member", application.MemberRoleMember}} {
		testdb.InsertTestUser(t, db, prefix+m.name)
		members = append(members, application.Member{ID: prefix + m.name + "-id", Role: m.role, PublicKey: prefix + m.name})
	}
	if err := appRepo.RegisterApplication(&application.Application{ID: appID, Name: "Role App", Members: members}); err != nil {
		t.Fatalf("failed to register application: %v", err)
	}
	return appRepo
}

func TestAcceptEvent_MemberRoleChanged_AdminPromotesMemberPersistsRole(t *testing.T) {
	db := testdb.Connect(t, "event")
	defer db.Close()
	prefix := "test-role-promote-"
	appRepo := seedRoleApp(t, db, prefix)
	service := NewEventService(NewEventRepository(db), appRepo, nil, nil)
	evt := &Event{
		ID:               prefix + "evt",
		Type:             EventTypeMemberRoleChanged,
		CreatorPublicKey: prefix + "admin",
		Version:          1,
		CreatedAt:        time.Now().Unix(),
		Data: map[string]interface{}{
			"applicationId": prefix + "app", "memberPublicKey": prefix + "member", "oldRole": "member", "newRole": "admin",
		},
	}

	_, err := service.AcceptEvent(context.Background(), evt, &user.User{PublicKey: prefix + "admin"})

	if err != nil {
		t.Fatalf("expected admin to be allowed to change a role, got: %v", err)
	}
	var role string
	if err := db.QueryRow("SELECT role FROM members WHERE application_id = $1 AND public_key = $2", prefix+"app", prefix+"member").Scan(&role); err != nil {
		t.Fatalf("failed to read role: %v", err)
	}
	if role != "admin" {
		t.Fatalf("expected persisted role admin, got %q", role)
	}
}

func TestAcceptEvent_DemotedAdminInFlightEvent_RejectedAndNotPersisted(t *testing.T) {
	db := testdb.Connect(t, "event")
	defer db.Close()
	prefix := "test-role-demoted-"
	appRepo := seedRoleApp(t, db, prefix)
	service := NewEventService(NewEventRepository(db), appRepo, nil, nil)
	inFlight := &Event{
		ID:               prefix + "removal",
		Type:             EventTypeMemberRemoved,
		CreatorPublicKey: prefix + "admin",
		Version:          1,
		CreatedAt:        time.Now().Unix(),
		Data:             map[string]interface{}{"applicationId": prefix + "app", "memberPublicKey": prefix + "member"},
	}
	demotion := &Event{
		ID:               prefix + "demotion",
		Type:             EventTypeMemberRoleChanged,
		CreatorPublicKey: prefix + "owner",
		Version:          1,
		CreatedAt:        time.Now().Unix(),
		Data: map[string]interface{}{
			"applicationId": prefix + "app", "memberPublicKey": prefix + "admin", "oldRole": "admin", "newRole": "member",
		},
	}
	if _, err := service.AcceptEvent(context.Background(), demotion, &user.User{PublicKey: prefix + "owner"}); err != nil {
		t.Fatalf("owner demotion failed: %v", err)
	}

	_, err := service.AcceptEvent(context.Background(), inFlight, &user.User{PublicKey: prefix + "admin"})

	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for the demoted admin's event, got: %v", err)
	}
	var members, events int
	if err := db.QueryRow("SELECT COUNT(*) FROM members WHERE application_id = $1 AND public_key = $2", prefix+"app", prefix+"member").Scan(&members); err != nil {
		t.Fatalf("failed to count members: %v", err)
	}
	if members != 1 {
		t.Fatalf("expected target member to remain, got %d rows", members)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM events WHERE id = $1", inFlight.ID).Scan(&events); err != nil {
		t.Fatalf("failed to count events: %v", err)
	}
	if events != 0 {
		t.Fatalf("expected rejected event not to be persisted, got %d rows", events)
	}
}

func TestAcceptEvent_ExpiredAdmin_RejectedAndNotPersisted(t *testing.T) {
	db := testdb.Connect(t, "event")
	defer db.Close()
	prefix := "test-role-expired-"
	appRepo := seedRoleApp(t, db, prefix)
	service := NewEventService(NewEventRepository(db), appRepo, nil, nil)
	if _, err := db.Exec("UPDATE members SET membership_expires_at = $1 WHERE application_id = $2 AND public_key = $3", time.Now().Add(-time.Hour).Unix(), prefix+"app", prefix+"admin"); err != nil {
		t.Fatalf("failed to expire admin: %v", err)
	}
	evt := &Event{
		ID:               prefix + "evt",
		Type:             EventTypeMemberRoleChanged,
		CreatorPublicKey: prefix + "admin",
		Version:          1,
		CreatedAt:        time.Now().Unix(),
		Data: map[string]interface{}{
			"applicationId": prefix + "app", "memberPublicKey": prefix + "member", "oldRole": "member", "newRole": "admin",
		},
	}

	_, err := service.AcceptEvent(context.Background(), evt, &user.User{PublicKey: prefix + "admin"})

	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for the expired admin's event, got: %v", err)
	}
	var role string
	if err := db.QueryRow("SELECT role FROM members WHERE application_id = $1 AND public_key = $2", prefix+"app", prefix+"member").Scan(&role); err != nil {
		t.Fatalf("failed to read role: %v", err)
	}
	if role != "member" {
		t.Fatalf("expected target role to stay member, got %q", role)
	}
	var events int
	if err := db.QueryRow("SELECT COUNT(*) FROM events WHERE id = $1", evt.ID).Scan(&events); err != nil {
		t.Fatalf("failed to count events: %v", err)
	}
	if events != 0 {
		t.Fatalf("expected rejected event not to be persisted, got %d rows", events)
	}
}

func TestAcceptEvent_RemovedAdmin_RejectedAndNotPersisted(t *testing.T) {
	db := testdb.Connect(t, "event")
	defer db.Close()
	prefix := "test-role-removed-"
	appRepo := seedRoleApp(t, db, prefix)
	service := NewEventService(NewEventRepository(db), appRepo, nil, nil)
	removal := &Event{
		ID:               prefix + "admin-removal",
		Type:             EventTypeMemberRemoved,
		CreatorPublicKey: prefix + "owner",
		Version:          1,
		CreatedAt:        time.Now().Unix(),
		Data:             map[string]interface{}{"applicationId": prefix + "app", "memberPublicKey": prefix + "admin"},
	}
	afterRemoval := &Event{
		ID:               prefix + "member-removal",
		Type:             EventTypeMemberRemoved,
		CreatorPublicKey: prefix + "admin",
		Version:          1,
		CreatedAt:        time.Now().Unix(),
		Data:             map[string]interface{}{"applicationId": prefix + "app", "memberPublicKey": prefix + "member"},
	}
	if _, err := service.AcceptEvent(context.Background(), removal, &user.User{PublicKey: prefix + "owner"}); err != nil {
		t.Fatalf("owner removal of admin failed: %v", err)
	}

	_, err := service.AcceptEvent(context.Background(), afterRemoval, &user.User{PublicKey: prefix + "admin"})

	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for the removed admin's event, got: %v", err)
	}
	var members, events int
	if err := db.QueryRow("SELECT COUNT(*) FROM members WHERE application_id = $1 AND public_key = $2", prefix+"app", prefix+"member").Scan(&members); err != nil {
		t.Fatalf("failed to count members: %v", err)
	}
	if members != 1 {
		t.Fatalf("expected target member to remain, got %d rows", members)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM events WHERE id = $1", afterRemoval.ID).Scan(&events); err != nil {
		t.Fatalf("failed to count events: %v", err)
	}
	if events != 0 {
		t.Fatalf("expected rejected event not to be persisted, got %d rows", events)
	}
}
