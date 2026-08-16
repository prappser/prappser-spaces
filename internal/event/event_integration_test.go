//go:build integration

package event

import (
	"context"
	"errors"
	"testing"

	_ "github.com/lib/pq"

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
