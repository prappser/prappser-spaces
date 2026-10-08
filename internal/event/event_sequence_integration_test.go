//go:build integration

package event

import (
	"context"
	"fmt"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/testdb"
	"github.com/prappser/prappser-spaces/internal/user"
)

// TestGetNextSequence_FloorsAgainstLastSequenceWhenEventsTableHasNone pins the
// write-side safety net on its own, independent of DeleteOlderThan's
// retention: even if an app's events rows are gone entirely,
// applications.last_sequence must still stop GetNextSequence from handing
// out a number the client has already seen.
func TestGetNextSequence_FloorsAgainstLastSequenceWhenEventsTableHasNone(t *testing.T) {
	db := testdb.Connect(t, "event")
	defer db.Close()
	repo := NewEventRepository(db)

	appID := "test-seq-floor-app-1"
	insertTestApplication(t, db, appID)
	if _, err := db.Exec("UPDATE applications SET last_sequence = $1 WHERE id = $2", int64(45), appID); err != nil {
		t.Fatalf("Failed to set last_sequence: %v", err)
	}

	seq, err := repo.GetNextSequence(appID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seq != 46 {
		t.Fatalf("expected 46 (floored from last_sequence=45 with no events rows), got %d", seq)
	}
}

// TestAcceptEvent_SequenceContinuesAfterPrune_DoesNotResetToOne is the
// issue's own repro: accept 3 events, prune, accept again - the next
// sequence number must be 4, never 1.
func TestAcceptEvent_SequenceContinuesAfterPrune_DoesNotResetToOne(t *testing.T) {
	db := testdb.Connect(t, "event")
	defer db.Close()
	eventRepo := NewEventRepository(db)
	appRepo := application.NewRepository(db)
	service := NewEventService(eventRepo, appRepo, nil, nil)

	appID := "test-seq-continuity-app-1"
	userPK := "test-seq-continuity-user-1"
	testdb.InsertTestUser(t, db, userPK)
	insertTestApplication(t, db, appID)
	insertTestMember(t, db, "test-seq-continuity-member-1", appID, userPK)

	submitter := &user.User{PublicKey: userPK}
	for i := 1; i <= 3; i++ {
		evt := &Event{
			ID:               fmt.Sprintf("seq-continuity-evt-%d", i),
			Type:             EventTypeApplicationDataChanged,
			CreatorPublicKey: userPK,
			Version:          1,
			Data:             map[string]interface{}{"applicationId": appID, "name": fmt.Sprintf("App Name %d", i)},
		}
		accepted, err := service.AcceptEvent(context.Background(), evt, submitter)
		if err != nil {
			t.Fatalf("unexpected error accepting event %d: %v", i, err)
		}
		if accepted.SequenceNumber != int64(i) {
			t.Fatalf("expected sequence %d, got %d", i, accepted.SequenceNumber)
		}
	}

	// Retention keeps the newest row (seq 3) alive on its own; this is the
	// issue's literal acceptance case. The floor's own isolated coverage is
	// TestGetNextSequence_FloorsAgainstLastSequenceWhenEventsTableHasNone.
	if _, err := eventRepo.DeleteOlderThan(time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatalf("unexpected error pruning: %v", err)
	}

	evt4 := &Event{
		ID:               "seq-continuity-evt-4",
		Type:             EventTypeApplicationDataChanged,
		CreatorPublicKey: userPK,
		Version:          1,
		Data:             map[string]interface{}{"applicationId": appID, "name": "App Name 4"},
	}
	accepted4, err := service.AcceptEvent(context.Background(), evt4, submitter)
	if err != nil {
		t.Fatalf("unexpected error accepting event 4: %v", err)
	}
	if accepted4.SequenceNumber != 4 {
		t.Fatalf("expected sequence 4 after prune, got %d (sequence numbers must never reset)", accepted4.SequenceNumber)
	}
}

// TestDeleteOlderThan_RetainsNewestRowPerAppAndPerUserScopedCreator writes
// several old rows past the cutoff for one app-scoped application and one
// user-scoped creator, then asserts exactly one row survives for each.
func TestDeleteOlderThan_RetainsNewestRowPerAppAndPerUserScopedCreator(t *testing.T) {
	db := testdb.Connect(t, "event")
	defer db.Close()
	repo := NewEventRepository(db)

	appID := "test-retention-app-1"
	userPK := "test-retention-user-1"
	testdb.InsertTestUser(t, db, userPK)
	insertTestApplication(t, db, appID)

	old := time.Now().Add(-30 * 24 * time.Hour).Unix()
	appScopedIDs := []string{"retention-app-evt-1", "retention-app-evt-2", "retention-app-evt-3"}
	for i, id := range appScopedIDs {
		e := &Event{ID: id, Type: EventTypeComponentDataChanged, ApplicationID: appID, CreatorPublicKey: userPK, Version: 1, Data: map[string]interface{}{}, CreatedAt: old + int64(i)}
		if err := repo.Create(e); err != nil {
			t.Fatalf("failed to create app-scoped event %s: %v", id, err)
		}
	}
	userScopedIDs := []string{"retention-user-evt-1", "retention-user-evt-2"}
	for i, id := range userScopedIDs {
		e := &Event{ID: id, Type: EventTypeUserSettingsChanged, CreatorPublicKey: userPK, Version: 1, Data: map[string]interface{}{}, CreatedAt: old + int64(i)}
		if err := repo.Create(e); err != nil {
			t.Fatalf("failed to create user-scoped event %s: %v", id, err)
		}
	}

	if _, err := repo.DeleteOlderThan(time.Now().Unix()); err != nil {
		t.Fatalf("unexpected error pruning: %v", err)
	}

	var appScopedCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM events WHERE application_id = $1", appID).Scan(&appScopedCount); err != nil {
		t.Fatalf("failed to count app-scoped rows: %v", err)
	}
	if appScopedCount != 1 {
		t.Fatalf("expected exactly 1 surviving app-scoped row, got %d", appScopedCount)
	}

	var remainingAppEventID string
	if err := db.QueryRow("SELECT id FROM events WHERE application_id = $1", appID).Scan(&remainingAppEventID); err != nil {
		t.Fatalf("failed to fetch surviving app-scoped row: %v", err)
	}
	if remainingAppEventID != appScopedIDs[len(appScopedIDs)-1] {
		t.Fatalf("expected the newest row (%s) to survive, got %s", appScopedIDs[len(appScopedIDs)-1], remainingAppEventID)
	}

	var userScopedCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM events WHERE application_id IS NULL AND creator_public_key = $1", userPK).Scan(&userScopedCount); err != nil {
		t.Fatalf("failed to count user-scoped rows: %v", err)
	}
	if userScopedCount != 1 {
		t.Fatalf("expected exactly 1 surviving user-scoped row, got %d", userScopedCount)
	}
}

// TestDeleteOlderThan_RetainsHighestRevTemplateChangedPerTemplate pins that
// pruning keeps the max-rev template_changed row per template (tombstones
// included) even when a newer user-scoped event of another type exists, so a
// fresh device polling from no cursor still receives every template.
func TestDeleteOlderThan_RetainsHighestRevTemplateChangedPerTemplate(t *testing.T) {
	db := testdb.Connect(t, "event")
	defer db.Close()
	repo := NewEventRepository(db)

	userPK := "test-retention-template-user-1"
	testdb.InsertTestUser(t, db, userPK)

	old := time.Now().Add(-30 * 24 * time.Hour).Unix()
	tmpl := func(id, tid string, rev int, state string, at int64) *Event {
		return &Event{ID: id, Type: EventTypeTemplateChanged, CreatorPublicKey: userPK, Version: 1, CreatedAt: at,
			Data: map[string]interface{}{"id": tid, "rev": rev, "state": state, "source": "user", "doc": map[string]interface{}{}, "createdAt": at, "updatedAt": at, "userPublicKey": userPK}}
	}
	events := []*Event{
		tmpl("retention-tmpl-a-rev2", "retention-tmpl-a", 2, "active", old),
		tmpl("retention-tmpl-a-rev1", "retention-tmpl-a", 1, "active", old+1),
		tmpl("retention-tmpl-a-rev2-tie", "retention-tmpl-a", 2, "active", old+2),
		tmpl("retention-tmpl-b-rev3", "retention-tmpl-b", 3, "deleted", old+3),
		{ID: "retention-tmpl-settings", Type: EventTypeUserSettingsChanged, CreatorPublicKey: userPK, Version: 1, Data: map[string]interface{}{}, CreatedAt: old + 4},
	}
	for _, e := range events {
		if err := repo.Create(e); err != nil {
			t.Fatalf("failed to create event %s: %v", e.ID, err)
		}
	}

	if _, err := repo.DeleteOlderThan(time.Now().Unix()); err != nil {
		t.Fatalf("unexpected error pruning: %v", err)
	}

	for id, want := range map[string]bool{
		"retention-tmpl-a-rev2": true, "retention-tmpl-a-rev2-tie": true, "retention-tmpl-a-rev1": false,
		"retention-tmpl-b-rev3": true, "retention-tmpl-settings": true,
	} {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM events WHERE id = $1", id).Scan(&n); err != nil {
			t.Fatalf("failed to count %s: %v", id, err)
		}
		if (n == 1) != want {
			t.Fatalf("event %s: survived=%v, want %v", id, n == 1, want)
		}
	}

	got, _, err := repo.GetSince(userPK, "", 100)
	if err != nil {
		t.Fatalf("GetSince failed: %v", err)
	}
	seen := map[string]bool{}
	for _, e := range got {
		seen[e.ID] = true
	}
	if !seen["retention-tmpl-a-rev2"] || !seen["retention-tmpl-b-rev3"] {
		t.Fatalf("fresh device did not receive both templates, got %v", seen)
	}
}
