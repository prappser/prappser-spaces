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

// insertTestOwnerMember mirrors insertTestMember (event_cursor_integration_test.go)
// but as an owner, needed for application_deleted's authorization check.
func insertTestOwnerMember(t *testing.T, db *sql.DB, id, appID, publicKey string) {
	t.Helper()
	if _, err := db.Exec(
		"INSERT INTO members (id, application_id, role, public_key) VALUES ($1,$2,'owner',$3)",
		id, appID, publicKey,
	); err != nil {
		t.Fatalf("Failed to insert test owner member %s: %v", id, err)
	}
}

// TestAcceptEvent_StaleApplicationDeleted_RejectedAppStillExistsNoEventRow is
// the incident itself: a 36-day-old application_deleted must be rejected,
// with the application untouched and nothing persisted.
func TestAcceptEvent_StaleApplicationDeleted_RejectedAppStillExistsNoEventRow(t *testing.T) {
	db := testdb.Connect(t, "event")
	defer db.Close()
	eventRepo := NewEventRepository(db)
	appRepo := application.NewRepository(db)
	service := NewEventService(eventRepo, appRepo, nil, nil)

	appID := "test-stale-app-1"
	userPK := "test-stale-user-1"
	testdb.InsertTestUser(t, db, userPK)
	insertTestApplication(t, db, appID)
	insertTestOwnerMember(t, db, "test-stale-owner-1", appID, userPK)

	submitter := &user.User{PublicKey: userPK}
	staleMintedAtMs := time.Now().Add(-36*24*time.Hour).Unix() * 1000

	evt := &Event{
		ID:               "stale-delete-evt-1",
		Type:             EventTypeApplicationDeleted,
		CreatorPublicKey: userPK,
		Version:          1,
		Data:             map[string]interface{}{"applicationId": appID, "deletedAt": staleMintedAtMs},
		CreatedAt:        staleMintedAtMs,
	}

	_, err := service.AcceptEvent(context.Background(), evt, submitter)
	if !errors.Is(err, ErrStaleEvent) {
		t.Fatalf("expected ErrStaleEvent, got %v", err)
	}

	if _, err := appRepo.GetApplicationByID(appID); err != nil {
		t.Fatalf("expected the application to still exist, got: %v", err)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM events WHERE id = $1", evt.ID).Scan(&count); err != nil {
		t.Fatalf("failed to query events: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected no event row to be written, got %d", count)
	}
}

// TestAcceptEvent_StaleComponentDataChanged_AcceptedAndMerged matters as much
// as the rejection test: a 36-day-old component_data_changed (an offline
// poll vote) must still be accepted and merged per key. If this fails, the
// staleness gate is too blunt.
func TestAcceptEvent_StaleComponentDataChanged_AcceptedAndMerged(t *testing.T) {
	db := testdb.Connect(t, "event")
	defer db.Close()
	eventRepo := NewEventRepository(db)
	appRepo := application.NewRepository(db)
	service := NewEventService(eventRepo, appRepo, nil, nil)

	appID := "test-stale-app-2"
	userPK := "test-stale-user-2"
	testdb.InsertTestUser(t, db, userPK)
	insertTestApplication(t, db, appID)
	insertTestMember(t, db, "test-stale-member-2", appID, userPK)

	groupID := "test-stale-group-1"
	componentID := "test-stale-component-1"
	if _, err := db.Exec("INSERT INTO component_groups (id, application_id, name, index_order) VALUES ($1,$2,$3,0)", groupID, appID, "Poll Group"); err != nil {
		t.Fatalf("failed to insert component group: %v", err)
	}
	if _, err := db.Exec("INSERT INTO components (id, component_group_id, application_id, name, data, index_order) VALUES ($1,$2,$3,$4,$5,0)", componentID, groupID, appID, "Poll", "{}"); err != nil {
		t.Fatalf("failed to insert component: %v", err)
	}

	submitter := &user.User{PublicKey: userPK}
	staleMintedAtMs := time.Now().Add(-36*24*time.Hour).Unix() * 1000
	voteKey := "vote_" + userPK

	evt := &Event{
		ID:               "stale-vote-evt-1",
		Type:             EventTypeComponentDataChanged,
		CreatorPublicKey: userPK,
		Version:          1,
		Data: map[string]interface{}{
			"applicationId": appID,
			"componentId":   componentID,
			"changedFields": map[string]interface{}{
				voteKey: map[string]interface{}{"oldValue": nil, "newValue": "yes"},
			},
		},
		CreatedAt: staleMintedAtMs,
	}

	if _, err := service.AcceptEvent(context.Background(), evt, submitter); err != nil {
		t.Fatalf("expected a 36-day-old component_data_changed to be accepted, got: %v", err)
	}

	component, err := appRepo.GetComponentByID(componentID)
	if err != nil {
		t.Fatalf("unexpected error fetching component: %v", err)
	}
	if component.Data[voteKey] != "yes" {
		t.Fatalf("expected %s to be merged into component data, got %v", voteKey, component.Data)
	}
}

// TestAcceptEvent_DestructiveEventWithZeroCreatedAt_Accepted pins mintedAt==0
// (client omitted createdAt) as an unconditional pass, even for a
// destructive type.
func TestAcceptEvent_DestructiveEventWithZeroCreatedAt_Accepted(t *testing.T) {
	db := testdb.Connect(t, "event")
	defer db.Close()
	eventRepo := NewEventRepository(db)
	appRepo := application.NewRepository(db)
	service := NewEventService(eventRepo, appRepo, nil, nil)

	appID := "test-stale-app-3"
	userPK := "test-stale-user-3"
	testdb.InsertTestUser(t, db, userPK)
	insertTestApplication(t, db, appID)
	insertTestOwnerMember(t, db, "test-stale-owner-3", appID, userPK)

	submitter := &user.User{PublicKey: userPK}
	evt := &Event{
		ID:               "zero-createdat-delete-evt-1",
		Type:             EventTypeApplicationDeleted,
		CreatorPublicKey: userPK,
		Version:          1,
		Data:             map[string]interface{}{"applicationId": appID, "deletedAt": int64(0)},
		CreatedAt:        0,
	}

	if _, err := service.AcceptEvent(context.Background(), evt, submitter); err != nil {
		t.Fatalf("expected createdAt=0 to bypass the staleness gate, got: %v", err)
	}
}

// TestGetSince_PrunedCursor_ReturnsErrCursorNotFound writes an event, deletes
// its row directly (simulating a prune past the cursor), then asserts
// GetSince surfaces ErrCursorNotFound instead of silently replaying from 0.
func TestGetSince_PrunedCursor_ReturnsErrCursorNotFound(t *testing.T) {
	db := testdb.Connect(t, "event")
	defer db.Close()
	repo := NewEventRepository(db)

	userPK := "test-cursor-pruned-user-1"
	testdb.InsertTestUser(t, db, userPK)

	evt := &Event{ID: "pruned-cursor-evt-1", Type: EventTypeUserSettingsChanged, CreatorPublicKey: userPK, Version: 1, Data: map[string]interface{}{}}
	if err := repo.Create(evt); err != nil {
		t.Fatalf("failed to create event: %v", err)
	}
	if _, err := db.Exec("DELETE FROM events WHERE id = $1", evt.ID); err != nil {
		t.Fatalf("failed to prune event: %v", err)
	}

	_, _, err := repo.GetSince(userPK, evt.ID, 10)
	if !errors.Is(err, ErrCursorNotFound) {
		t.Fatalf("expected ErrCursorNotFound, got %v", err)
	}
}

// TestGetEventsSince_PrunedCursor_SetsFullResyncRequiredWithAppVersions
// exercises the service-level branch end to end: a pruned cursor must set
// fullResyncRequired with appVersions populated, since the client needs
// those to re-baseline.
func TestGetEventsSince_PrunedCursor_SetsFullResyncRequiredWithAppVersions(t *testing.T) {
	db := testdb.Connect(t, "event")
	defer db.Close()
	eventRepo := NewEventRepository(db)
	appRepo := application.NewRepository(db)
	service := NewEventService(eventRepo, appRepo, nil, nil)

	appID := "test-fullresync-app-1"
	userPK := "test-fullresync-user-1"
	testdb.InsertTestUser(t, db, userPK)
	insertTestApplication(t, db, appID)
	insertTestMember(t, db, "test-fullresync-member-1", appID, userPK)

	if err := appRepo.UpdateLastSequence(appID, 7); err != nil {
		t.Fatalf("failed to set last_sequence: %v", err)
	}

	evt := &Event{ID: "fullresync-cursor-evt-1", Type: EventTypeUserSettingsChanged, CreatorPublicKey: userPK, Version: 1, Data: map[string]interface{}{}}
	if err := eventRepo.Create(evt); err != nil {
		t.Fatalf("failed to create event: %v", err)
	}
	if _, err := db.Exec("DELETE FROM events WHERE id = $1", evt.ID); err != nil {
		t.Fatalf("failed to prune event: %v", err)
	}

	resp, err := service.GetEventsSince(userPK, evt.ID, 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.FullResyncRequired {
		t.Fatalf("expected FullResyncRequired to be true")
	}
	version, ok := resp.AppVersions[appID]
	if !ok {
		t.Fatalf("expected appVersions to contain %s, got %v", appID, resp.AppVersions)
	}
	if version.LastSequence != 7 {
		t.Fatalf("expected lastSequence 7, got %d", version.LastSequence)
	}
}
