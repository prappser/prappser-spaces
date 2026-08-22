//go:build integration

package event

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/prappser/prappser-spaces/internal/testdb"
)

// insertTestApplication inserts a bare-minimum applications row so events can
// carry a real application_id foreign key.
func insertTestApplication(t *testing.T, db *sql.DB, appID string) {
	t.Helper()
	now := time.Now().Unix()
	if _, err := db.Exec(
		"INSERT INTO applications (id, name, created_at, updated_at) VALUES ($1,$2,$3,$3)",
		appID, "Test App "+appID, now,
	); err != nil {
		t.Fatalf("Failed to insert test application %s: %v", appID, err)
	}
}

// insertTestMember inserts a bare-minimum members row. members.name was
// dropped by migration 000013, so it is never in this column list.
func insertTestMember(t *testing.T, db *sql.DB, id, appID, publicKey string) {
	t.Helper()
	if _, err := db.Exec(
		"INSERT INTO members (id, application_id, role, public_key) VALUES ($1,$2,'member',$3)",
		id, appID, publicKey,
	); err != nil {
		t.Fatalf("Failed to insert test member %s: %v", id, err)
	}
}

// rawInsertUserScopedEvent inserts an events row with the same column values
// repo.Create would write for a user-scoped event, but through an explicit
// transaction so the caller controls commit timing. Needed only for test 4,
// which has to observe a row that has taken its ordinal but not yet committed.
func rawInsertUserScopedEvent(t *testing.T, tx *sql.Tx, id string, eventType EventType, creator string, createdAt int64) {
	t.Helper()
	if _, err := tx.Exec(
		`INSERT INTO events (id, created_at, application_id, sequence_number, type, creator_public_key, version, data, space_id)
		 VALUES ($1, $2, NULL, 0, $3, $4, 1, '{}', NULL)`,
		id, createdAt, string(eventType), creator,
	); err != nil {
		t.Fatalf("Failed to raw-insert event %s: %v", id, err)
	}
}

// TestGetSince_ShouldReturnAppScopedEventWrittenInSameSecondAsUserScopedCursor
// is the issue's own repro: a user-scoped event and an app-scoped event share
// a created_at second, the user-scoped one becomes the cursor, and the
// app-scoped one must still come back. On today's code (event_repository.go
// :206) the app-scoped half filters with a bare "created_at > $2" and drops
// it forever.
func TestGetSince_ShouldReturnAppScopedEventWrittenInSameSecondAsUserScopedCursor(t *testing.T) {
	db := testdb.Connect(t, "event")
	defer db.Close()
	repo := NewEventRepository(db)

	userPK := "test-cursor-user-1"
	testdb.InsertTestUser(t, db, userPK)
	appID := "test-cursor-app-1"
	insertTestApplication(t, db, appID)
	insertTestMember(t, db, "test-cursor-member-1", appID, userPK)

	sameSecond := time.Now().Unix()

	u1 := &Event{ID: "u1-same-second", Type: EventTypeUserSettingsChanged, CreatorPublicKey: userPK, Version: 1, Data: map[string]interface{}{}, CreatedAt: sameSecond}
	if err := repo.Create(u1); err != nil {
		t.Fatalf("Failed to create user-scoped event: %v", err)
	}
	a1 := &Event{ID: "a1-same-second", Type: EventTypeComponentDataChanged, ApplicationID: appID, CreatorPublicKey: userPK, Version: 1, Data: map[string]interface{}{}, CreatedAt: sameSecond}
	if err := repo.Create(a1); err != nil {
		t.Fatalf("Failed to create app-scoped event: %v", err)
	}

	all, _, err := repo.GetSince(userPK, "", 10)
	if err != nil {
		t.Fatalf("unexpected error calling GetSince with no cursor: %v", err)
	}
	if len(all) != 2 || all[0].ID != u1.ID || all[1].ID != a1.ID {
		t.Fatalf("expected [%s, %s] with no cursor, got %v", u1.ID, a1.ID, idsOf(all))
	}

	sinceU1, _, err := repo.GetSince(userPK, u1.ID, 10)
	if err != nil {
		t.Fatalf("unexpected error calling GetSince with cursor %s: %v", u1.ID, err)
	}
	if len(sinceU1) != 1 || sinceU1[0].ID != a1.ID {
		t.Fatalf("expected exactly [%s] since the user-scoped cursor, got %v", a1.ID, idsOf(sinceU1))
	}
}

// TestGetSince_ShouldDrainEveryEventWhenPagingWithLimitOne writes five events
// inside one created_at second, spread across two applications the user
// belongs to plus their own user-scoped events, then chains the cursor at
// limit=1 until the feed is empty. Every event must surface exactly once, in
// the order it was written.
func TestGetSince_ShouldDrainEveryEventWhenPagingWithLimitOne(t *testing.T) {
	db := testdb.Connect(t, "event")
	defer db.Close()
	repo := NewEventRepository(db)

	userPK := "test-cursor-user-2"
	testdb.InsertTestUser(t, db, userPK)
	app1 := "test-cursor-app-2a"
	app2 := "test-cursor-app-2b"
	insertTestApplication(t, db, app1)
	insertTestApplication(t, db, app2)
	insertTestMember(t, db, "test-cursor-member-2a", app1, userPK)
	insertTestMember(t, db, "test-cursor-member-2b", app2, userPK)

	sameSecond := time.Now().Unix()

	expectedOrder := []string{"e1-app1", "e2-user", "e3-app2", "e4-app1", "e5-user"}
	events := map[string]*Event{
		"e1-app1": {ID: "e1-app1", Type: EventTypeComponentDataChanged, ApplicationID: app1, CreatorPublicKey: userPK, Version: 1, Data: map[string]interface{}{}, CreatedAt: sameSecond},
		"e2-user": {ID: "e2-user", Type: EventTypeUserSettingsChanged, CreatorPublicKey: userPK, Version: 1, Data: map[string]interface{}{}, CreatedAt: sameSecond},
		"e3-app2": {ID: "e3-app2", Type: EventTypeComponentDataChanged, ApplicationID: app2, CreatorPublicKey: userPK, Version: 1, Data: map[string]interface{}{}, CreatedAt: sameSecond},
		"e4-app1": {ID: "e4-app1", Type: EventTypeComponentDataChanged, ApplicationID: app1, CreatorPublicKey: userPK, Version: 1, Data: map[string]interface{}{}, CreatedAt: sameSecond},
		"e5-user": {ID: "e5-user", Type: EventTypeUserSettingsChanged, CreatorPublicKey: userPK, Version: 1, Data: map[string]interface{}{}, CreatedAt: sameSecond},
	}
	for _, id := range expectedOrder {
		if err := repo.Create(events[id]); err != nil {
			t.Fatalf("Failed to create event %s: %v", id, err)
		}
	}

	// Bounded so a regression (stuck cursor, duplicate page) fails the test
	// instead of hanging the suite.
	maxIterations := len(expectedOrder) + 2

	var drainedIDs []string
	cursor := ""
	drained := false
	for i := 0; i < maxIterations; i++ {
		page, _, err := repo.GetSince(userPK, cursor, 1)
		if err != nil {
			t.Fatalf("GetSince failed at iteration %d: %v", i, err)
		}
		if len(page) == 0 {
			drained = true
			break
		}
		if len(page) != 1 {
			t.Fatalf("expected at most 1 event per page at limit=1, got %d at iteration %d", len(page), i)
		}
		drainedIDs = append(drainedIDs, page[0].ID)
		cursor = page[0].ID
	}
	if !drained {
		t.Fatalf("did not drain within %d iterations, possible cursor regression, collected so far: %v", maxIterations, drainedIDs)
	}

	if len(drainedIDs) != len(expectedOrder) {
		t.Fatalf("expected %d events drained in order %v, got %v", len(expectedOrder), expectedOrder, drainedIDs)
	}
	for i, id := range expectedOrder {
		if drainedIDs[i] != id {
			t.Fatalf("expected event %d to be %s, got %s (full sequence: %v)", i, id, drainedIDs[i], drainedIDs)
		}
	}
}

// TestGetSince_ShouldReturnSameSecondEventWhoseIdSortsBeforeTheCursor pins the
// ordinal-based decision against the issue's own fix sketch: a
// "(created_at, id) with id >" tie-break would still drop this row, because
// the app-scoped event's id sorts lexicographically BEFORE the cursor's id
// even though it was written after it. Only insertion order (ordinal), not
// id, may decide inclusion.
func TestGetSince_ShouldReturnSameSecondEventWhoseIdSortsBeforeTheCursor(t *testing.T) {
	db := testdb.Connect(t, "event")
	defer db.Close()
	repo := NewEventRepository(db)

	userPK := "test-cursor-user-3"
	testdb.InsertTestUser(t, db, userPK)
	appID := "test-cursor-app-3"
	insertTestApplication(t, db, appID)
	insertTestMember(t, db, "test-cursor-member-3", appID, userPK)

	sameSecond := time.Now().Unix()

	// Written first (lower ordinal), id sorts late.
	cursorEvent := &Event{ID: "zzz-cursor-user-scoped", Type: EventTypeUserSettingsChanged, CreatorPublicKey: userPK, Version: 1, Data: map[string]interface{}{}, CreatedAt: sameSecond}
	if err := repo.Create(cursorEvent); err != nil {
		t.Fatalf("Failed to create cursor event: %v", err)
	}
	// Written second (higher ordinal), id sorts early.
	laterEvent := &Event{ID: "aaa-later-app-scoped", Type: EventTypeComponentDataChanged, ApplicationID: appID, CreatorPublicKey: userPK, Version: 1, Data: map[string]interface{}{}, CreatedAt: sameSecond}
	if err := repo.Create(laterEvent); err != nil {
		t.Fatalf("Failed to create later event: %v", err)
	}

	since, _, err := repo.GetSince(userPK, cursorEvent.ID, 10)
	if err != nil {
		t.Fatalf("unexpected error calling GetSince: %v", err)
	}
	if len(since) != 1 || since[0].ID != laterEvent.ID {
		t.Fatalf("expected the later-written event %s despite its lexicographically earlier id, got %v", laterEvent.ID, idsOf(since))
	}
}

// TestGetSince_ShouldSkipEventCommittedAfterAHigherOrdinalWasRead pins the one
// residual hole the fix knowingly leaves open (plan risk 3): ordinal is
// assigned at INSERT, visible at COMMIT, so two concurrent writers can commit
// out of order. A reader that lands between the two commits advances its
// cursor past the higher ordinal, and the lower one that commits later is
// permanently invisible to it, even though it exists in the table.
//
// Accepted exposure. Upgrade path if this is ever observed in practice: a
// bounded overlap re-read ("ordinal > $2 - K") plus the app's existing id
// dedup. If someone implements that, this test should go red and get
// inverted into one asserting the skipped event IS returned.
func TestGetSince_ShouldSkipEventCommittedAfterAHigherOrdinalWasRead(t *testing.T) {
	db := testdb.Connect(t, "event")
	defer db.Close()
	repo := NewEventRepository(db)

	userPK := "test-cursor-user-4"
	testdb.InsertTestUser(t, db, userPK)

	sameSecond := time.Now().Unix()

	tx1, err := db.Begin()
	if err != nil {
		t.Fatalf("Failed to begin tx1: %v", err)
	}
	rawInsertUserScopedEvent(t, tx1, "evt-x-lower-ordinal", EventTypeUserSettingsChanged, userPK, sameSecond)
	// tx1 deliberately left open: x has taken the lower ordinal but is not
	// yet committed, so no other session can see it.

	tx2, err := db.Begin()
	if err != nil {
		t.Fatalf("Failed to begin tx2: %v", err)
	}
	rawInsertUserScopedEvent(t, tx2, "evt-y-higher-ordinal", EventTypeUserSettingsChanged, userPK, sameSecond)
	if err := tx2.Commit(); err != nil {
		t.Fatalf("Failed to commit tx2: %v", err)
	}

	// A read landing between the two commits only sees the committed higher
	// ordinal, y, and a caller advances its stored cursor to it.
	firstPage, _, err := repo.GetSince(userPK, "", 10)
	if err != nil {
		t.Fatalf("unexpected error calling GetSince before tx1 commits: %v", err)
	}
	if len(firstPage) != 1 || firstPage[0].ID != "evt-y-higher-ordinal" {
		t.Fatalf("expected only the committed higher-ordinal event y, got %v", idsOf(firstPage))
	}

	if err := tx1.Commit(); err != nil {
		t.Fatalf("Failed to commit tx1: %v", err)
	}

	// x is now visible in the table, but its ordinal is lower than the cursor
	// the reader already advanced past, so it stays permanently unreturned.
	secondPage, _, err := repo.GetSince(userPK, "evt-y-higher-ordinal", 10)
	if err != nil {
		t.Fatalf("unexpected error calling GetSince after tx1 commits: %v", err)
	}
	if len(secondPage) != 0 {
		t.Fatalf("expected event x to be permanently skipped (accepted exposure, plan risk 3), got %v", idsOf(secondPage))
	}
}

func idsOf(events []*Event) []string {
	ids := make([]string, len(events))
	for i, e := range events {
		ids[i] = e.ID
	}
	return ids
}
