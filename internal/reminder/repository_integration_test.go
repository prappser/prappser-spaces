//go:build integration

package reminder

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/testdb"
)

// getTestDB returns a *sql.DB scoped to this package's own Postgres schema
// (see internal/testdb), with one application/component_group/component row
// so the reminder table's component_id FK is satisfiable.
func getTestDB(t *testing.T) (db *sql.DB, componentID string) {
	t.Helper()
	db = testdb.Connect(t, "reminder")

	now := time.Now().Unix()
	if _, err := db.Exec(
		"INSERT INTO applications (id, name, created_at, updated_at) VALUES ($1,$2,$3,$3) ON CONFLICT DO NOTHING",
		"test-app-1", "Test App", now,
	); err != nil {
		t.Fatalf("Failed to insert test application: %v", err)
	}
	if _, err := db.Exec(
		"INSERT INTO component_groups (id, application_id, name, index_order) VALUES ($1,$2,$3,0) ON CONFLICT DO NOTHING",
		"test-group-1", "test-app-1", "Test Group",
	); err != nil {
		t.Fatalf("Failed to insert test component group: %v", err)
	}
	if _, err := db.Exec(
		"INSERT INTO components (id, component_group_id, application_id, name, index_order) VALUES ($1,$2,$3,$4,0) ON CONFLICT DO NOTHING",
		"test-component-1", "test-group-1", "test-app-1", "Test Component",
	); err != nil {
		t.Fatalf("Failed to insert test component: %v", err)
	}

	return db, "test-component-1"
}

func rowStates(t *testing.T, db *sql.DB, ruleID string) map[int]string {
	t.Helper()
	rows, err := db.Query(`SELECT offset_index, state FROM reminder WHERE rule_id = $1`, ruleID)
	if err != nil {
		t.Fatalf("Failed to query rows for rule %s: %v", ruleID, err)
	}
	defer rows.Close()

	result := map[int]string{}
	for rows.Next() {
		var idx int
		var state string
		if err := rows.Scan(&idx, &state); err != nil {
			t.Fatalf("Failed to scan row: %v", err)
		}
		result[idx] = state
	}
	return result
}

func TestApplyRuleChange_Integration_CreatesPendingRowsPerOffset(t *testing.T) {
	// given
	db, componentID := getTestDB(t)
	defer db.Close()
	repo := NewRepository(db)

	data := &event.ReminderChangedData{
		ID:            "rule-create",
		ApplicationID: "test-app-1",
		ComponentID:   componentID,
		TargetKey:     "item:1",
		Title:         "Buy milk",
		DueAt:         1800000000,
		TZ:            "Europe/Warsaw",
		Offsets:       []string{"PT0S", "-PT30M"},
		State:         "pending",
		Rev:           1,
	}

	// when
	err := repo.ApplyRuleChange(context.Background(), data)

	// then
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	states := rowStates(t, db, "rule-create")
	if len(states) != 2 || states[0] != "pending" || states[1] != "pending" {
		t.Fatalf("expected two pending rows, got %v", states)
	}
}

func TestApplyRuleChange_Integration_RevGuardDropsStaleUpdate(t *testing.T) {
	// given: rev 2 applied first, then a stale rev 1 update arrives late
	// (out-of-order sync) and must not overwrite rev 2's rows.
	db, componentID := getTestDB(t)
	defer db.Close()
	repo := NewRepository(db)

	base := &event.ReminderChangedData{
		ID: "rule-rev-guard", ApplicationID: "test-app-1", ComponentID: componentID,
		TargetKey: "item:1", Title: "v2", DueAt: 1800000000, TZ: "Europe/Warsaw",
		Offsets: []string{"PT0S"}, State: "pending", Rev: 2,
	}
	if err := repo.ApplyRuleChange(context.Background(), base); err != nil {
		t.Fatalf("unexpected error applying rev 2: %v", err)
	}

	stale := &event.ReminderChangedData{
		ID: "rule-rev-guard", ApplicationID: "test-app-1", ComponentID: componentID,
		TargetKey: "item:1", Title: "v1-stale", DueAt: 1900000000, TZ: "Europe/Warsaw",
		Offsets: []string{"PT0S"}, State: "pending", Rev: 1,
	}

	// when
	err := repo.ApplyRuleChange(context.Background(), stale)

	// then
	if err != nil {
		t.Fatalf("unexpected error applying stale rev: %v", err)
	}
	var title string
	if err := db.QueryRow(`SELECT title FROM reminder WHERE rule_id = $1 AND offset_index = 0`, "rule-rev-guard").Scan(&title); err != nil {
		t.Fatalf("Failed to read row: %v", err)
	}
	if title != "v2" {
		t.Fatalf("expected the stale rev-1 update to be dropped, but title is %q", title)
	}
}

func TestApplyRuleChange_Integration_EditedDueDateLeavesNoOldPendingRow(t *testing.T) {
	// given: a rule at due_at=X, then edited (higher rev) to due_at=Y.
	// Delete-before-reinsert must mean the OLD due_at's row is gone entirely,
	// not just superseded - a scheduler tick between the two writes must not
	// find a stale due-at-X row to fire.
	db, componentID := getTestDB(t)
	defer db.Close()
	repo := NewRepository(db)

	original := &event.ReminderChangedData{
		ID: "rule-edit", ApplicationID: "test-app-1", ComponentID: componentID,
		TargetKey: "item:1", Title: "Original", DueAt: 1800000000, TZ: "Europe/Warsaw",
		Offsets: []string{"PT0S"}, State: "pending", Rev: 1,
	}
	if err := repo.ApplyRuleChange(context.Background(), original); err != nil {
		t.Fatalf("unexpected error applying original: %v", err)
	}

	edited := &event.ReminderChangedData{
		ID: "rule-edit", ApplicationID: "test-app-1", ComponentID: componentID,
		TargetKey: "item:1", Title: "Edited", DueAt: 1900000000, TZ: "Europe/Warsaw",
		Offsets: []string{"PT0S"}, State: "pending", Rev: 2,
	}

	// when
	err := repo.ApplyRuleChange(context.Background(), edited)

	// then
	if err != nil {
		t.Fatalf("unexpected error applying edit: %v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM reminder WHERE rule_id = $1 AND due_at = $2`, "rule-edit", int64(1800000000)).Scan(&count); err != nil {
		t.Fatalf("Failed to count old rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected no row left at the old due_at, found %d", count)
	}
	var dueAt int64
	if err := db.QueryRow(`SELECT due_at FROM reminder WHERE rule_id = $1 AND offset_index = 0`, "rule-edit").Scan(&dueAt); err != nil {
		t.Fatalf("Failed to read current row: %v", err)
	}
	if dueAt != 1900000000 {
		t.Fatalf("expected due_at 1900000000, got %d", dueAt)
	}
}

func TestApplyRuleChange_Integration_CancelledLeavesOnlyTombstone(t *testing.T) {
	// given
	db, componentID := getTestDB(t)
	defer db.Close()
	repo := NewRepository(db)

	created := &event.ReminderChangedData{
		ID: "rule-cancel", ApplicationID: "test-app-1", ComponentID: componentID,
		TargetKey: "item:1", Title: "To cancel", DueAt: 1800000000, TZ: "Europe/Warsaw",
		Offsets: []string{"PT0S", "-PT30M"}, State: "pending", Rev: 1,
	}
	if err := repo.ApplyRuleChange(context.Background(), created); err != nil {
		t.Fatalf("unexpected error creating rule: %v", err)
	}

	cancelled := &event.ReminderChangedData{
		ID: "rule-cancel", ApplicationID: "test-app-1", ComponentID: componentID,
		TargetKey: "item:1", Title: "To cancel", DueAt: 1800000000, TZ: "Europe/Warsaw",
		Offsets: []string{"PT0S", "-PT30M"}, State: "cancelled", Rev: 2,
	}

	// when
	err := repo.ApplyRuleChange(context.Background(), cancelled)

	// then
	if err != nil {
		t.Fatalf("unexpected error cancelling: %v", err)
	}
	states := rowStates(t, db, "rule-cancel")
	if len(states) != 1 {
		t.Fatalf("expected exactly one tombstone row, got %v", states)
	}
	if states[tombstoneOffsetIndex] != "cancelled" {
		t.Fatalf("expected the tombstone row's state to be cancelled, got %v", states)
	}
}

func TestApplyRuleChange_Integration_StalePendingCannotResurrectCancelledRule(t *testing.T) {
	// given: rule cancelled at rev 3, then a stale rev-2 pending upsert
	// (delayed sync from before the cancellation) arrives - the tombstone's
	// rev must make MAX(rev) still resolve to 3, so the stale write is
	// dropped rather than resurrecting the rule.
	db, componentID := getTestDB(t)
	defer db.Close()
	repo := NewRepository(db)

	created := &event.ReminderChangedData{
		ID: "rule-resurrect", ApplicationID: "test-app-1", ComponentID: componentID,
		TargetKey: "item:1", Title: "v1", DueAt: 1800000000, TZ: "Europe/Warsaw",
		Offsets: []string{"PT0S"}, State: "pending", Rev: 1,
	}
	if err := repo.ApplyRuleChange(context.Background(), created); err != nil {
		t.Fatalf("unexpected error creating rule: %v", err)
	}

	cancelled := &event.ReminderChangedData{
		ID: "rule-resurrect", ApplicationID: "test-app-1", ComponentID: componentID,
		TargetKey: "item:1", Title: "v1", DueAt: 1800000000, TZ: "Europe/Warsaw",
		Offsets: []string{"PT0S"}, State: "cancelled", Rev: 3,
	}
	if err := repo.ApplyRuleChange(context.Background(), cancelled); err != nil {
		t.Fatalf("unexpected error cancelling rule: %v", err)
	}

	staleResurrect := &event.ReminderChangedData{
		ID: "rule-resurrect", ApplicationID: "test-app-1", ComponentID: componentID,
		TargetKey: "item:1", Title: "stale-v2", DueAt: 1900000000, TZ: "Europe/Warsaw",
		Offsets: []string{"PT0S"}, State: "pending", Rev: 2,
	}

	// when
	err := repo.ApplyRuleChange(context.Background(), staleResurrect)

	// then
	if err != nil {
		t.Fatalf("unexpected error applying stale resurrect attempt: %v", err)
	}
	states := rowStates(t, db, "rule-resurrect")
	if len(states) != 1 || states[tombstoneOffsetIndex] != "cancelled" {
		t.Fatalf("expected the rule to remain cancelled with only its tombstone, got %v", states)
	}
}
