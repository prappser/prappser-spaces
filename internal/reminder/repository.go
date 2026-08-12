package reminder

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/rs/zerolog/log"
)

// tombstoneOffsetIndex is the reserved offset_index for the single row kept
// around after a rule is cancelled - see ApplyRuleChange's doc comment for
// why a tombstone, not a plain delete, is needed for the rev guard.
const tombstoneOffsetIndex = -1

// Repository stores reminder rows and satisfies event.ReminderStore.
type Repository struct {
	db *sql.DB
}

// NewRepository creates a reminder Repository.
func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// ApplyRuleChange applies a reminder_changed rule update in one transaction:
// drop stale writes (incoming rev <= stored rev), otherwise delete every row
// for rule_id and reinsert freshly computed ones. Delete-before-reinsert is
// what makes an edited due date unable to fire under its old schedule.
//
// Tombstone decision: cancelling a rule deletes its pending rows and inserts
// a single row at offset_index = -1 with state = 'cancelled', rather than
// leaving the pending rows in place with state flipped. Rationale: the rev
// guard above reads "stored rev for this rule" as MAX(rev) across whatever
// rows currently exist for rule_id - a plain DELETE on cancel would leave no
// row to read that MAX from, so a stale pending upsert (lower rev) arriving
// out of order after the cancellation would see no stored rev, pass the
// guard, and resurrect the rule. Keeping exactly one tombstone row (instead
// of flipping state on every existing offset row) keeps that read cheap and
// the cancelled case simple: it doesn't matter how many offsets the rule
// had, there is always exactly one row to find. The scheduler's due query
// filters on state = 'pending', so the tombstone is never selected.
//
// Client contract (this is the invariant that makes the tombstone safe, not
// just an implementation detail - the next person to touch either side of
// #42 needs to see it): a cancelled rule's rule_id is retired forever. A
// user re-creating "the same" reminder after cancelling it must get a FRESH
// rule_id - ids are never reused post-cancel. And rev must be monotonic
// per rule_id even across a client with no local copy of the rule (e.g. a
// second device that never saw the original): the client computes
// rev = max(lastKnownRev + 1, nowUnixMillis), so a genuinely new rule's
// first rev is astronomically larger than any tombstone's rev and the guard
// below can never mistake a fresh rule for a resurrection attempt. Without
// BOTH halves of that contract, a stale pending write for an old,
// cancelled rule_id would be dropped forever by the guard below - which is
// correct for stale sync traffic, but would also permanently block a
// deliberately reused rule_id with a restarted rev counter. That scenario
// should not occur under the contract above; if it ever does, the WARN log
// below is what surfaces it.
func (r *Repository) ApplyRuleChange(ctx context.Context, data *event.ReminderChangedData) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	var storedRev sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(rev) FROM reminder WHERE rule_id = $1`, data.ID).Scan(&storedRev); err != nil {
		return fmt.Errorf("read stored rev for rule %s: %w", data.ID, err)
	}
	if storedRev.Valid && data.Rev <= storedRev.Int64 {
		// WARN, not debug: under the client contract documented above, this
		// branch should only ever be hit by genuinely stale sync traffic
		// (an out-of-order retry/replay of an old write). If it fires for
		// any other reason - e.g. a client violating the fresh-rule_id or
		// monotonic-rev contract - a rule silently never gets applied, so
		// this needs to be visible without turning on debug logging.
		log.Warn().
			Str("ruleId", data.ID).
			Int64("incomingRev", data.Rev).
			Int64("storedRev", storedRev.Int64).
			Msg("[REMINDER] Dropping stale rule update")
		return tx.Commit()
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM reminder WHERE rule_id = $1`, data.ID); err != nil {
		return fmt.Errorf("delete existing rows for rule %s: %w", data.ID, err)
	}

	recipientsJSON, err := json.Marshal(data.Recipients)
	if err != nil {
		return fmt.Errorf("marshal recipients for rule %s: %w", data.ID, err)
	}

	// anchor_at = data.DueAt always: a reminder_changed fully resets the
	// rule, so the incoming dueAt IS the new true start, for the tombstone
	// row too (irrelevant there since it's never expanded, but keeping it
	// set avoids a NULL/zero anchor for whichever row a future edit revives).
	if data.State == "cancelled" {
		if err := insertRow(ctx, tx, data, tombstoneOffsetIndex, "PT0S", data.DueAt, data.DueAt, data.DueAt, recipientsJSON, "cancelled"); err != nil {
			return fmt.Errorf("insert tombstone for rule %s: %w", data.ID, err)
		}
		return tx.Commit()
	}

	for i, offsetSpec := range data.Offsets {
		fireAt, err := FireAt(data.DueAt, offsetSpec)
		if err != nil {
			return fmt.Errorf("rule %s offset %q: %w", data.ID, offsetSpec, err)
		}
		if err := insertRow(ctx, tx, data, i, offsetSpec, data.DueAt, data.DueAt, fireAt, recipientsJSON, "pending"); err != nil {
			return fmt.Errorf("insert row for rule %s offset %d: %w", data.ID, i, err)
		}
	}

	return tx.Commit()
}

func insertRow(ctx context.Context, tx *sql.Tx, data *event.ReminderChangedData, offsetIndex int, offsetSpec string, anchorAt, dueAt, fireAt int64, recipientsJSON []byte, state string) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO reminder (rule_id, offset_index, application_id, component_id, target_key,
			title, tz, rrule, offset_spec, anchor_at, due_at, fire_at, recipients, state, rev)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
		data.ID, offsetIndex, data.ApplicationID, data.ComponentID, data.TargetKey,
		data.Title, data.TZ, data.RRule, offsetSpec, anchorAt, dueAt, fireAt, recipientsJSON, state, data.Rev,
	)
	return err
}
