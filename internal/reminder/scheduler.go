package reminder

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/rs/zerolog/log"
)

const (
	tickInterval = 30 * time.Second
	batchSize    = 100
	// graceWindow: a restart after downtime must not produce an avalanche of
	// stale pushes for everything that was due while the space was down. Rows
	// older than this are marked skipped without pushing; the item still
	// renders as overdue client side. Spaces are self-hosted (laptop asleep,
	// free-tier cold stop), so 6+ hours of downtime is normal here - silently
	// never notifying is the failure a user would actually call a bug.
	// 24h is the point where the avalanche argument starts to win instead.
	// Keep this a single named const so it stays tunable.
	graceWindow = 24 * time.Hour
)

// EventProducer is the narrow interface the scheduler needs to fire
// reminder_fired events. Declared here (not in internal/event) so the
// scheduler is testable with a stub, mirroring storage.EventService and
// profile.EventService's use of the same narrow-interface pattern.
type EventProducer interface {
	ProduceEvent(ctx context.Context, e *event.Event) (*event.Event, error)
}

// Scheduler polls due reminder rows on a fixed interval and fires
// reminder_fired events for them, modelled on
// storage.PendingCleanupScheduler.
type Scheduler struct {
	db               *sql.DB
	producer         EventProducer
	creatorPublicKey string // the space's own public key: reminder_fired is space-produced, not by any member
	ticker           *time.Ticker
	done             chan bool
}

// NewScheduler creates a reminder scheduler.
func NewScheduler(db *sql.DB, producer EventProducer, creatorPublicKey string) *Scheduler {
	return &Scheduler{
		db:               db,
		producer:         producer,
		creatorPublicKey: creatorPublicKey,
		done:             make(chan bool),
	}
}

// Start begins the polling loop in a background goroutine.
func (s *Scheduler) Start() {
	s.ticker = time.NewTicker(tickInterval)
	log.Info().Dur("interval", tickInterval).Msg("[REMINDER] Scheduler started")
	go s.loop()
}

func (s *Scheduler) loop() {
	for {
		select {
		case <-s.ticker.C:
			if err := s.Tick(context.Background()); err != nil {
				log.Error().Err(err).Msg("[REMINDER] Tick failed")
			}
		case <-s.done:
			s.ticker.Stop()
			return
		}
	}
}

// Stop halts the scheduler.
func (s *Scheduler) Stop() {
	log.Info().Msg("[REMINDER] Stopping scheduler")
	if s.ticker != nil {
		s.done <- true
	}
}

// dueRowKey identifies one reminder row without its payload - the result of
// the lock-free worklist scan in Tick, re-locked one at a time by
// processRowByKey.
type dueRowKey struct {
	ruleID      string
	offsetIndex int
}

// dueRow mirrors one locked reminder row.
type dueRow struct {
	ruleID        string
	offsetIndex   int
	applicationID string
	componentID   string
	targetKey     string
	title         string
	tz            string
	rrule         *string
	offsetSpec    string
	anchorAt      int64
	dueAt         int64
	fireAt        int64
	recipients    []string
}

// Tick runs one polling cycle: takes a lock-free snapshot of up to
// batchSize due row keys, then processes each in its OWN transaction via
// processRowByKey.
//
// One transaction per row, not one per batch, is deliberate: fire() (the
// ProduceEvent call) happens outside any reminder-table transaction, so if
// a whole batch shared one transaction, an error on row N would roll back
// row N's transaction and undo the advance()s already committed for rows
// 1..N-1 - EXCEPT ProduceEvent for rows 1..N-1 already happened and can't be
// un-produced, so those rows would refire on the next tick. Scoping the
// transaction to a single row means a failure there can only affect that
// row: it stays 'pending' (unadvanced, so it's retried later) and every
// other row in the batch keeps whatever it already committed. A row's
// failure is logged and the loop continues - it must never abort the batch.
func (s *Scheduler) Tick(ctx context.Context) error {
	now := time.Now().Unix()
	keys, err := selectDueRowKeys(ctx, s.db, now)
	if err != nil {
		return fmt.Errorf("select due row keys: %w", err)
	}

	for _, k := range keys {
		if err := s.processRowByKey(ctx, k); err != nil {
			log.Error().Err(err).Str("ruleId", k.ruleID).Int("offsetIndex", k.offsetIndex).
				Msg("[REMINDER] Failed to process reminder row, continuing with remaining rows")
		}
	}

	return nil
}

// selectDueRowKeys takes a lock-free snapshot of due row keys to build this
// tick's worklist. No FOR UPDATE here - each key is re-locked individually,
// one row at a time, by processRowByKey.
func selectDueRowKeys(ctx context.Context, db *sql.DB, now int64) ([]dueRowKey, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT rule_id, offset_index
		FROM reminder
		WHERE state = 'pending' AND fire_at <= $1
		ORDER BY fire_at
		LIMIT $2`, now, batchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []dueRowKey
	for rows.Next() {
		var k dueRowKey
		if err := rows.Scan(&k.ruleID, &k.offsetIndex); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// processRowByKey re-locks a single row in its own transaction and fires/
// advances it, committing only that row. FOR UPDATE SKIP LOCKED on the
// single-row lock means a row already claimed by a concurrent tick/worker
// (or no longer 'pending' by the time we get to it) is silently skipped
// rather than double-processed.
func (s *Scheduler) processRowByKey(ctx context.Context, k dueRowKey) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	row, ok, err := lockRow(ctx, tx, k)
	if err != nil {
		return fmt.Errorf("lock row: %w", err)
	}
	if !ok {
		return nil
	}

	if err := s.processRow(ctx, tx, row, time.Now().Unix()); err != nil {
		return err
	}

	return tx.Commit()
}

// lockRow re-fetches and locks a single row by key. ok=false (no error)
// means the row was taken by someone else or is no longer pending - both
// are a no-op for the caller, not a failure.
func lockRow(ctx context.Context, tx *sql.Tx, k dueRowKey) (dueRow, bool, error) {
	var r dueRow
	var recipientsJSON sql.NullString
	err := tx.QueryRowContext(ctx, `
		SELECT rule_id, offset_index, application_id, component_id, target_key, title, tz,
		       rrule, offset_spec, anchor_at, due_at, fire_at, recipients
		FROM reminder
		WHERE rule_id = $1 AND offset_index = $2 AND state = 'pending'
		FOR UPDATE SKIP LOCKED`, k.ruleID, k.offsetIndex,
	).Scan(&r.ruleID, &r.offsetIndex, &r.applicationID, &r.componentID, &r.targetKey,
		&r.title, &r.tz, &r.rrule, &r.offsetSpec, &r.anchorAt, &r.dueAt, &r.fireAt, &recipientsJSON)
	if err == sql.ErrNoRows {
		return dueRow{}, false, nil
	}
	if err != nil {
		return dueRow{}, false, err
	}

	if recipientsJSON.Valid && recipientsJSON.String != "" {
		if err := json.Unmarshal([]byte(recipientsJSON.String), &r.recipients); err != nil {
			return dueRow{}, false, fmt.Errorf("unmarshal recipients for rule %s: %w", r.ruleID, err)
		}
	}
	return r, true, nil
}

// isWithinGrace reports whether a row that fell due at fireAt is still
// worth pushing at now, rather than silently marked skipped. Split out as a
// pure function so the grace-window boundary is unit-testable without a DB.
func isWithinGrace(now, fireAt int64) bool {
	return now-fireAt <= int64(graceWindow.Seconds())
}

// fireKind derives the reminder_fired wire enum ("due" | "before") from an
// offset spec: zero duration means the reminder fired at the occurrence
// itself, anything else fired some time before it.
func fireKind(offsetSpec string) (kind string, err error) {
	d, err := ParseOffsetDuration(offsetSpec)
	if err != nil {
		return "", err
	}
	if d == 0 {
		return "due", nil
	}
	return "before", nil
}

func (s *Scheduler) processRow(ctx context.Context, tx *sql.Tx, row dueRow, now int64) error {
	if !isWithinGrace(now, row.fireAt) {
		log.Debug().Str("ruleId", row.ruleID).Int("offsetIndex", row.offsetIndex).
			Msg("[REMINDER] Grace window exceeded, skipping without push")
		_, err := tx.ExecContext(ctx, `UPDATE reminder SET state = 'skipped' WHERE rule_id = $1 AND offset_index = $2`,
			row.ruleID, row.offsetIndex)
		return err
	}

	if err := s.fire(ctx, row); err != nil {
		return fmt.Errorf("fire: %w", err)
	}

	return s.advance(ctx, tx, row)
}

// fire produces the reminder_fired event. It runs outside the row's own SQL
// transaction (ProduceEvent does its own persistence), matching how other
// space-produced events are emitted (see storage/endpoints.go,
// invitation_service.go).
func (s *Scheduler) fire(ctx context.Context, row dueRow) error {
	kind, err := fireKind(row.offsetSpec)
	if err != nil {
		return fmt.Errorf("rule %s offset %q: %w", row.ruleID, row.offsetSpec, err)
	}

	firedData := &event.ReminderFiredData{
		Version:       1,
		ApplicationID: row.applicationID,
		ComponentID:   row.componentID,
		TargetKey:     row.targetKey,
		RuleID:        row.ruleID,
		OccurrenceAt:  row.dueAt,
		Kind:          kind,
		Offset:        row.offsetSpec,
		ItemTitle:     row.title,
		Recipients:    row.recipients,
	}
	data, err := event.MarshalData(firedData)
	if err != nil {
		return fmt.Errorf("marshal reminder_fired data: %w", err)
	}

	evt := &event.Event{
		ID:               uuid.New().String(),
		Type:             event.EventTypeReminderFired,
		CreatorPublicKey: s.creatorPublicKey,
		ApplicationID:    row.applicationID,
		Data:             data,
	}

	_, err = s.producer.ProduceEvent(ctx, evt)
	return err
}

// advance moves the row to its next occurrence, or retires it (state =
// 'done') once the recurrence is exhausted or fails to parse.
func (s *Scheduler) advance(ctx context.Context, tx *sql.Tx, row dueRow) error {
	rruleStr := ""
	if row.rrule != nil {
		rruleStr = *row.rrule
	}

	nextDue, ok, err := NextOccurrence(rruleStr, row.tz, row.anchorAt, row.dueAt)
	if err != nil {
		log.Error().Err(err).Str("ruleId", row.ruleID).
			Msg("[REMINDER] Failed to compute next occurrence, marking done")
		ok = false
	}
	if !ok {
		_, err := tx.ExecContext(ctx, `UPDATE reminder SET state = 'done' WHERE rule_id = $1 AND offset_index = $2`,
			row.ruleID, row.offsetIndex)
		return err
	}

	nextFireAt, err := FireAt(nextDue, row.offsetSpec)
	if err != nil {
		return fmt.Errorf("compute next fire_at: %w", err)
	}

	_, err = tx.ExecContext(ctx, `UPDATE reminder SET due_at = $1, fire_at = $2 WHERE rule_id = $3 AND offset_index = $4`,
		nextDue, nextFireAt, row.ruleID, row.offsetIndex)
	return err
}
