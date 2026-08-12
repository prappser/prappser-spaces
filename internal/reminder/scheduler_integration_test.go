//go:build integration

package reminder

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/prappser/prappser-spaces/internal/event"
)

// countingProducer is a thread-safe EventProducer stub: it records every
// produced event without touching a real event service, so this test can
// isolate the reminder table's SKIP LOCKED behavior from the rest of the
// event pipeline (already covered separately by internal/event's tests).
type countingProducer struct {
	mu       sync.Mutex
	count    int
	produced []*event.Event
}

func (p *countingProducer) ProduceEvent(ctx context.Context, e *event.Event) (*event.Event, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.count++
	p.produced = append(p.produced, e)
	return e, nil
}

func TestScheduler_Integration_ConcurrentTicksFireRowExactlyOnce(t *testing.T) {
	// given: a due, one-shot row with two explicit recipients.
	db, componentID := getTestDB(t)
	defer db.Close()
	repo := NewRepository(db)

	now := time.Now().Unix()
	data := &event.ReminderChangedData{
		ID: "rule-concurrent", ApplicationID: "test-app-1", ComponentID: componentID,
		TargetKey: "item:1", Title: "Concurrent test", DueAt: now - 10, TZ: "Europe/Warsaw",
		Offsets: []string{"PT0S"}, Recipients: []string{"pk-alice", "pk-bob"}, State: "pending", Rev: 1,
	}
	if err := repo.ApplyRuleChange(context.Background(), data); err != nil {
		t.Fatalf("unexpected error creating rule: %v", err)
	}

	producer := &countingProducer{}
	// Two independent Scheduler instances sharing the same *sql.DB, standing
	// in for two space instances/goroutines racing on the same due row -
	// FOR UPDATE SKIP LOCKED is what has to keep this to exactly one fire.
	s1 := NewScheduler(db, producer, "space-key")
	s2 := NewScheduler(db, producer, "space-key")

	// when
	var wg sync.WaitGroup
	wg.Add(2)
	errs := make(chan error, 2)
	go func() {
		defer wg.Done()
		errs <- s1.Tick(context.Background())
	}()
	go func() {
		defer wg.Done()
		errs <- s2.Tick(context.Background())
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("unexpected tick error: %v", err)
		}
	}

	// then
	producer.mu.Lock()
	defer producer.mu.Unlock()
	if producer.count != 1 {
		t.Fatalf("expected exactly one fire across both concurrent ticks, got %d", producer.count)
	}

	got := producer.produced[0]
	recipientsRaw, _ := got.Data["recipients"].([]interface{})
	if len(recipientsRaw) != 2 || recipientsRaw[0] != "pk-alice" || recipientsRaw[1] != "pk-bob" {
		t.Fatalf("expected recipients [pk-alice pk-bob], got %v", got.Data["recipients"])
	}

	states := rowStates(t, db, "rule-concurrent")
	if states[0] != "done" {
		t.Fatalf("expected the one-shot row to be marked done after firing, got %v", states)
	}
}

func TestScheduler_Integration_CountExhaustion_FiresExactlyThreeTimes(t *testing.T) {
	// given: a COUNT=3 rule whose 3 occurrences (1 minute apart) are all
	// already due, so each Tick fires the next one and advances - this
	// exercises the real fire->advance->done pipeline, not just the pure
	// recurrence math (see TestNextOccurrence_CountExhaustion).
	db, componentID := getTestDB(t)
	defer db.Close()
	repo := NewRepository(db)

	now := time.Now().Unix()
	dueAt := now - 120 // occurrences at dueAt, dueAt+60, dueAt+120(=now) - all due, all within the grace window
	rruleStr := "FREQ=MINUTELY;COUNT=3"
	data := &event.ReminderChangedData{
		ID: "rule-count3", ApplicationID: "test-app-1", ComponentID: componentID,
		TargetKey: "item:1", Title: "Count test", DueAt: dueAt, TZ: "Europe/Warsaw",
		RRule: &rruleStr, Offsets: []string{"PT0S"}, State: "pending", Rev: 1,
	}
	if err := repo.ApplyRuleChange(context.Background(), data); err != nil {
		t.Fatalf("unexpected error creating rule: %v", err)
	}

	producer := &countingProducer{}
	s := NewScheduler(db, producer, "space-key")

	// when: enough ticks to exhaust the 3 occurrences, plus one more to
	// confirm nothing fires a 4th time.
	for i := 0; i < 4; i++ {
		if err := s.Tick(context.Background()); err != nil {
			t.Fatalf("tick %d: unexpected error: %v", i, err)
		}
	}

	// then
	producer.mu.Lock()
	defer producer.mu.Unlock()
	if producer.count != 3 {
		t.Fatalf("expected exactly 3 fires for a COUNT=3 rule, got %d", producer.count)
	}

	states := rowStates(t, db, "rule-count3")
	if states[0] != "done" {
		t.Fatalf("expected the exhausted row to be in a terminal 'done' state, got %v", states)
	}
}

// selectiveFailProducer fails ProduceEvent for one specific ruleId and
// succeeds for every other - used to prove a mid-batch failure only affects
// its own row (see the fix for the batch-wide-transaction bug: fire()
// happens outside the reminder table's transaction, so a shared
// per-transaction batch would roll back already-fired rows' advance() and
// refire them next tick).
type selectiveFailProducer struct {
	mu       sync.Mutex
	failRule string
	calls    map[string]int
	produced []*event.Event
}

func newSelectiveFailProducer(failRule string) *selectiveFailProducer {
	return &selectiveFailProducer{failRule: failRule, calls: map[string]int{}}
}

func (p *selectiveFailProducer) ProduceEvent(ctx context.Context, e *event.Event) (*event.Event, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ruleID, _ := e.Data["ruleId"].(string)
	p.calls[ruleID]++
	if ruleID == p.failRule {
		return nil, fmt.Errorf("simulated producer failure for %s", ruleID)
	}
	p.produced = append(p.produced, e)
	return e, nil
}

func TestScheduler_Integration_MidBatchFailureDoesNotRollBackOrRefireOthers(t *testing.T) {
	// given: three due one-shot rows, ordered a, b, c by fire_at. The
	// producer fails only for rule-b.
	db, componentID := getTestDB(t)
	defer db.Close()
	repo := NewRepository(db)

	now := time.Now().Unix()
	for i, id := range []string{"rule-a", "rule-b", "rule-c"} {
		data := &event.ReminderChangedData{
			ID: id, ApplicationID: "test-app-1", ComponentID: componentID,
			TargetKey: "item:1", Title: "Batch test", DueAt: now - int64(3-i), TZ: "Europe/Warsaw",
			Offsets: []string{"PT0S"}, State: "pending", Rev: 1,
		}
		if err := repo.ApplyRuleChange(context.Background(), data); err != nil {
			t.Fatalf("unexpected error creating %s: %v", id, err)
		}
	}

	producer := newSelectiveFailProducer("rule-b")
	s := NewScheduler(db, producer, "space-key")

	// when: first tick - rule-b's fire fails, rule-a and rule-c must still
	// advance despite rule-b erroring in between them.
	if err := s.Tick(context.Background()); err != nil {
		t.Fatalf("unexpected tick error: %v", err)
	}

	// then
	statesAfterFirstTick := map[string]string{
		"rule-a": rowStates(t, db, "rule-a")[0],
		"rule-b": rowStates(t, db, "rule-b")[0],
		"rule-c": rowStates(t, db, "rule-c")[0],
	}
	if statesAfterFirstTick["rule-a"] != "done" {
		t.Errorf("expected rule-a to be done after tick 1, got %v", statesAfterFirstTick["rule-a"])
	}
	if statesAfterFirstTick["rule-c"] != "done" {
		t.Errorf("expected rule-c to be done after tick 1 (must not be rolled back by rule-b's failure), got %v", statesAfterFirstTick["rule-c"])
	}
	if statesAfterFirstTick["rule-b"] != "pending" {
		t.Errorf("expected rule-b to remain pending (unadvanced) after its own failed fire, got %v", statesAfterFirstTick["rule-b"])
	}

	// when: second tick - rule-a/rule-c must not refire (they're done);
	// rule-b is retried since it's still pending.
	if err := s.Tick(context.Background()); err != nil {
		t.Fatalf("unexpected tick error: %v", err)
	}

	// then
	producer.mu.Lock()
	defer producer.mu.Unlock()
	if producer.calls["rule-a"] != 1 {
		t.Errorf("expected rule-a to be fired exactly once across both ticks, got %d calls", producer.calls["rule-a"])
	}
	if producer.calls["rule-c"] != 1 {
		t.Errorf("expected rule-c to be fired exactly once across both ticks, got %d calls", producer.calls["rule-c"])
	}
	if producer.calls["rule-b"] != 2 {
		t.Errorf("expected rule-b to be retried on tick 2 (still pending), got %d calls", producer.calls["rule-b"])
	}

	if got := rowStates(t, db, "rule-b")[0]; got != "pending" {
		t.Errorf("expected rule-b to still be pending after its second failed fire, got %v", got)
	}
}
