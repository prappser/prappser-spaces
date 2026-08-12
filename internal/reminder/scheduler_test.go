package reminder

import (
	"context"
	"testing"

	"github.com/prappser/prappser-spaces/internal/event"
)

func TestIsWithinGrace(t *testing.T) {
	now := int64(1700000000)

	cases := []struct {
		name   string
		fireAt int64
		want   bool
	}{
		{"exactly due", now, true},
		{"12 hours late", now - 12*60*60, true},
		{"exactly at the 24h boundary", now - 24*60*60, true},
		{"24h and 1s late", now - 24*60*60 - 1, false},
		{"two days late", now - 48*60*60, false},
	}
	for _, c := range cases {
		if got := isWithinGrace(now, c.fireAt); got != c.want {
			t.Errorf("%s: expected %v, got %v", c.name, c.want, got)
		}
	}
}

func TestFireKind(t *testing.T) {
	cases := map[string]string{
		"PT0S":   "due",
		"-PT30M": "before",
		"PT30M":  "before",
		"P1D":    "before",
	}
	for spec, want := range cases {
		got, err := fireKind(spec)
		if err != nil {
			t.Errorf("%q: unexpected error: %v", spec, err)
			continue
		}
		if got != want {
			t.Errorf("%q: expected kind %q, got %q", spec, want, got)
		}
	}
}

func TestFireKind_InvalidOffset(t *testing.T) {
	if _, err := fireKind("tomorrow"); err == nil {
		t.Fatal("expected an error for an unparseable offset")
	}
}

// fakeProducer captures the event passed to ProduceEvent, for asserting the
// scheduler builds a well-formed reminder_fired without needing a DB.
type fakeProducer struct {
	produced *event.Event
	err      error
}

func (f *fakeProducer) ProduceEvent(ctx context.Context, e *event.Event) (*event.Event, error) {
	f.produced = e
	return e, f.err
}

func TestFire_BuildsReminderFiredEvent(t *testing.T) {
	// given
	producer := &fakeProducer{}
	s := NewScheduler(nil, producer, "space-public-key")
	row := dueRow{
		ruleID:        "rule-1",
		offsetIndex:   1,
		applicationID: "app-1",
		componentID:   "comp-1",
		targetKey:     "item:1",
		title:         "Buy milk",
		tz:            "Europe/Warsaw",
		offsetSpec:    "-PT30M",
		dueAt:         1700000000,
		fireAt:        1700000000 - 1800,
		recipients:    []string{"pk-1", "pk-2"},
	}

	// when
	err := s.fire(context.Background(), row)

	// then
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if producer.produced == nil {
		t.Fatal("expected ProduceEvent to be called")
	}
	evt := producer.produced
	if evt.Type != event.EventTypeReminderFired {
		t.Errorf("expected type %q, got %q", event.EventTypeReminderFired, evt.Type)
	}
	if evt.CreatorPublicKey != "space-public-key" {
		t.Errorf("expected creator to be the space's own key, got %q", evt.CreatorPublicKey)
	}
	if evt.ApplicationID != "app-1" {
		t.Errorf("expected applicationId app-1, got %q", evt.ApplicationID)
	}
	if evt.Data["kind"] != "before" {
		t.Errorf("expected kind 'before' for a non-zero offset, got %v", evt.Data["kind"])
	}
	if evt.Data["ruleId"] != "rule-1" {
		t.Errorf("expected ruleId rule-1, got %v", evt.Data["ruleId"])
	}
}

func TestFire_DueKindForZeroOffset(t *testing.T) {
	producer := &fakeProducer{}
	s := NewScheduler(nil, producer, "space-public-key")
	row := dueRow{
		ruleID:        "rule-1",
		offsetIndex:   0,
		applicationID: "app-1",
		componentID:   "comp-1",
		targetKey:     "item:1",
		offsetSpec:    "PT0S",
		dueAt:         1700000000,
		fireAt:        1700000000,
	}

	if err := s.fire(context.Background(), row); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if producer.produced.Data["kind"] != "due" {
		t.Errorf("expected kind 'due' for a zero offset, got %v", producer.produced.Data["kind"])
	}
}

func TestFire_PropagatesProducerError(t *testing.T) {
	producer := &fakeProducer{err: context.DeadlineExceeded}
	s := NewScheduler(nil, producer, "space-public-key")
	row := dueRow{ruleID: "rule-1", applicationID: "app-1", componentID: "comp-1", offsetSpec: "PT0S", dueAt: 1700000000}

	if err := s.fire(context.Background(), row); err == nil {
		t.Fatal("expected the producer's error to propagate")
	}
}
