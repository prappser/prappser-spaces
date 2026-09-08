package event

import (
	"errors"
	"testing"
	"time"
)

// #52 incident payload: client mint 1785679572173 (ms) against a server
// created_at of 1788771858 (s), ~36 days apart once normalized to the same unit.
func TestNormalizeMintedAt_MillisecondValue_DividesToSeconds(t *testing.T) {
	got := normalizeMintedAt(1785679572173)

	if got != 1785679572 {
		t.Fatalf("expected 1785679572, got %d", got)
	}
}

func TestNormalizeMintedAt_SecondValue_PassesThroughUnchanged(t *testing.T) {
	got := normalizeMintedAt(1788771858)

	if got != 1788771858 {
		t.Fatalf("expected 1788771858, got %d", got)
	}
}

func TestCheckEventStaleness_DestructiveEventOlderThanWindow_Rejected(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	mintedAtMs := (now.Unix() - 36*24*60*60) * 1000 // 36 days old, client-minted ms

	err := checkEventStaleness(EventTypeApplicationDeleted, mintedAtMs, now)

	if !errors.Is(err, ErrStaleEvent) {
		t.Fatalf("expected ErrStaleEvent, got %v", err)
	}
}

func TestCheckEventStaleness_DestructiveEventWithinWindow_Accepted(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	mintedAtMs := (now.Unix() - 1*24*60*60) * 1000 // 1 day old

	if err := checkEventStaleness(EventTypeApplicationDeleted, mintedAtMs, now); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckEventStaleness_NonDestructiveTypeOlderThanWindow_Accepted(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	mintedAtMs := (now.Unix() - 36*24*60*60) * 1000

	if err := checkEventStaleness(EventTypeComponentDataChanged, mintedAtMs, now); err != nil {
		t.Fatalf("expected component_data_changed to never be gated by staleness, got %v", err)
	}
}

func TestCheckEventStaleness_MintedAtZero_Accepted(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)

	if err := checkEventStaleness(EventTypeApplicationDeleted, 0, now); err != nil {
		t.Fatalf("expected mintedAt=0 to be accepted, got %v", err)
	}
}
