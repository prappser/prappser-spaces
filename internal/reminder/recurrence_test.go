package reminder

import "testing"

func TestParseOffsetDuration_Valid(t *testing.T) {
	cases := map[string]int64{
		"PT0S":    0,
		"PT30M":   30 * 60,
		"-PT30M":  -30 * 60,
		"PT1H30M": 90 * 60,
		"P1D":     24 * 60 * 60,
		"-P1D":    -24 * 60 * 60,
	}
	for spec, wantSeconds := range cases {
		d, err := ParseOffsetDuration(spec)
		if err != nil {
			t.Errorf("%q: unexpected error: %v", spec, err)
			continue
		}
		if int64(d.Seconds()) != wantSeconds {
			t.Errorf("%q: expected %ds, got %ds", spec, wantSeconds, int64(d.Seconds()))
		}
	}
}

func TestParseOffsetDuration_Invalid(t *testing.T) {
	for _, spec := range []string{"", "PT", "-PT", "tomorrow", "30M", "PDay"} {
		if _, err := ParseOffsetDuration(spec); err == nil {
			t.Errorf("%q: expected an error", spec)
		}
	}
}

func TestFireAt_AppliesOffset(t *testing.T) {
	got, err := FireAt(1700000000, "-PT30M")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := int64(1700000000 - 1800); got != want {
		t.Fatalf("expected %d, got %d", want, got)
	}
}

func TestNextOccurrence_OneShotNeverRepeats(t *testing.T) {
	next, ok, err := NextOccurrence("", "Europe/Warsaw", 1700000000, 1700000000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("expected a one-shot to have no next occurrence, got %d", next)
	}
}

func TestNextOccurrence_DailyAcrossSpringForward(t *testing.T) {
	// anchor 2026-03-27T02:30:00+01:00, current 2026-03-28T02:30:00+01:00
	// (the day before Europe/Warsaw's spring-forward, from the golden
	// fixture's daily-spring-forward case) - the next daily occurrence lands
	// on the transition day itself, where wall clock 02:30 doesn't exist, so
	// it must resolve to 03:30 CEST rather than erroring or silently landing
	// an hour early/late.
	anchor := int64(1774575000)
	current := int64(1774661400)

	next, ok, err := NextOccurrence("FREQ=DAILY", "Europe/Warsaw", anchor, current)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected a next occurrence")
	}
	if want := int64(1774747800); next != want {
		t.Fatalf("expected %d (2026-03-29T03:30:00+02:00), got %d", want, next)
	}
}

func TestNextOccurrence_DailyAcrossFallBack(t *testing.T) {
	// anchor 2026-10-23T02:30:00+02:00, current 2026-10-24T02:30:00+02:00
	// (the day before Europe/Warsaw's fall-back, from the golden fixture's
	// daily-fall-back case) - the next occurrence lands on the transition
	// day, where wall clock 02:30 happens twice.
	anchor := int64(1792715400)
	current := int64(1792801800)

	next, ok, err := NextOccurrence("FREQ=DAILY", "Europe/Warsaw", anchor, current)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected a next occurrence")
	}
	if want := int64(1792891800); next != want {
		t.Fatalf("expected %d (2026-10-25T02:30:00+01:00), got %d", want, next)
	}
}

func TestNextOccurrence_InvalidTZ(t *testing.T) {
	_, _, err := NextOccurrence("FREQ=DAILY", "Not/A_Real_Zone", 1700000000, 1700000000)
	if err == nil {
		t.Fatal("expected an error for an invalid timezone")
	}
}

func TestNextOccurrence_InvalidRRule(t *testing.T) {
	_, _, err := NextOccurrence("FREQ=NOTAREALFREQ", "Europe/Warsaw", 1700000000, 1700000000)
	if err == nil {
		t.Fatal("expected an error for an invalid rrule")
	}
}

func TestNextOccurrence_CountExhaustion(t *testing.T) {
	// A COUNT=3 rule must fire exactly 3 times: the initial due_at (occurrence
	// 1, not exercised through NextOccurrence - the scheduler fires it
	// directly) plus exactly 2 more advances, then no more. Anchoring at the
	// true start (anchor) rather than at whatever occurrence just fired is
	// what makes this exact instead of running long.
	anchor := int64(1774575000) // 2026-03-27T02:30:00+01:00
	const rruleStr = "FREQ=DAILY;COUNT=3"

	occ2, ok, err := NextOccurrence(rruleStr, "Europe/Warsaw", anchor, anchor)
	if err != nil {
		t.Fatalf("unexpected error computing occurrence 2: %v", err)
	}
	if !ok {
		t.Fatal("expected occurrence 2")
	}
	if want := int64(1774661400); occ2 != want { // 2026-03-28T02:30:00+01:00
		t.Fatalf("occurrence 2: expected %d, got %d", want, occ2)
	}

	occ3, ok, err := NextOccurrence(rruleStr, "Europe/Warsaw", anchor, occ2)
	if err != nil {
		t.Fatalf("unexpected error computing occurrence 3: %v", err)
	}
	if !ok {
		t.Fatal("expected occurrence 3")
	}
	if want := int64(1774747800); occ3 != want { // 2026-03-29T03:30:00+02:00 (crosses spring-forward)
		t.Fatalf("occurrence 3: expected %d, got %d", want, occ3)
	}

	_, ok, err = NextOccurrence(rruleStr, "Europe/Warsaw", anchor, occ3)
	if err != nil {
		t.Fatalf("unexpected error computing occurrence 4: %v", err)
	}
	if ok {
		t.Fatal("expected COUNT=3 to be exhausted after 3 occurrences")
	}
}

func TestFirstOccurrences_OneShot(t *testing.T) {
	got, err := FirstOccurrences("", "Europe/Warsaw", 1780308000, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != 1780308000 {
		t.Fatalf("expected a single occurrence at dtstart, got %v", got)
	}
}
