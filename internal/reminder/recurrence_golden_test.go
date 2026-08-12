package reminder

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// files/reminder_recurrence_fixture.json is the cross-language contract with
// the Dart recurrence implementation in prappser/prappser-app: both sides
// assert the same (rrule, tz, dtstart) -> next N instants cases, so a
// semantic drift between the two implementations fails a test on whichever
// side introduced it, rather than surfacing as a silently-wrong reminder.
// This file is generated/owned externally - do not edit the fixture to make
// a test pass; a mismatch is a real finding in this package's expander.

type fixtureFile struct {
	Note  string        `json:"note"`
	Cases []fixtureCase `json:"cases"`
}

type fixtureCase struct {
	Name     string  `json:"name"`
	RRule    *string `json:"rrule"`
	TZ       string  `json:"tz"`
	Dtstart  string  `json:"dtstart"`
	Expected []int64 `json:"expected"`
}

func TestRecurrenceGoldenFixture(t *testing.T) {
	raw, err := os.ReadFile("../../files/reminder_recurrence_fixture.json")
	if err != nil {
		t.Fatalf("Failed to read fixture: %v", err)
	}

	var fixture fixtureFile
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("Failed to parse fixture: %v", err)
	}
	if len(fixture.Cases) == 0 {
		t.Fatal("Expected at least one fixture case")
	}

	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			rruleStr := ""
			if c.RRule != nil {
				rruleStr = *c.RRule
			}

			loc, err := time.LoadLocation(c.TZ)
			if err != nil {
				t.Fatalf("Failed to load tz %q: %v", c.TZ, err)
			}
			dtstart, err := time.ParseInLocation("2006-01-02T15:04:05", c.Dtstart, loc)
			if err != nil {
				t.Fatalf("Failed to parse dtstart %q: %v", c.Dtstart, err)
			}

			got, err := FirstOccurrences(rruleStr, c.TZ, dtstart.Unix(), len(c.Expected))
			if err != nil {
				t.Fatalf("FirstOccurrences failed: %v", err)
			}

			if len(got) != len(c.Expected) {
				t.Fatalf("Expected %d occurrences, got %d: %v", len(c.Expected), len(got), got)
			}
			for i, want := range c.Expected {
				if got[i] != want {
					t.Errorf("occurrence[%d]: expected %d, got %d", i, want, got[i])
				}
			}
		})
	}
}
