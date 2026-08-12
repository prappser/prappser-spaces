// Package reminder implements the generic timer queue for #42: the server
// stores reminder rows keyed by an opaque targetKey the owning component
// defines, and a scheduler polls due rows and fires reminder_fired events.
// The server itself knows nothing about checklists or any other component.
package reminder

import (
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/teambition/rrule-go"
)

// offsetPattern is the small ISO-8601 duration subset used for reminder
// offsets: an optional leading '-', then either "PT" plus H/M/S components
// (e.g. "PT0S", "-PT30M") or "P<n>D" (e.g. "P1D", "-P1D"). This is
// deliberately not a general ISO-8601 duration parser.
var offsetPattern = regexp.MustCompile(`^(-)?P(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?|(\d+)D)$`)

// ParseOffsetDuration parses one reminder offset spec into a signed
// duration. Groups: 1=sign, 2=hours, 3=minutes, 4=seconds, 5=days (the P<n>D
// form). At least one of the H/M/S/D components must be present - "PT" alone
// is rejected.
func ParseOffsetDuration(spec string) (time.Duration, error) {
	m := offsetPattern.FindStringSubmatch(spec)
	if m == nil {
		return 0, fmt.Errorf("invalid offset spec %q", spec)
	}

	var d time.Duration
	switch {
	case m[5] != "":
		days, _ := strconv.Atoi(m[5])
		d = time.Duration(days) * 24 * time.Hour
	case m[2] != "" || m[3] != "" || m[4] != "":
		if m[2] != "" {
			h, _ := strconv.Atoi(m[2])
			d += time.Duration(h) * time.Hour
		}
		if m[3] != "" {
			mm, _ := strconv.Atoi(m[3])
			d += time.Duration(mm) * time.Minute
		}
		if m[4] != "" {
			s, _ := strconv.Atoi(m[4])
			d += time.Duration(s) * time.Second
		}
	default:
		return 0, fmt.Errorf("invalid offset spec %q: no H/M/S/D component", spec)
	}

	if m[1] == "-" {
		d = -d
	}
	return d, nil
}

// FireAt applies an offset spec to an occurrence timestamp (both epoch
// seconds), e.g. FireAt(dueAt, "-PT30M") fires 30 minutes before dueAt.
func FireAt(occurrenceAt int64, offsetSpec string) (int64, error) {
	d, err := ParseOffsetDuration(offsetSpec)
	if err != nil {
		return 0, err
	}
	return occurrenceAt + int64(d.Seconds()), nil
}

// buildRRule parses rruleStr (an RFC 5545 RRULE string with no DTSTART
// line, e.g. "FREQ=WEEKLY;BYDAY=MO") and anchors it at dtstart (epoch
// seconds) interpreted in tz, so occurrences land on the correct wall-clock
// time across DST transitions. rrule-go's iterator builds every candidate
// via time.Date(..., dtstart.Location()), and Go's time.Date normalizes for
// that Location's DST rules - that's what makes this DST-correct.
func buildRRule(rruleStr, tz string, dtstart int64) (*rrule.RRule, error) {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return nil, fmt.Errorf("invalid tz %q: %w", tz, err)
	}

	opt, err := rrule.StrToROption(rruleStr)
	if err != nil {
		return nil, fmt.Errorf("invalid rrule %q: %w", rruleStr, err)
	}
	opt.Dtstart = time.Unix(dtstart, 0).In(loc)

	r, err := rrule.NewRRule(*opt)
	if err != nil {
		return nil, fmt.Errorf("invalid rrule options for %q: %w", rruleStr, err)
	}
	return r, nil
}

// NextOccurrence returns the next occurrence of the rule strictly after
// current (epoch seconds), expanding the rrule from anchor - the rule's
// original occurrence, which never changes as a row advances (see
// files/migrations/000027_reminder.up.sql). Anchoring at the true start
// rather than at current on every call is what makes COUNT and UNTIL exact:
// the RRule's internal state (occurrences consumed so far) is always
// computed from the real beginning of the series, not from wherever the row
// happens to be. An empty rruleStr means one-shot: a one-shot never has a
// next occurrence once it has already fired once, so this always returns
// ok=false for it.
func NextOccurrence(rruleStr, tz string, anchor, current int64) (next int64, ok bool, err error) {
	if rruleStr == "" {
		return 0, false, nil
	}

	r, err := buildRRule(rruleStr, tz, anchor)
	if err != nil {
		return 0, false, err
	}

	loc := r.OrigOptions.Dtstart.Location()
	nextTime := r.After(time.Unix(current, 0).In(loc), false)
	if nextTime.IsZero() {
		return 0, false, nil
	}
	return nextTime.Unix(), true, nil
}

// FirstOccurrences returns the first n occurrences at or after dtstart
// (epoch seconds, inclusive), or a single-element slice containing dtstart
// for a one-shot (empty rruleStr). This is the pure function exercised by
// the golden fixture test (recurrence_golden_test.go) - the cross-language
// contract with the Dart recurrence implementation in prappser-app.
func FirstOccurrences(rruleStr, tz string, dtstart int64, n int) ([]int64, error) {
	if n <= 0 {
		return nil, nil
	}

	if rruleStr == "" {
		return []int64{dtstart}, nil
	}

	r, err := buildRRule(rruleStr, tz, dtstart)
	if err != nil {
		return nil, err
	}

	iter := r.Iterator()
	result := make([]int64, 0, n)
	for i := 0; i < n; i++ {
		t, ok := iter()
		if !ok {
			break
		}
		result = append(result, t.Unix())
	}
	return result, nil
}
