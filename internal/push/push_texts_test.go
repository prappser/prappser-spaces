package push

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/prappser/prappser-spaces/internal/event"
)

func TestCut_ShouldKeep120RunesAndAddEllipsisBeyond(t *testing.T) {
	// given
	exact := strings.Repeat("a", 120)
	over := strings.Repeat("a", 121)

	// when / then
	assert.Equal(t, exact, cut(exact))
	assert.Equal(t, exact+"…", cut(over))
	assert.Len(t, []rune(cut(over)), 121)
}

func TestCut_ShouldCollapseWhitespaceAndCountRunes(t *testing.T) {
	// given
	multi := strings.Repeat("ą", 121)

	// when / then
	assert.Equal(t, "a b c", cut("a\n\n b\t c "))
	assert.Equal(t, strings.Repeat("ą", 120)+"…", cut(multi))
}

func TestLangOf_ShouldFallBackToEnglish(t *testing.T) {
	// when / then
	assert.Equal(t, "pl", langOf("pl"))
	assert.Equal(t, "en", langOf(""))
	assert.Equal(t, "en", langOf("de"))
	assert.Equal(t, "en", langOf("en"))
}

func TestPerson_ShouldFallBackToSomeoneAndLabelAgents(t *testing.T) {
	// when / then
	assert.Equal(t, "Ann", textsEN.person(" Ann ", false))
	assert.Equal(t, "Someone", textsEN.person("", false))
	assert.Equal(t, "Ktoś (agent)", textsPL.person("  ", true))
}

func TestPlPlural_ShouldPickPolishForm(t *testing.T) {
	// given
	cases := map[int]string{1: "one", 2: "few", 4: "few", 5: "many", 12: "many", 14: "many", 21: "many", 22: "few", 112: "many"}

	for n, want := range cases {
		// when / then
		assert.Equal(t, want, plPlural(n), n)
	}
}

func TestMinorUnits_ShouldFormatWithSign(t *testing.T) {
	// when / then
	assert.Equal(t, "45.00", minorUnits(4500))
	assert.Equal(t, "0.05", minorUnits(5))
	assert.Equal(t, "-0.50", minorUnits(-50))
	assert.Equal(t, "-12.34", minorUnits(-1234))
}

func TestReminderPhrases_ShouldPluralizeEnglishAndPolish(t *testing.T) {
	// when / then
	assert.Equal(t, "6:00 PM, in 1 hour", textsEN.inHours("6:00 PM", 1))
	assert.Equal(t, "6:00 PM, in 2 hours", textsEN.inHours("6:00 PM", 2))
	assert.Equal(t, "18:00, za 1 godzinę", textsPL.inHours("18:00", 1))
	assert.Equal(t, "18:00, za 2 godziny", textsPL.inHours("18:00", 2))
	assert.Equal(t, "18:00, za 5 godzin", textsPL.inHours("18:00", 5))
	assert.Equal(t, "18:00, za 1 dzień", textsPL.inDays("18:00", 1))
	assert.Equal(t, "18:00, za 3 dni", textsPL.inDays("18:00", 3))
	assert.Equal(t, "6:00 PM, in 1 day", textsEN.inDays("6:00 PM", 1))
}

func TestDescribeReminder_ShouldOmitClockWithoutOccurrenceTime(t *testing.T) {
	// given
	ev := &event.Event{Data: map[string]interface{}{"itemTitle": "Call mom", "offset": "-PT15M"}}

	// when
	en := describeReminder(ev, nil, textsEN)
	pl := describeReminder(ev, nil, textsPL)

	// then
	assert.Equal(t, "", en.body)
	assert.Equal(t, "", pl.body)
	assert.Equal(t, "🔔 Call mom", en.title)
}
