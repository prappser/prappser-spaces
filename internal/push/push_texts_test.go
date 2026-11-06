package push

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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
