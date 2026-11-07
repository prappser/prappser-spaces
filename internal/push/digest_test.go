package push

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return loc
}

func TestLastDigestAt_ShouldFollowLocal19AcrossWarsawDST(t *testing.T) {
	// given
	warsaw := mustLoc(t, "Europe/Warsaw")
	cases := []struct {
		name string
		now  string
		want string
	}{
		{"before the spring change", "2026-03-28T20:00:00Z", "2026-03-28T18:00:00Z"},
		{"morning of the spring change", "2026-03-29T16:59:00Z", "2026-03-28T18:00:00Z"},
		{"after the spring change", "2026-03-29T18:00:00Z", "2026-03-29T17:00:00Z"},
		{"before the autumn change", "2026-10-24T20:00:00Z", "2026-10-24T17:00:00Z"},
		{"morning of the autumn change", "2026-10-25T17:59:00Z", "2026-10-24T17:00:00Z"},
		{"after the autumn change", "2026-10-25T18:00:00Z", "2026-10-25T18:00:00Z"},
	}
	for _, tc := range cases {
		now, _ := time.Parse(time.RFC3339, tc.now)
		want, _ := time.Parse(time.RFC3339, tc.want)

		// when
		got := lastDigestAt(now, warsaw)

		// then
		assert.True(t, want.Equal(got), "%s: want %s got %s", tc.name, want, got)
	}
}

func TestLastDigestAt_ShouldUseUTCWhenLocationIsUTC(t *testing.T) {
	// given
	now := time.Date(2026, 5, 1, 18, 59, 0, 0, time.UTC)

	// when
	before := lastDigestAt(now, time.UTC)
	at := lastDigestAt(now.Add(time.Minute), time.UTC)

	// then
	assert.Equal(t, time.Date(2026, 4, 30, 19, 0, 0, 0, time.UTC), before)
	assert.Equal(t, time.Date(2026, 5, 1, 19, 0, 0, 0, time.UTC), at)
}

func TestDigestTitle_ShouldPluralizeEnglishAndPolish(t *testing.T) {
	cases := []struct {
		total int
		en    string
		pl    string
	}{
		{1, "1 new in 1 app", "1 nowe w 1 aplikacji"},
		{2, "2 new in 1 app", "2 nowe w 1 aplikacji"},
		{4, "4 new in 1 app", "4 nowe w 1 aplikacji"},
		{5, "5 new in 1 app", "5 nowych w 1 aplikacji"},
		{12, "12 new in 1 app", "12 nowych w 1 aplikacji"},
		{14, "14 new in 1 app", "14 nowych w 1 aplikacji"},
		{21, "21 new in 1 app", "21 nowych w 1 aplikacji"},
		{22, "22 new in 1 app", "22 nowe w 1 aplikacji"},
		{112, "112 new in 1 app", "112 nowych w 1 aplikacji"},
	}
	for _, tc := range cases {
		// when
		en := textsEN.digestTitle(tc.total, 1)
		pl := textsPL.digestTitle(tc.total, 1)

		// then
		assert.Equal(t, tc.en, en)
		assert.Equal(t, tc.pl, pl)
	}
}

func TestDigestTitle_ShouldPluralizeApps(t *testing.T) {
	// when / then
	assert.Equal(t, "12 new in 3 apps", textsEN.digestTitle(12, 3))
	assert.Equal(t, "12 nowych w 3 aplikacjach", textsPL.digestTitle(12, 3))
}

func TestDigestPayload_ShouldBuildGoldenPayloadForSeveralApps(t *testing.T) {
	// given
	apps := []digestApp{
		{ApplicationID: "a1", Name: "Groceries", Count: 7, Labels: []digestLabel{{Kind: KindItem, Title: "Costs", Count: 4}, {Kind: KindItem, Title: "Costs", Count: 1}, {Kind: KindChat, Count: 2}}},
		{ApplicationID: "a2", Name: "Trip", Count: 3, Labels: []digestLabel{{Kind: KindPoll, Count: 3}}},
		{ApplicationID: "a3", Name: "Home", Count: 2, Labels: []digestLabel{{Kind: KindFile, Count: 2}}},
	}

	// when
	got, err := digestPayload("en", "https://space.example", apps)

	// then
	assert.NoError(t, err)
	assert.JSONEq(t, `{
		"v": 2, "applicationId": "", "eventId": "", "kind": "digest",
		"title": "12 new in 3 apps", "body": "Groceries: Costs 5, Chat 2\nTrip: Polls 3\nHome: Files 2", "tag": "digest",
		"data": {"digest": {"spaceUrl": "https://space.example", "total": 12, "apps": [
			{"applicationId": "a1", "name": "Groceries", "count": 7},
			{"applicationId": "a2", "name": "Trip", "count": 3},
			{"applicationId": "a3", "name": "Home", "count": 2}]}}
	}`, string(got))
}

func TestDigestPayload_ShouldKeepTopThreeLabelsAndCapAppLines(t *testing.T) {
	// given
	apps := []digestApp{
		{ApplicationID: "a1", Name: "A", Count: 10, Labels: []digestLabel{{Title: "x", Count: 1}, {Title: "y", Count: 4}, {Kind: KindChat, Count: 3}, {Title: "z", Count: 2}}},
		{ApplicationID: "a2", Name: "B", Count: 1, Labels: []digestLabel{{Kind: KindMember, Count: 1}}},
		{ApplicationID: "a3", Name: "C", Count: 1, Labels: []digestLabel{{Count: 1}}},
		{ApplicationID: "a4", Name: "D", Count: 1, Labels: []digestLabel{{Count: 1}}},
		{ApplicationID: "a5", Name: "E", Count: 1, Labels: []digestLabel{{Count: 1}}},
	}

	// when
	en, errEN := digestPayload("en", "", apps)
	pl, errPL := digestPayload("pl", "", apps)

	// then
	assert.NoError(t, errEN)
	assert.NoError(t, errPL)
	var decEN, decPL struct{ Body string }
	assert.NoError(t, json.Unmarshal(en, &decEN))
	assert.NoError(t, json.Unmarshal(pl, &decPL))
	assert.Equal(t, "A: y 4, Chat 3, z 2\nB: Members 1\nC: Activity 1\n+2 more apps", decEN.Body)
	assert.Equal(t, "A: y 4, Czat 3, z 2\nB: Osoby 1\nC: Aktywność 1\n+2 aplikacji więcej", decPL.Body)
}

func TestDigestPayload_ShouldRenderOneAppLineAndPolishTitle(t *testing.T) {
	// given
	apps := []digestApp{{ApplicationID: "a1", Name: "Groceries", Count: 5, Labels: []digestLabel{{Kind: KindChat, Count: 5}}}}

	// when
	got, err := digestPayload("pl", "", apps)

	// then
	assert.NoError(t, err)
	var decoded struct {
		Title, Body string
		Data        struct {
			Digest struct {
				SpaceURL string `json:"spaceUrl"`
			}
		}
	}
	assert.NoError(t, json.Unmarshal(got, &decoded))
	assert.Equal(t, "5 nowych w 1 aplikacji", decoded.Title)
	assert.Equal(t, "Groceries: Czat 5", decoded.Body)
	assert.Equal(t, "", decoded.Data.Digest.SpaceURL)
}

func TestDigestPayload_ShouldCutLongBody(t *testing.T) {
	// given
	long := make([]rune, 300)
	for i := range long {
		long[i] = 'x'
	}
	apps := []digestApp{{ApplicationID: "a1", Name: string(long), Count: 1, Labels: []digestLabel{{Kind: KindChat, Count: 1}}}}

	// when
	got, err := digestPayload("en", "", apps)

	// then
	assert.NoError(t, err)
	var decoded struct{ Body string }
	assert.NoError(t, json.Unmarshal(got, &decoded))
	assert.Len(t, []rune(decoded.Body), maxWhatRunes+1)
}
