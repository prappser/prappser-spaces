package push

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const schedUser = "pk-1"

func utcAt(h, m int) time.Time { return time.Date(2026, 5, 10, h, m, 0, 0, time.UTC) }

func newSchedulerFixture(now time.Time, sentAt int64, tz string) (*DigestScheduler, *mockPushRepository, *mockWebpushSender) {
	repo := newMockPushRepository()
	sender := newMockWebpushSender(SendResult{StatusCode: 201})
	svc := NewPushService(repo, sender, newMockSpaceVapidService("pub", "priv"), nil)
	repo.dailyUsers = []DigestUser{{PublicKey: schedUser, Timezone: tz, SentAt: sentAt}}
	repo.subscriptions["sub-1"] = &Subscription{ID: "sub-1", DevicePublicKey: schedUser, Endpoint: "https://push.example.com/1", MutedApplicationIDs: []string{}, Locale: "pl"}
	repo.claimRows = map[string][]DigestRow{schedUser: {
		{SubscriptionID: "sub-1", ApplicationID: "a1", AppName: "Groceries", Count: 7},
		{SubscriptionID: "sub-1", ApplicationID: "a2", AppName: "Trip", Count: 3},
	}}
	s := NewDigestScheduler(repo, svc, "https://space.example")
	s.now = func() time.Time { return now }
	return s, repo, sender
}

func TestDigestScheduler_Tick_ShouldNotSendBefore19(t *testing.T) {
	// given
	s, repo, sender := newSchedulerFixture(utcAt(18, 59), utcAt(20, 0).Unix()-86400, "")

	// when
	err := s.Tick(context.Background())

	// then
	assert.NoError(t, err)
	assert.Empty(t, repo.claimCalls)
	assert.Equal(t, 0, sender.callCount())
}

func TestDigestScheduler_Tick_ShouldSendOneDigestAt19InSubscriptionLocale(t *testing.T) {
	// given
	s, _, sender := newSchedulerFixture(utcAt(19, 0), utcAt(0, 0).Unix()-86400, "")

	// when
	err := s.Tick(context.Background())

	// then
	assert.NoError(t, err)
	if assert.Equal(t, 1, sender.callCount()) {
		var p struct{ Title, Body, Kind string }
		assert.NoError(t, json.Unmarshal(sender.calls[0].payload, &p))
		assert.Equal(t, "digest", p.Kind)
		assert.Equal(t, "10 nowych w 2 aplikacjach", p.Title)
		assert.Equal(t, "Groceries 7, Trip 3", p.Body)
		assert.Equal(t, digestSendOptions, sender.calls[0].opts)
	}
}

func TestDigestScheduler_Tick_ShouldSendOnceAfterDowntimeAndNotAgainSameDay(t *testing.T) {
	// given: the space was down since yesterday and wakes at 21:30
	s, _, sender := newSchedulerFixture(utcAt(21, 30), utcAt(0, 0).Unix()-2*86400, "")

	// when
	assert.NoError(t, s.Tick(context.Background()))
	s.now = func() time.Time { return utcAt(21, 31) }
	assert.NoError(t, s.Tick(context.Background()))

	// then
	assert.Equal(t, 1, sender.callCount())
}

func TestDigestScheduler_Tick_ShouldStampButNotSendWhenNothingIsPending(t *testing.T) {
	// given
	s, repo, sender := newSchedulerFixture(utcAt(19, 0), 0, "")
	repo.claimRows = nil

	// when
	assert.NoError(t, s.Tick(context.Background()))
	assert.NoError(t, s.Tick(context.Background()))

	// then
	assert.Equal(t, 0, sender.callCount())
	assert.Equal(t, utcAt(19, 0).Unix(), repo.dailyUsers[0].SentAt)
	assert.Len(t, repo.claimCalls, 1)
}

func TestDigestScheduler_Tick_ShouldFallBackToUTCForBadStoredTimezone(t *testing.T) {
	// given
	s, _, sender := newSchedulerFixture(utcAt(19, 0), 0, "Mars/Base")

	// when
	assert.NoError(t, s.Tick(context.Background()))

	// then
	assert.Equal(t, 1, sender.callCount())
}

func TestDigestScheduler_Tick_ShouldUseUserTimezoneForDueTime(t *testing.T) {
	// given: 18:30Z is 20:30 in Warsaw (CEST), after 19:00 local
	s, _, sender := newSchedulerFixture(utcAt(18, 30), utcAt(0, 0).Unix()-86400, "Europe/Warsaw")

	// when
	assert.NoError(t, s.Tick(context.Background()))

	// then
	assert.Equal(t, 1, sender.callCount())
}

func TestDigestScheduler_Tick_ShouldSkipAppsMutedByTheSubscription(t *testing.T) {
	// given
	s, repo, sender := newSchedulerFixture(utcAt(19, 0), 0, "")
	repo.subscriptions["sub-1"].MutedApplicationIDs = []string{"a1"}

	// when
	assert.NoError(t, s.Tick(context.Background()))

	// then
	if assert.Equal(t, 1, sender.callCount()) {
		var p struct{ Title, Body string }
		assert.NoError(t, json.Unmarshal(sender.calls[0].payload, &p))
		assert.Equal(t, "3 nowe w 1 aplikacji", p.Title)
		assert.Equal(t, "Trip", p.Body)
	}
}

func TestDigestScheduler_Tick_ShouldNotSendWhenEveryAppIsMuted(t *testing.T) {
	// given
	s, repo, sender := newSchedulerFixture(utcAt(19, 0), 0, "")
	repo.subscriptions["sub-1"].MutedApplicationIDs = []string{"a1", "a2"}

	// when
	assert.NoError(t, s.Tick(context.Background()))

	// then
	assert.Equal(t, 0, sender.callCount())
}

type failingSubsRepository struct{ *mockPushRepository }

func (failingSubsRepository) GetSubscriptionsForUsers([]string) ([]*Subscription, error) {
	return nil, errors.New("db down")
}

func TestDigestScheduler_Tick_ShouldNotClaimWhenSubscriptionsQueryFails(t *testing.T) {
	// given
	s, repo, sender := newSchedulerFixture(utcAt(19, 0), 0, "")
	s.repo = failingSubsRepository{repo}

	// when
	err := s.Tick(context.Background())

	// then
	assert.NoError(t, err)
	assert.Empty(t, repo.claimCalls)
	assert.Equal(t, 0, sender.callCount())
	assert.Len(t, repo.claimRows[schedUser], 2)
}

func TestDigestScheduler_Tick_ShouldWarnOncePerUserAboutBadTimezone(t *testing.T) {
	// given
	s, repo, sender := newSchedulerFixture(utcAt(19, 0), 0, "Mars/Base")

	// when
	assert.NoError(t, s.Tick(context.Background()))
	repo.dailyUsers[0].SentAt = 0
	repo.claimRows = map[string][]DigestRow{schedUser: {{SubscriptionID: "sub-1", ApplicationID: "a1", AppName: "Groceries", Count: 1}}}
	assert.NoError(t, s.Tick(context.Background()))

	// then
	assert.Equal(t, 2, sender.callCount())
	assert.Equal(t, utcAt(19, 0).Unix(), repo.dailyUsers[0].SentAt)
	assert.Len(t, s.warnedTZ, 1)
}

func TestShortKey_ShouldCutToEightChars(t *testing.T) {
	assert.Equal(t, "abcdefgh", shortKey("abcdefghijkl"))
	assert.Equal(t, "pk-1", shortKey("pk-1"))
}
