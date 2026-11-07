package push

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/rs/zerolog/log"
)

const digestTickInterval = 60 * time.Second

type DigestScheduler struct {
	repo     PushRepository
	svc      *PushService
	spaceURL string
	now      func() time.Time
	ticker   *time.Ticker
	done     chan bool
}

func NewDigestScheduler(repo PushRepository, svc *PushService, spaceURL string) *DigestScheduler {
	return &DigestScheduler{repo: repo, svc: svc, spaceURL: spaceURL, now: time.Now, done: make(chan bool)}
}

func (s *DigestScheduler) Start() {
	s.ticker = time.NewTicker(digestTickInterval)
	log.Info().Dur("interval", digestTickInterval).Msg("[DIGEST] Scheduler started")
	go s.loop()
}

func (s *DigestScheduler) loop() {
	for {
		select {
		case <-s.ticker.C:
			if err := s.Tick(context.Background()); err != nil {
				log.Error().Err(err).Msg("[DIGEST] Tick failed")
			}
		case <-s.done:
			s.ticker.Stop()
			return
		}
	}
}

func (s *DigestScheduler) Stop() {
	log.Info().Msg("[DIGEST] Stopping scheduler")
	if s.ticker != nil {
		s.done <- true
	}
}

func (s *DigestScheduler) Tick(ctx context.Context) error {
	users, err := s.repo.GetDailyUsers()
	if err != nil {
		return fmt.Errorf("get daily users: %w", err)
	}
	now := s.now()
	for _, u := range users {
		if err := s.digestFor(u, now); err != nil {
			log.Error().Err(err).Msg("[DIGEST] Failed to send digest, continuing with remaining accounts")
		}
	}
	return nil
}

func (s *DigestScheduler) digestFor(u DigestUser, now time.Time) error {
	loc := time.UTC
	if u.Timezone != "" {
		l, err := time.LoadLocation(u.Timezone)
		if err != nil {
			log.Warn().Err(err).Str("timezone", u.Timezone).Msg("[DIGEST] Unknown timezone, using UTC")
		} else {
			loc = l
		}
	}
	due := lastDigestAt(now, loc).Unix()
	if due <= u.SentAt {
		return nil
	}

	rows, claimed, err := s.repo.ClaimDigest(u.PublicKey, due, now.Unix())
	if err != nil {
		return fmt.Errorf("claim digest: %w", err)
	}
	if !claimed || len(rows) == 0 {
		return nil
	}
	subs, err := s.repo.GetSubscriptionsForUsers([]string{u.PublicKey})
	if err != nil {
		return fmt.Errorf("get subscriptions: %w", err)
	}

	vapid := s.svc.vapid()
	for _, sub := range subs {
		var apps []digestApp
		for _, r := range rows {
			if r.SubscriptionID == sub.ID && !slices.Contains(sub.MutedApplicationIDs, r.ApplicationID) {
				apps = append(apps, digestApp{ApplicationID: r.ApplicationID, Name: r.AppName, Count: r.Count})
			}
		}
		if len(apps) == 0 {
			continue
		}
		payload, err := digestPayload(langOf(sub.Locale), s.spaceURL, apps)
		if err != nil {
			log.Warn().Err(err).Str("subscriptionId", sub.ID).Msg("[DIGEST] Failed to build payload")
			continue
		}
		s.svc.send(sub, vapid, payload, digestSendOptions)
	}
	return nil
}
