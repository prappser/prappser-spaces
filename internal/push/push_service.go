package push

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/component"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/rs/zerolog/log"
)

// PushService fans out web push notifications to subscribers after an event is accepted.
type PushService struct {
	repo         PushRepository
	sender       WebpushSender
	vapidService *SpaceVapidService
	validator    *component.Validator
}

func NewPushService(repo PushRepository, sender WebpushSender, vapidService *SpaceVapidService, validator *component.Validator) *PushService {
	return &PushService{repo: repo, sender: sender, vapidService: vapidService, validator: validator}
}

// Push delivers a web push notification for ev to each recipient in recipientPublicKeys.
// It returns immediately; delivery runs in a background goroutine.
// The caller (EventService) excludes the event creator from recipientPublicKeys.
func (s *PushService) Push(ev *event.Event, app *application.Application, creatorDisplayName string, agent bool, recipientPublicKeys []string) {
	if len(recipientPublicKeys) == 0 {
		return
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error().Interface("panic", r).Msg("[PUSH] fanout panicked")
			}
		}()
		s.fanout(ev, app, creatorDisplayName, agent, recipientPublicKeys)
	}()
}

type rendered struct {
	payload []byte
	opts    SendOptions
}

func (s *PushService) fanout(ev *event.Event, app *application.Application, creatorDisplayName string, agent bool, recipientPublicKeys []string) {
	// An event without a rule never reaches the subscription query.
	en, ok := s.describe(ev, app, creatorDisplayName, agent, "en")
	if !ok {
		log.Debug().
			Str("eventId", ev.ID).
			Str("type", string(ev.Type)).
			Msg("[PUSH] Event has no notification rule, skipping")
		return
	}

	subs, err := s.repo.GetSubscriptionsForUsers(recipientPublicKeys)
	if err != nil {
		log.Warn().Err(err).Str("eventId", ev.ID).Msg("[PUSH] Failed to fetch subscriptions")
		return
	}
	if len(subs) == 0 {
		return
	}

	vapid := &SpaceVapid{
		VapidPublicKey:  s.vapidService.PublicKey(),
		VapidPrivateKey: s.vapidService.PrivateKey(),
	}

	// Render once per language, not once per subscription.
	byLang := map[string]rendered{}
	for _, sub := range subs {
		if ev.ApplicationID != "" && slices.Contains(sub.MutedApplicationIDs, ev.ApplicationID) {
			continue
		}
		if !en.kind.sendsIn(sub.NotifyMode) {
			continue
		}

		lang := langOf(sub.Locale)
		r, ok := byLang[lang]
		if !ok {
			n, _ := s.describe(ev, app, creatorDisplayName, agent, lang)
			payload, err := buildPayload(ev, appName(app), n)
			if err != nil {
				log.Warn().Err(err).Str("eventId", ev.ID).Msg("[PUSH] Failed to build payload")
				continue
			}
			r = rendered{payload: payload, opts: sendOptionsFor(n, ev)}
			byLang[lang] = r
		}

		s.deliver(sub, vapid, r.payload, r.opts)
	}
}

// deliver sends one push and updates subscription health fields based on the result.
func (s *PushService) deliver(sub *Subscription, vapid *SpaceVapid, payload []byte, opts SendOptions) {
	result := s.sender.Send(sub, vapid, payload, opts)

	if result.Err != nil {
		// Transport error - no HTTP response received.
		log.Warn().Err(result.Err).
			Str("subscriptionId", sub.ID).
			Str("endpoint", sub.Endpoint).
			Msg("[PUSH] Transport error delivering push")
		if err := s.repo.IncrementFailure(sub.ID); err != nil {
			log.Warn().Err(err).Str("subscriptionId", sub.ID).Msg("[PUSH] Failed to increment failure count")
		}
		return
	}

	switch {
	case result.StatusCode >= 200 && result.StatusCode < 300:
		if err := s.repo.MarkSuccess(sub.ID, time.Now().Unix()); err != nil {
			log.Warn().Err(err).Str("subscriptionId", sub.ID).Msg("[PUSH] Failed to mark success")
		}

	case result.StatusCode == 404 || result.StatusCode == 410:
		// Subscription is gone - remove it.
		log.Debug().
			Int("statusCode", result.StatusCode).
			Str("subscriptionId", sub.ID).
			Msg("[PUSH] Subscription expired - deleting")
		if err := s.repo.DeleteSubscription(sub.ID, sub.DevicePublicKey); err != nil {
			log.Warn().Err(err).Str("subscriptionId", sub.ID).Msg("[PUSH] Failed to delete expired subscription")
		}

	case result.StatusCode == 429:
		// Rate-limited - back off but keep the subscription.
		log.Warn().
			Str("subscriptionId", sub.ID).
			Str("endpoint", sub.Endpoint).
			Msg("[PUSH] Rate limited by push service")
		if err := s.repo.IncrementFailure(sub.ID); err != nil {
			log.Warn().Err(err).Str("subscriptionId", sub.ID).Msg("[PUSH] Failed to increment failure count")
		}

	default:
		log.Warn().
			Int("statusCode", result.StatusCode).
			Str("subscriptionId", sub.ID).
			Msg("[PUSH] Unexpected status from push service")
		if err := s.repo.IncrementFailure(sub.ID); err != nil {
			log.Warn().Err(err).Str("subscriptionId", sub.ID).Msg("[PUSH] Failed to increment failure count")
		}
	}
}

// pushPayload is payload v2. Additive fields are fine; the app only needs string title and body.
type pushPayload struct {
	V             int    `json:"v"`
	ApplicationID string `json:"applicationId"`
	EventID       string `json:"eventId"`
	Kind          Kind   `json:"kind"`
	Title         string `json:"title"`
	Body          string `json:"body"`
	Tag           string `json:"tag"`
	View          string `json:"view,omitempty"`
}

func appName(app *application.Application) string {
	if app == nil {
		return ""
	}
	return app.Name
}

func buildPayload(ev *event.Event, name string, n notice) ([]byte, error) {
	if name = cut(name); name == "" {
		name = "Prappser"
	}
	return json.Marshal(pushPayload{
		V:             2,
		ApplicationID: ev.ApplicationID,
		EventID:       ev.ID,
		Kind:          n.kind,
		Title:         name,
		Body:          n.body,
		Tag:           ev.ApplicationID + "|" + string(n.kind) + "|" + n.scope,
		View:          n.view,
	})
}

// topicFor is the first 32 chars of base64url(sha256(app|component|creator)), so
// queued item pushes from one person collapse to the latest.
func topicFor(applicationID, componentID, creatorPublicKey string) string {
	sum := sha256.Sum256([]byte(applicationID + "|" + componentID + "|" + creatorPublicKey))
	return base64.RawURLEncoding.EncodeToString(sum[:])[:32]
}

func sendOptionsFor(n notice, ev *event.Event) SendOptions {
	switch n.kind {
	case KindChat:
		return SendOptions{Urgency: webpush.UrgencyHigh, TTL: 21600}
	case KindItem:
		return SendOptions{Urgency: webpush.UrgencyNormal, TTL: 43200, Topic: topicFor(ev.ApplicationID, n.componentID, ev.CreatorPublicKey)}
	case KindRole, KindReminder:
		return SendOptions{Urgency: webpush.UrgencyHigh, TTL: 86400}
	}
	return SendOptions{Urgency: webpush.UrgencyNormal, TTL: 43200}
}
