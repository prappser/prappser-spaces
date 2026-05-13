package push

import (
	"encoding/json"
	"time"

	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/rs/zerolog/log"
)

// PushService fans out web push notifications to subscribers after an event is accepted.
type PushService struct {
	repo   PushRepository
	sender WebpushSender
}

// NewPushService creates a PushService with the given repository and sender.
func NewPushService(repo PushRepository, sender WebpushSender) *PushService {
	return &PushService{repo: repo, sender: sender}
}

// Push delivers a web push notification for ev to each recipient in recipientPublicKeys.
// It returns immediately; delivery runs in a background goroutine.
// The caller (EventService) excludes the event creator from recipientPublicKeys.
//
// Phase 2: one push per matching subscription per event.
// The "cap to 5 then collapse to summary" logic for catchup/rejoin batches is a
// future feature (Phase 5) and is intentionally not implemented here.
func (s *PushService) Push(ev *event.Event, recipientPublicKeys []string) {
	if len(recipientPublicKeys) == 0 {
		return
	}

	go s.fanout(ev, recipientPublicKeys)
}

func (s *PushService) fanout(ev *event.Event, recipientPublicKeys []string) {
	// given: determine which category this event belongs to
	category, ok := CategoryForEventType(string(ev.Type))
	if !ok {
		log.Debug().
			Str("eventId", ev.ID).
			Str("type", string(ev.Type)).
			Msg("[PUSH] Event type has no push category, skipping")
		return
	}

	// when: fetch all subscriptions for the recipients
	subs, err := s.repo.GetSubscriptionsForUsers(recipientPublicKeys)
	if err != nil {
		log.Warn().Err(err).Str("eventId", ev.ID).Msg("[PUSH] Failed to fetch subscriptions")
		return
	}
	if len(subs) == 0 {
		return
	}

	// Build the push payload once - same JSON for every subscriber.
	payload, err := buildPayload(ev)
	if err != nil {
		log.Warn().Err(err).Str("eventId", ev.ID).Msg("[PUSH] Failed to build payload")
		return
	}

	// Cache VAPID keys per owner to avoid repeated DB round-trips when one user
	// has multiple subscriptions.
	vapidCache := make(map[string]*VapidKey)

	// then: deliver to each matching subscription
	for _, sub := range subs {
		if !sub.Categories.Has(category) {
			continue
		}

		vapid, cached := vapidCache[sub.UserPublicKey]
		if !cached {
			vapid, err = s.repo.GetVapidKey(sub.UserPublicKey)
			if err != nil {
				log.Warn().Err(err).
					Str("userPublicKey", sub.UserPublicKey).
					Msg("[PUSH] Failed to fetch VAPID key")
				continue
			}
			vapidCache[sub.UserPublicKey] = vapid
		}

		if vapid == nil {
			log.Debug().
				Str("userPublicKey", sub.UserPublicKey).
				Str("subscriptionId", sub.ID).
				Msg("[PUSH] No VAPID key for user - skipping subscription")
			continue
		}

		s.deliver(sub, vapid, payload)
	}
}

// deliver sends one push and updates subscription health fields based on the result.
func (s *PushService) deliver(sub *Subscription, vapid *VapidKey, payload []byte) {
	result := s.sender.Send(sub, vapid, payload)

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
		if err := s.repo.DeleteSubscription(sub.ID, sub.UserPublicKey); err != nil {
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

// pushPayload is the wire shape sent to the browser - matches the WebSocket event wire format.
type pushPayload struct {
	EventID       string                 `json:"eventId"`
	Type          string                 `json:"type"`
	ApplicationID string                 `json:"applicationId"`
	Data          map[string]interface{} `json:"data"`
	Timestamp     int64                  `json:"timestamp"`
}

func buildPayload(ev *event.Event) ([]byte, error) {
	p := pushPayload{
		EventID:       ev.ID,
		Type:          string(ev.Type),
		ApplicationID: ev.ApplicationID,
		Data:          ev.Data,
		Timestamp:     ev.CreatedAt,
	}
	return json.Marshal(p)
}
