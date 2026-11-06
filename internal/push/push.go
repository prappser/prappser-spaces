package push

import (
	webpush "github.com/SherClockHolmes/webpush-go"

	"github.com/prappser/prappser-spaces/internal/user"
)

type Kind string

const (
	KindChat     Kind = "chat"
	KindItem     Kind = "item"
	KindPoll     Kind = "poll"
	KindFile     Kind = "file"
	KindMember   Kind = "member"
	KindRole     Kind = "role"
	KindReminder Kind = "reminder"
)

// SendOptions are the per-message push service headers.
type SendOptions struct {
	Urgency webpush.Urgency
	TTL     int
	Topic   string
}

// SpaceVapid holds the space-level VAPID keypair for signing web push messages.
// The singleton row always has id = 1 (enforced by a CHECK constraint in the DB).
type SpaceVapid struct {
	VapidPublicKey  string
	VapidPrivateKey string
	CreatedAt       int64
	UpdatedAt       int64
}

func (k Kind) sendsIn(mode string) bool {
	return mode != user.NotifyModeChat || k == KindChat || k == KindReminder || k == KindRole
}

// Subscription represents a browser PushSubscription registered by a device.
type Subscription struct {
	ID                  string
	DevicePublicKey     string
	Endpoint            string
	P256dh              string
	Auth                string
	DeviceLabel         *string
	MutedApplicationIDs []string
	CreatedAt           int64
	LastSuccessAt       *int64
	FailureCount        int
	// Locale is the owning account's language, filled only by GetSubscriptionsForUsers.
	Locale string
	// NotifyMode is the owning account's notify mode, filled only by GetSubscriptionsForUsers.
	NotifyMode string
}

// SendResult is the outcome of a single web push delivery attempt.
type SendResult struct {
	// StatusCode is the HTTP response status from the push service.
	// Zero when Err is set due to a transport failure before a response was received.
	StatusCode int
	// Err is non-nil for transport-level failures (no HTTP response received).
	Err error
}

// WebpushSender is the delivery interface used by PushService.
// It is defined here as the seam for unit-testing fanout without hitting real push services.
// No context parameter: HTTPWebpushSender builds its own 10-second timeout context internally,
// so the parameter was unused and misleading.
type WebpushSender interface {
	Send(sub *Subscription, vapid *SpaceVapid, payloadJSON []byte, opts SendOptions) SendResult
}

// PushRepository is the data-access interface for space_vapid and push_subscriptions.
// The concrete implementation is in push_repository.go.
type PushRepository interface {
	UpsertSpaceVapid(v *SpaceVapid) error
	GetSpaceVapid() (*SpaceVapid, error)
	CreateSubscription(s *Subscription) error
	UpdateSubscription(s *Subscription) error
	DeleteSubscription(id, devicePublicKey string) error
	// GetSubscriptionsForUsers takes ACCOUNT keys (not device keys) and joins
	// through user_devices to every non-revoked device of those accounts.
	GetSubscriptionsForUsers(userPublicKeys []string) ([]*Subscription, error)
	GetSubscriptionByID(id, devicePublicKey string) (*Subscription, error)
	MarkSuccess(id string, ts int64) error
	IncrementFailure(id string) error
}
