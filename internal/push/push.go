package push

import (
	"github.com/prappser/prappser-spaces/internal/event"
)

// SpaceVapid holds the space-level VAPID keypair for signing web push messages.
// The singleton row always has id = 1 (enforced by a CHECK constraint in the DB).
type SpaceVapid struct {
	VapidPublicKey  string
	VapidPrivateKey string
	CreatedAt       int64
	UpdatedAt       int64
}

// Categories controls which buckets of events trigger a push for a subscription.
// Unknown keys are treated as false (forward-compatible).
type Categories struct {
	Member   bool `json:"member"`
	Edit     bool `json:"edit"`
	Reminder bool `json:"reminder"`
}

// Has returns true if the named category is enabled.
// Unknown names always return false.
func (c Categories) Has(name string) bool {
	switch name {
	case "member":
		return c.Member
	case "edit":
		return c.Edit
	case "reminder":
		return c.Reminder
	default:
		return false
	}
}

// Subscription represents a browser PushSubscription registered by a device.
type Subscription struct {
	ID                  string
	DevicePublicKey     string
	Endpoint            string
	P256dh              string
	Auth                string
	DeviceLabel         *string
	Categories          Categories
	MutedApplicationIDs []string
	CreatedAt           int64
	LastSuccessAt       *int64
	FailureCount        int
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
	Send(sub *Subscription, vapid *SpaceVapid, payloadJSON []byte) SendResult
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

// CategoryForEventType maps an event type string to its push category name.
// Returns ("", false) for event types that should not trigger any push notification.
//
// Category buckets:
//   - "member":   member lifecycle events
//   - "edit":     application content-change events
//   - "reminder": timer-fired notifications
//
// No-push types: application_created, user_settings_changed, application_deleted
// (application_created is already covered by onboarding UX; the others have no meaningful push story)
//
// reminder_changed (editing a rule) is edit noise, not a notification, so it
// deliberately has no category here - only reminder_fired pushes.
func CategoryForEventType(eventType string) (categoryName string, ok bool) {
	switch event.EventType(eventType) {
	case event.EventTypeMemberAdded,
		event.EventTypeMemberRemoved,
		event.EventTypeMemberRoleChanged,
		event.EventTypeInviteRevoked:
		return "member", true

	case event.EventTypeApplicationDataChanged,
		event.EventTypeApplicationFileCreated,
		event.EventTypeApplicationFileDeleted,
		event.EventTypeComponentDataChanged,
		event.EventTypeApplicationAfterEditModeChanged:
		return "edit", true

	case event.EventTypeReminderFired:
		return "reminder", true

	default:
		// application_created, user_settings_changed, application_deleted,
		// member_details_changed, reminder_changed, and any future unknown
		// types: no push.
		return "", false
	}
}
