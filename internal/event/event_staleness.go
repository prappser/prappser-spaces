package event

import (
	"errors"
	"fmt"
	"time"
)

// ErrStaleEvent means a destructive event's client mint time is older than
// staleDestructiveWindowSeconds. AcceptEvent rejects it before persisting.
var ErrStaleEvent = errors.New("stale event")

// destructiveEventTypes are the event types checked for staleness. Their
// effect is not safely mergeable after the fact (unlike component_data_changed,
// which merges per key, or application_after_edit_mode_changed, which
// batches offline layout work and is deliberately excluded here).
var destructiveEventTypes = map[EventType]bool{
	EventTypeApplicationDeleted:     true,
	EventTypeMemberRemoved:          true,
	EventTypeMemberRoleChanged:      true,
	EventTypeInviteRevoked:          true,
	EventTypeApplicationFileDeleted: true,
}

// staleDestructiveWindowSeconds has its own constant rather than reusing
// retentionDays: the two answer different questions, and sharing them would
// mean raising retention for forensics silently widens this gate and
// re-accepts an old delete.
const staleDestructiveWindowSeconds = 30 * 24 * 60 * 60 // 30 days

// msEpochFloor separates a seconds epoch from a milliseconds one: any real
// "now" in seconds stays under this for millennia, while a real "now" in
// milliseconds has been over it since 2001.
const msEpochFloor = 10_000_000_000

// normalizeMintedAt converts a client-minted createdAt to whole seconds.
// Clients mint milliseconds; the server stores (and compares) seconds.
func normalizeMintedAt(mintedAt int64) int64 {
	if mintedAt > msEpochFloor {
		return mintedAt / 1000
	}
	return mintedAt
}

// checkEventStaleness rejects a destructive event whose normalized mint time
// is older than the staleness window. mintedAt == 0 (client omitted
// createdAt) always accepts, and non-destructive types are never gated.
func checkEventStaleness(eventType EventType, mintedAt int64, now time.Time) error {
	if mintedAt == 0 || !destructiveEventTypes[eventType] {
		return nil
	}
	age := now.Unix() - normalizeMintedAt(mintedAt)
	if age > staleDestructiveWindowSeconds {
		return fmt.Errorf("%w: %s minted %ds ago exceeds the %ds staleness window", ErrStaleEvent, eventType, age, staleDestructiveWindowSeconds)
	}
	return nil
}
