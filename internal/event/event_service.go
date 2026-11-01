package event

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
)

// EventBroadcaster broadcasts events to connected WebSocket clients
type EventBroadcaster interface {
	BroadcastToApplication(applicationID string, event *Event)
	BroadcastToUser(userPublicKey string, event *Event)
}

// EventPusher delivers web push notifications to offline members after fanout.
// Defined here to avoid an import cycle: push imports event, so event cannot import push.
// push.PushService satisfies this interface by signature.
type EventPusher interface {
	Push(event *Event, appName string, creatorDisplayName string, recipientPublicKeys []string)
}

// ReminderStore applies a reminder_changed rule update to the reminder
// table. Declared here (not in internal/reminder) and injected the same way
// as appRepo: internal/reminder imports internal/event for its wire types,
// so event cannot import reminder back without a cycle.
type ReminderStore interface {
	ApplyRuleChange(ctx context.Context, data *ReminderChangedData) error
}

type EventService struct {
	repo          *EventRepository
	appRepo       application.ApplicationRepository
	broadcaster   EventBroadcaster
	pusher        EventPusher   // optional; nil disables web push
	reminderStore ReminderStore // optional; nil disables reminder_changed execution
}

func NewEventService(repo *EventRepository, appRepo application.ApplicationRepository, broadcaster EventBroadcaster, pusher EventPusher) *EventService {
	return &EventService{
		repo:        repo,
		appRepo:     appRepo,
		broadcaster: broadcaster,
		pusher:      pusher,
	}
}

// SetReminderStore wires the reminder store after construction, mirroring
// how main.go builds these services: EventService is constructed before
// reminder.NewRepository(db) needs a *sql.DB that isn't relevant to the rest
// of EventService's dependencies.
func (s *EventService) SetReminderStore(store ReminderStore) {
	s.reminderStore = store
}

func (s *EventService) AcceptEvent(ctx context.Context, event *Event, submitter *user.User) (*Event, error) {
	log.Debug().
		Str("eventId", event.ID).
		Str("type", string(event.Type)).
		Str("submitter", submitter.Username).
		Msg("[EVENT] Received from client")

	if err := ValidateEvent(event); err != nil {
		log.Debug().
			Str("eventId", event.ID).
			Err(err).
			Msg("[EVENT] Validation failed")
		return nil, fmt.Errorf("validation failed: %w", err)
	}
	log.Debug().Str("eventId", event.ID).Msg("[EVENT] Validation passed")

	if !IsUserScoped(event.Type) {
		appID, ok := event.Data["applicationId"].(string)
		if !ok || appID == "" {
			return nil, fmt.Errorf("%w: applicationId not found in event data", ErrValidation)
		}
		event.ApplicationID = appID
	}

	// A retry must not be re-authorized against the state its first attempt changed.
	existing, err := s.repo.GetByID(event.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to check for duplicate event: %w", err)
	}
	if isRetryOf(existing, event.ApplicationID, submitter.PublicKey, event.Type) {
		log.Debug().Str("eventId", event.ID).Msg("[EVENT] Duplicate, returning stored event")
		return existing, nil
	}

	// User-scoped events bypass application lookup and use a separate authorization path
	if IsUserScoped(event.Type) {
		return s.acceptUserScopedEvent(ctx, event, submitter)
	}

	// Set space ID from submitter's JWT claims
	event.SpaceID = submitter.SpaceID

	// ponytail: the guard isn't atomic with the insert, so an event racing CompleteMove can land on the tombstone (hidden, purged with it); row-lock if that matters.
	if err := s.appRepo.MoveGuard(event.ApplicationID, submitter.PublicKey, true); err != nil {
		return nil, err
	}

	app, err := s.appRepo.GetApplicationByID(event.ApplicationID)
	if errors.Is(err, application.ErrNotFound) {
		return nil, fmt.Errorf("%w: %w", ErrUnappliable, err)
	}
	if err != nil {
		return nil, fmt.Errorf("application not found: %w", err)
	}

	if err := AuthorizeEvent(event, submitter, app); err != nil {
		log.Debug().
			Str("eventId", event.ID).
			Err(err).
			Msg("[EVENT] Authorization failed")
		return nil, fmt.Errorf("authorization failed: %w", err)
	}
	log.Debug().Str("eventId", event.ID).Msg("[EVENT] Authorization passed")

	// event.CreatedAt still holds the client's mint time here; checked
	// against the submitter's own clock before it's overwritten below.
	if err := checkEventStaleness(event.Type, event.CreatedAt, time.Now()); err != nil {
		log.Debug().
			Str("eventId", event.ID).
			Str("type", string(event.Type)).
			Int64("mintedAt", event.CreatedAt).
			Msg("[EVENT] Rejected as stale")
		return nil, err
	}

	stored, dup, err := s.persistAndApply(ctx, event, true)
	if err != nil {
		return nil, err
	}
	if dup {
		return stored, nil
	}

	log.Debug().
		Str("eventId", event.ID).
		Str("type", string(event.Type)).
		Int64("sequence", event.SequenceNumber).
		Msg("[EVENT] Accepted successfully")

	// Broadcast to WebSocket clients
	s.broadcastEvent(stored)

	return stored, nil
}

// acceptUserScopedEvent handles the user-scoped event path (no application context).
func (s *EventService) acceptUserScopedEvent(ctx context.Context, event *Event, submitter *user.User) (*Event, error) {
	if err := AuthorizeUserScopedEvent(event, submitter); err != nil {
		log.Debug().
			Str("eventId", event.ID).
			Err(err).
			Msg("[EVENT] Authorization failed")
		return nil, fmt.Errorf("authorization failed: %w", err)
	}
	log.Debug().Str("eventId", event.ID).Msg("[EVENT] Authorization passed")

	// Set space ID from submitter's JWT claims
	event.SpaceID = submitter.SpaceID

	stored, dup, err := s.persistAndApply(ctx, event, false)
	if err != nil {
		return nil, err
	}
	if dup {
		return stored, nil
	}

	log.Debug().
		Str("eventId", event.ID).
		Str("type", string(event.Type)).
		Msg("[EVENT] User-scoped event accepted successfully")

	if s.broadcaster != nil {
		s.broadcaster.BroadcastToUser(stored.CreatorPublicKey, stored)
	}

	return stored, nil
}

// ProduceEvent creates an event without authorization checks.
// Used for space-generated events where the action was already validated by the endpoint.
// The event is sequenced, persisted, and executed but authorization is skipped.
func (s *EventService) ProduceEvent(ctx context.Context, event *Event) (*Event, error) {
	log.Debug().
		Str("eventId", event.ID).
		Str("type", string(event.Type)).
		Msg("[EVENT] Space-produced event received")

	if err := ValidateEvent(event); err != nil {
		log.Debug().
			Str("eventId", event.ID).
			Err(err).
			Msg("[EVENT] Validation failed")
		return nil, fmt.Errorf("validation failed: %w", err)
	}
	log.Debug().Str("eventId", event.ID).Msg("[EVENT] Validation passed")

	// User-scoped events have no application context or sequence number.
	// Exception: if ApplicationID is explicitly set, treat as app-scoped (e.g. fan-out from avatar upload).
	if IsUserScoped(event.Type) && event.ApplicationID == "" {
		return s.produceUserScopedEvent(ctx, event)
	}

	appID, ok := event.Data["applicationId"].(string)
	if !ok || appID == "" {
		return nil, fmt.Errorf("%w: applicationId not found in event data", ErrValidation)
	}

	// Set ApplicationID field from data
	event.ApplicationID = appID

	stored, dup, err := s.persistAndApply(ctx, event, true)
	if err != nil {
		return nil, err
	}
	if dup {
		return stored, nil
	}

	log.Debug().
		Str("eventId", event.ID).
		Str("type", string(event.Type)).
		Int64("sequence", event.SequenceNumber).
		Msg("[EVENT] Space-produced event accepted successfully")

	// Broadcast to WebSocket clients
	s.broadcastEvent(stored)

	return stored, nil
}

// produceUserScopedEvent handles the user-scoped path for space-produced events.
func (s *EventService) produceUserScopedEvent(ctx context.Context, event *Event) (*Event, error) {
	stored, dup, err := s.persistAndApply(ctx, event, false)
	if err != nil {
		return nil, err
	}
	if dup {
		return stored, nil
	}

	log.Debug().
		Str("eventId", event.ID).
		Str("type", string(event.Type)).
		Msg("[EVENT] Server-produced user-scoped event accepted successfully")

	if s.broadcaster != nil {
		s.broadcaster.BroadcastToUser(stored.CreatorPublicKey, stored)
	}

	return stored, nil
}

// applyErr marks err ErrUnappliable only when no retry can succeed.
func applyErr(err error) error {
	if err == nil || errors.Is(err, ErrUnappliable) || isTransient(err) {
		return err
	}
	if errors.Is(err, ErrValidation) || isDataErr(err) {
		return fmt.Errorf("%w: %w", ErrUnappliable, err)
	}
	return err
}

func isTransient(err error) bool {
	var netErr net.Error
	if errors.Is(err, driver.ErrBadConn) || errors.Is(err, sql.ErrConnDone) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &netErr) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) {
		return false
	}
	switch pqErr.Code.Class() {
	case "08", "53", "57":
		return true
	}
	switch pqErr.Code {
	case "40001", "40P01", "55P03":
		return true
	}
	return false
}

func isDataErr(err error) bool {
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) {
		return false
	}
	switch pqErr.Code.Class() {
	case "22", "23":
		// A duplicate events_pkey stays retryable: the retry dedupes.
		return pqErr.Code != "23505" || pqErr.Constraint != "events_pkey"
	}
	return false
}

func isRetryOf(stored *Event, appID, creator string, t EventType) bool {
	return stored != nil && stored.ApplicationID == appID && stored.CreatorPublicKey == creator && stored.Type == t
}

func (s *EventService) persistAndApply(ctx context.Context, event *Event, sequenced bool) (stored *Event, dup bool, err error) {
	defer func() {
		err = applyErr(err)
		if err != nil {
			log.Debug().Str("eventId", event.ID).Err(err).Msg("[EVENT] Rejected, nothing persisted")
		}
	}()

	// A bare *fasthttp.RequestCtx (tests, background callers) panics in Done().
	ctx = context.WithoutCancel(ctx)
	tx, err := s.repo.conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("failed to begin event transaction: %w", err)
	}
	defer tx.Rollback()

	txs := *s
	txs.repo = s.repo.withTx(tx)
	if s.appRepo != nil {
		txs.appRepo = s.appRepo.WithTx(tx)
	}

	if sequenced {
		// ponytail: the reminder scheduler holds a reminder row lock while it calls
		// ProduceEvent, and a component delete under this app lock cascades into that
		// row. The cycle passes through Go so Postgres can't see it; the timeout breaks
		// it and both sides retry (client on 5xx, scheduler row stays pending).
		if _, err := tx.ExecContext(ctx, `SET LOCAL lock_timeout = '5s'`); err != nil {
			return nil, false, fmt.Errorf("failed to set lock timeout: %w", err)
		}
		var deleted bool
		err := tx.QueryRowContext(ctx, `SELECT deleted_at IS NOT NULL FROM applications WHERE id = $1 FOR NO KEY UPDATE`, event.ApplicationID).Scan(&deleted)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && deleted && event.Type != EventTypeApplicationMoved) {
			return nil, false, fmt.Errorf("%w: application %s not found", ErrUnappliable, event.ApplicationID)
		}
		if err != nil {
			return nil, false, fmt.Errorf("failed to lock application: %w", err)
		}
	}

	existing, err := txs.repo.GetByID(event.ID)
	if err != nil {
		return nil, false, fmt.Errorf("failed to check for duplicate event: %w", err)
	}
	if isRetryOf(existing, event.ApplicationID, event.CreatorPublicKey, event.Type) {
		log.Debug().Str("eventId", event.ID).Msg("[EVENT] Duplicate, returning stored event")
		return existing, true, nil
	}
	if existing != nil {
		return nil, false, fmt.Errorf("%w: event id %s is already used by another event", ErrUnappliable, event.ID)
	}

	event.SequenceNumber = 0
	if sequenced {
		seq, err := txs.repo.GetNextSequence(event.ApplicationID)
		if err != nil {
			return nil, false, fmt.Errorf("sequence generation failed: %w", err)
		}
		event.SequenceNumber = seq
	}
	event.CreatedAt = time.Now().Unix()

	log.Debug().
		Str("eventId", event.ID).
		Int64("sequence", event.SequenceNumber).
		Msg("[EVENT] Persisting to database")

	if err := txs.repo.Create(event); err != nil {
		log.Error().
			Str("eventId", event.ID).
			Err(err).
			Msg("[EVENT] Persistence failed")
		return nil, false, fmt.Errorf("persistence failed: %w", err)
	}

	if err := txs.executeEvent(ctx, event); err != nil {
		return nil, false, fmt.Errorf("execution failed: %w", err)
	}
	log.Debug().
		Str("eventId", event.ID).
		Str("type", string(event.Type)).
		Msg("[EVENT] Execution complete")

	if sequenced {
		txs.updateAppVersion(event)
	}

	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("failed to commit event: %w", err)
	}
	return event, false, nil
}

// explicitRecipientEventTypes is the allowlist of event types whose
// data.recipients is trusted as the exact push list, instead of "all
// members except creator". It must stay an explicit allowlist keyed on
// event.Type, never "does event.Data contain a recipients key": most
// validators in event_validator.go (e.g. validateComponentDataChangedData)
// deliberately accept unknown data keys, since they trust client data for
// everything else those event types carry. Without this allowlist, any
// member could submit e.g. a component_data_changed with a forged
// "recipients" key to suppress push to the real members or aim push at a
// public key that isn't even a member of the app (GetSubscriptionsForUsers
// doesn't check membership - it just resolves whatever keys it's given).
var explicitRecipientEventTypes = map[EventType]bool{
	EventTypeReminderFired: true,
}

func isUserChannelFanout(t EventType) bool {
	return t == EventTypeApplicationDeleted || t == EventTypeApplicationMoved
}

// broadcastEvent sends an event to all relevant WebSocket clients and queues web push
// notifications for offline members.
// For application_deleted and application_moved events, it additionally broadcasts to each
// member's user channel so all devices receive them regardless of which app they have focused.
func (s *EventService) broadcastEvent(event *Event) {
	if s.broadcaster != nil {
		s.broadcaster.BroadcastToApplication(event.ApplicationID, event)
	}

	// Fetch members once and share between the deletion fanout and push fanout.
	// A failed fetch is non-fatal: log a warning and skip the member-dependent paths.
	var members []*application.Member
	if event.ApplicationID != "" && (isUserChannelFanout(event.Type) || s.pusher != nil) {
		var err error
		members, err = s.appRepo.GetMembersByApplicationID(event.ApplicationID)
		if err != nil {
			log.Warn().Err(err).Str("applicationId", event.ApplicationID).Msg("[EVENT] Failed to get members for broadcast")
		}
	}

	// application_deleted/application_moved: also broadcast to each member's user
	// channel so all devices receive them regardless of which app they have open.
	if isUserChannelFanout(event.Type) && s.broadcaster != nil {
		for _, member := range members {
			s.broadcaster.BroadcastToUser(member.PublicKey, event)
		}
	}

	// Web push: notify the explicit recipient list if the event's type is
	// allowlisted for it (e.g. reminder_fired, targeted at whoever the
	// client assigned the reminder to - not "all members"), otherwise all
	// members except the event creator. The allowlisted events are
	// space-produced, so CreatorPublicKey is the space's own key and would
	// never match a member's, meaning recipients would reach everyone if the
	// code fell through to the default branch.
	if s.pusher != nil && event.ApplicationID != "" {
		var recipientKeys []string
		if explicitRecipientEventTypes[event.Type] {
			recipientKeys = extractRecipients(event.Data)
		}
		if len(recipientKeys) == 0 {
			recipientKeys = make([]string, 0, len(members))
			for _, member := range members {
				if member.PublicKey != event.CreatorPublicKey {
					recipientKeys = append(recipientKeys, member.PublicKey)
				}
			}
		}

		if len(recipientKeys) > 0 {
			// Look up the application name so the browser SW can title notifications.
			// On error or nil result, fall back to empty string; the client falls back to "Prappser".
			appName := ""
			app, err := s.appRepo.GetApplicationByID(event.ApplicationID)
			if err != nil {
				log.Debug().Err(err).Str("applicationId", event.ApplicationID).Msg("[EVENT] Failed to get application name for push")
			} else if app != nil {
				appName = app.Name
			}

			// Resolve the actor's display name from the already-fetched members slice.
			// No additional DB call needed. Empty string if not found or name is nil.
			creatorDisplayName := ""
			for _, m := range members {
				if m.PublicKey == event.CreatorPublicKey && m.UserDisplayName != nil {
					creatorDisplayName = *m.UserDisplayName
					break
				}
			}

			s.pusher.Push(event, appName, creatorDisplayName, recipientKeys)
		}
	}
}

// ProduceApplicationMoved records that an application finished moving to another space.
func (s *EventService) ProduceApplicationMoved(ctx context.Context, appID, creatorPublicKey, targetSpaceURL, inviteToken string) error {
	id, err := uuid.NewV7()
	if err != nil {
		id = uuid.New()
	}
	data, err := MarshalData(&ApplicationMovedData{
		Version:        1,
		ApplicationID:  appID,
		TargetSpaceURL: targetSpaceURL,
		InviteToken:    inviteToken,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal application_moved data: %w", err)
	}
	_, err = s.ProduceEvent(ctx, &Event{
		ID:               id.String(),
		Type:             EventTypeApplicationMoved,
		CreatorPublicKey: creatorPublicKey,
		ApplicationID:    appID,
		Version:          1,
		Data:             data,
	})
	return err
}

// GetEventsSince retrieves events since a given event ID for the authenticated user's applications
func (s *EventService) GetEventsSince(userPublicKey string, sinceEventID string, limit int) (*EventsResponse, error) {
	events, hasMore, err := s.repo.GetSince(userPublicKey, sinceEventID, limit)
	if err != nil {
		if errors.Is(err, ErrCursorNotFound) {
			return &EventsResponse{
				FullResyncRequired: true,
				Reason:             "Events expired or gap detected",
				AppVersions:        s.loadAppVersions(userPublicKey),
			}, nil
		}
		return nil, fmt.Errorf("failed to get events: %w", err)
	}

	// Only include app versions when the client is caught up (no more pages).
	// This avoids a DB query on every poll tick while the client is still paging through events.
	var appVersions map[string]AppVersion
	if !hasMore {
		appVersions = s.loadAppVersions(userPublicKey)
	}

	return &EventsResponse{
		Events:      events,
		HasMore:     hasMore,
		AppVersions: appVersions,
	}, nil
}

// loadAppVersions fetches the last sequence number for all apps the user is a member of.
// Uses a lightweight query (id, last_sequence only) to avoid N+1 full-app loads.
func (s *EventService) loadAppVersions(userPublicKey string) map[string]AppVersion {
	appVersions, err := s.appRepo.GetAppVersionsByMemberPublicKey(userPublicKey)
	if err != nil {
		log.Warn().Err(err).Str("userPublicKey", userPublicKey).Msg("[EVENT] Failed to load app versions for poll response")
		return nil
	}
	if len(appVersions) == 0 {
		return nil
	}
	result := make(map[string]AppVersion, len(appVersions))
	for appID, info := range appVersions {
		if info.LastSequence != nil {
			result[appID] = AppVersion{
				LastSequence: *info.LastSequence,
			}
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// updateAppVersion persists the last processed sequence number for an app-scoped event.
// Errors are logged but do not fail the event pipeline.
func (s *EventService) updateAppVersion(event *Event) {
	if event.ApplicationID == "" {
		return
	}
	if err := s.appRepo.UpdateLastSequence(event.ApplicationID, event.SequenceNumber); err != nil {
		log.Error().
			Str("eventId", event.ID).
			Str("applicationId", event.ApplicationID).
			Err(err).
			Msg("[EVENT] Failed to update app version")
	}
}

// CleanupOldEvents deletes events older than the retention period (7 days)
func (s *EventService) CleanupOldEvents(retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		retentionDays = 7 // Default 7 days
	}

	cutoffTime := time.Now().AddDate(0, 0, -retentionDays).Unix()
	return s.repo.DeleteOlderThan(cutoffTime)
}

// executeEvent executes an event by updating the database state
func (s *EventService) executeEvent(ctx context.Context, event *Event) error {
	log.Debug().
		Str("eventId", event.ID).
		Str("type", string(event.Type)).
		Msg("[EVENT] Dispatching to handler")

	switch event.Type {
	case "member_added":
		log.Debug().Str("eventId", event.ID).Msg("[EVENT] Handler: member_added")
		return s.executeMemberAdded(ctx, event)
	case "member_removed":
		log.Debug().Str("eventId", event.ID).Msg("[EVENT] Handler: member_removed")
		return s.executeMemberRemoved(ctx, event)
	case EventTypeApplicationDeleted:
		log.Debug().Str("eventId", event.ID).Msg("[EVENT] Handler: application_deleted")
		return s.executeApplicationDeleted(ctx, event)
	case "member_role_changed":
		log.Debug().Str("eventId", event.ID).Msg("[EVENT] Handler: member_role_changed")
		return s.executeMemberRoleChanged(ctx, event)
	case "component_data_changed":
		log.Debug().Str("eventId", event.ID).Msg("[EVENT] Handler: component_data_changed")
		return s.executeComponentDataChanged(ctx, event)
	case "application_after_edit_mode_changed":
		log.Debug().Str("eventId", event.ID).Msg("[EVENT] Handler: application_after_edit_mode_changed")
		return s.executeApplicationAfterEditModeChanged(ctx, event)
	case EventTypeReminderChanged:
		log.Debug().Str("eventId", event.ID).Msg("[EVENT] Handler: reminder_changed")
		return s.executeReminderChanged(ctx, event)
	case EventTypeReminderFired:
		// Delivery already happened via broadcastEvent/ProduceEvent; the fired
		// event carries no database state to update on its own.
		log.Debug().Str("eventId", event.ID).Msg("[EVENT] Handler: reminder_fired (no-op)")
		return nil
	case "user_settings_changed":
		log.Debug().Str("eventId", event.ID).Msg("[EVENT] Handler: user_settings_changed")
		return s.executeUserSettingsChanged(event)
	case EventTypeSpaceProfileChanged:
		log.Debug().Str("eventId", event.ID).Msg("[EVENT] Handler: space_profile_changed (no-op)")
		return nil
	case "member_details_changed":
		// Future: update member record
		log.Debug().Str("eventId", event.ID).Msg("[EVENT] Handler: member_details_changed (no-op)")
		return nil
	case EventTypeApplicationDataChanged:
		log.Debug().Str("eventId", event.ID).Msg("[EVENT] Handler: application_data_changed")
		return s.executeApplicationDataChanged(ctx, event)
	case "application_created":
		// No server-side state change: application was already registered by the creator device
		log.Debug().Str("eventId", event.ID).Msg("[EVENT] Handler: application_created (no-op)")
		return nil
	case EventTypeApplicationFileCreated, EventTypeApplicationFileDeleted:
		// Storage already managed by storage service; event is for client sync only
		log.Debug().Str("eventId", event.ID).Msg("[EVENT] Handler: application_file event (no-op)")
		return nil
	default:
		// Unknown event types are not executed (forward compatibility)
		log.Debug().
			Str("eventId", event.ID).
			Str("type", string(event.Type)).
			Msg("[EVENT] Unknown event type - skipping execution (forward compatibility)")
		return nil
	}
}

// executeMemberAdded creates a member record in the database
func (s *EventService) executeMemberAdded(ctx context.Context, event *Event) error {
	appID, ok := event.Data["applicationId"].(string)
	if !ok || appID == "" {
		return fmt.Errorf("missing applicationId in member_added event")
	}

	memberPublicKey, ok := event.Data["memberPublicKey"].(string)
	if !ok || memberPublicKey == "" {
		return fmt.Errorf("missing memberPublicKey in member_added event")
	}

	roleStr, _ := event.Data["role"].(string)

	member := &application.Member{
		ID:                  uuid.New().String(),
		ApplicationID:       appID,
		Role:                application.MemberRole(roleStr),
		PublicKey:           memberPublicKey,
		MembershipExpiresAt: getInt64Ptr(event.Data, "membershipExpiresAt"),
	}

	return s.appRepo.CreateMember(member)
}

// executeMemberRemoved deletes a member record from the database
func (s *EventService) executeMemberRemoved(ctx context.Context, event *Event) error {
	appID, ok := event.Data["applicationId"].(string)
	if !ok || appID == "" {
		return fmt.Errorf("missing applicationId in member_removed event")
	}

	memberPublicKey, ok := event.Data["memberPublicKey"].(string)
	if !ok || memberPublicKey == "" {
		return fmt.Errorf("missing memberPublicKey in member_removed event")
	}
	short := memberPublicKey[:min(20, len(memberPublicKey))] + "..."

	log.Debug().
		Str("applicationId", appID).
		Str("memberPublicKey", short).
		Msg("[MEMBER_REMOVED] Executing member_removed event - looking up member")

	// Get member by publicKey to get the member ID
	member, err := s.appRepo.GetMemberByPublicKey(appID, memberPublicKey)
	if errors.Is(err, application.ErrNotFound) {
		log.Debug().
			Str("applicationId", appID).
			Str("memberPublicKey", short).
			Msg("[MEMBER_REMOVED] Member already gone, nothing to delete")
		return nil
	}
	if err != nil {
		log.Error().
			Str("applicationId", appID).
			Str("memberPublicKey", short).
			Err(err).
			Msg("[MEMBER_REMOVED] Failed to find member for deletion")
		return fmt.Errorf("member not found: %w", err)
	}

	log.Debug().
		Str("applicationId", appID).
		Str("memberId", member.ID).
		Str("memberPublicKey", short).
		Msg("[MEMBER_REMOVED] Found member, deleting from database")

	// Delete member by ID
	if err := s.appRepo.DeleteMember(member.ID); err != nil {
		log.Error().
			Str("applicationId", appID).
			Str("memberId", member.ID).
			Err(err).
			Msg("[MEMBER_REMOVED] Failed to delete member from database")
		return err
	}

	log.Info().
		Str("applicationId", appID).
		Str("memberId", member.ID).
		Str("memberPublicKey", short).
		Msg("[MEMBER_REMOVED] Successfully deleted member from database")

	return nil
}

// executeApplicationDataChanged updates application name and icon
func (s *EventService) executeApplicationDataChanged(ctx context.Context, event *Event) error {
	appID, ok := event.Data["applicationId"].(string)
	if !ok || appID == "" {
		return fmt.Errorf("missing applicationId in application_data_changed event")
	}

	name, ok := event.Data["name"].(string)
	if !ok || name == "" {
		return fmt.Errorf("missing name in application_data_changed event")
	}

	var icon *string
	if iconVal, ok := event.Data["icon"].(string); ok && iconVal != "" {
		icon = &iconVal
	}

	return s.appRepo.UpdateApplicationMetadata(appID, name, icon)
}

// executeUserSettingsChanged is a no-op on the server side — user identity (displayName, avatar)
// is stored on the User entity, not on Member. Clients derive member identity from User via events.
func (s *EventService) executeUserSettingsChanged(event *Event) error {
	return nil
}

// executeApplicationDeleted deletes an application (cascades to members, groups, components)
func (s *EventService) executeApplicationDeleted(ctx context.Context, event *Event) error {
	appID, ok := event.Data["applicationId"].(string)
	if !ok || appID == "" {
		return fmt.Errorf("missing applicationId in application_deleted event")
	}

	return s.appRepo.DeleteApplication(appID)
}

// executeMemberRoleChanged updates a member's role in the database
func (s *EventService) executeMemberRoleChanged(ctx context.Context, event *Event) error {
	appID, ok := event.Data["applicationId"].(string)
	if !ok || appID == "" {
		return fmt.Errorf("missing applicationId in member_role_changed event")
	}

	memberPublicKey, ok := event.Data["memberPublicKey"].(string)
	if !ok || memberPublicKey == "" {
		return fmt.Errorf("missing memberPublicKey in member_role_changed event")
	}

	newRole, ok := event.Data["newRole"].(string)
	if !ok || newRole == "" {
		return fmt.Errorf("missing newRole in member_role_changed event")
	}

	// Get member by publicKey
	member, err := s.appRepo.GetMemberByPublicKey(appID, memberPublicKey)
	if errors.Is(err, application.ErrNotFound) {
		return fmt.Errorf("%w: %w", ErrUnappliable, err)
	}
	if err != nil {
		return fmt.Errorf("member not found: %w", err)
	}

	// Update role
	return s.appRepo.UpdateMemberRole(member.ID, application.MemberRole(newRole))
}

// executeComponentDataChanged applies delta changes to a component's data
func (s *EventService) executeComponentDataChanged(ctx context.Context, event *Event) error {
	componentID, ok := event.Data["componentId"].(string)
	if !ok || componentID == "" {
		return fmt.Errorf("%w: missing componentId in component_data_changed event", ErrValidation)
	}

	changedFieldsRaw, ok := event.Data["changedFields"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("%w: missing changedFields in component_data_changed event", ErrValidation)
	}

	// Get current component
	component, err := s.componentInApp(event.ApplicationID, componentID)
	if err != nil {
		return err
	}

	// Apply delta: extract newValue from each field change
	if component.Data == nil {
		component.Data = make(map[string]interface{})
	}

	for fieldName, changeRaw := range changedFieldsRaw {
		change, ok := changeRaw.(map[string]interface{})
		if !ok {
			continue
		}
		// Apply newValue to component data
		component.Data[fieldName] = change["newValue"]
	}

	// Update component data in database
	return s.appRepo.UpdateComponentData(componentID, component.Data)
}

// executeReminderChanged applies a reminder_changed rule update to the
// reminder table via the injected ReminderStore. A nil store (no reminder
// package wired up, e.g. in tests that construct EventService directly) is
// a no-op rather than an error, so existing callers keep working unchanged.
func (s *EventService) executeReminderChanged(ctx context.Context, event *Event) error {
	if s.reminderStore == nil {
		log.Debug().Str("eventId", event.ID).Msg("[EVENT] No reminder store wired, skipping reminder_changed")
		return nil
	}

	var data ReminderChangedData
	if err := UnmarshalData(event.Data, &data); err != nil {
		return fmt.Errorf("%w: failed to unmarshal reminder_changed data: %w", ErrValidation, err)
	}

	return s.reminderStore.ApplyRuleChange(ctx, &data)
}

// executeApplicationAfterEditModeChanged applies a batch of structural changes
func (s *EventService) executeApplicationAfterEditModeChanged(ctx context.Context, event *Event) error {
	changesRaw, ok := event.Data["changes"].([]interface{})
	if !ok {
		return fmt.Errorf("missing changes in application_after_edit_mode_changed event")
	}

	appID := event.ApplicationID
	for i, changeRaw := range changesRaw {
		change, ok := changeRaw.(map[string]interface{})
		if !ok {
			return fmt.Errorf("%w: change %d is not an object", ErrValidation, i)
		}

		changeType, _ := change["changeType"].(string)
		entityID, _ := change["entityId"].(string)

		var err error
		switch changeType {
		case "component_added":
			err = s.executeComponentAdded(appID, change)
		case "component_removed":
			if _, err = s.componentInApp(appID, entityID); err == nil {
				err = s.appRepo.DeleteComponent(entityID)
			} else if errors.Is(err, ErrUnappliable) {
				err = nil
			}
		case "component_reordered":
			if _, err = s.componentInApp(appID, entityID); err == nil {
				err = s.appRepo.UpdateComponentIndex(entityID, getInt(change, "index"))
			}
		case "component_data_changed":
			err = s.executeComponentDataDelta(appID, entityID, change)
		case "component_group_added":
			err = s.executeComponentGroupAdded(appID, change)
		case "component_group_removed":
			if _, err = s.groupInApp(appID, entityID); err == nil {
				err = s.appRepo.DeleteComponentGroup(entityID)
			} else if errors.Is(err, ErrUnappliable) {
				err = nil
			}
		case "component_group_reordered":
			if _, err = s.groupInApp(appID, entityID); err == nil {
				err = s.appRepo.UpdateComponentGroupIndex(entityID, getInt(change, "index"))
			}
		case "component_group_changed":
			var group *application.ComponentGroup
			if group, err = s.groupInApp(appID, entityID); err == nil {
				data, _ := change["data"].(map[string]interface{})
				name, _ := data["name"].(string)
				if name == "" {
					name = group.Name
				}
				index := group.Index
				if n, ok := numberValue(data["index"]); ok {
					index = int(n)
				}
				err = s.appRepo.UpdateComponentGroup(entityID, name, index)
			}
		default:
			err = fmt.Errorf("%w: unknown change type %q", ErrValidation, changeType)
		}
		if err != nil {
			return fmt.Errorf("change %d (%s %s): %w", i, changeType, entityID, err)
		}
	}

	return nil
}

func (s *EventService) componentInApp(appID, id string) (*application.Component, error) {
	component, err := s.appRepo.GetComponentByID(id)
	if errors.Is(err, application.ErrNotFound) || (err == nil && component.ApplicationID != appID) {
		return nil, fmt.Errorf("%w: component %s not found", ErrUnappliable, id)
	}
	return component, err
}

func (s *EventService) groupInApp(appID, id string) (*application.ComponentGroup, error) {
	group, err := s.appRepo.GetComponentGroupByID(id)
	if errors.Is(err, application.ErrNotFound) || (err == nil && group.ApplicationID != appID) {
		return nil, fmt.Errorf("%w: component group %s not found", ErrUnappliable, id)
	}
	return group, err
}

func upsertTarget(appID string, data map[string]interface{}, lookupErr error, existingAppID func() string) error {
	if lookupErr != nil && !errors.Is(lookupErr, application.ErrNotFound) {
		return lookupErr
	}
	target := getString(data, "applicationId")
	if (target != "" && target != appID) || (lookupErr == nil && existingAppID() != appID) {
		return fmt.Errorf("%w: %s belongs to another application", ErrUnappliable, getString(data, "id"))
	}
	return nil
}

// executeComponentAdded creates a new component from change data
func (s *EventService) executeComponentAdded(appID string, change map[string]interface{}) error {
	data, ok := change["data"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("missing data for component_added")
	}

	existing, err := s.appRepo.GetComponentByID(getString(data, "id"))
	if err := upsertTarget(appID, data, err, func() string { return existing.ApplicationID }); err != nil {
		return err
	}
	if _, err := s.groupInApp(appID, getString(data, "componentGroupId")); err != nil {
		return err
	}

	component := &application.Component{
		ID:               getString(data, "id"),
		ComponentGroupID: getString(data, "componentGroupId"),
		ApplicationID:    appID,
		Name:             getString(data, "name"),
		Index:            getInt(data, "index"),
	}

	if componentData, ok := data["data"].(map[string]interface{}); ok {
		component.Data = componentData
	}

	return s.appRepo.CreateComponent(component)
}

// executeComponentGroupAdded creates a new component group from change data
func (s *EventService) executeComponentGroupAdded(appID string, change map[string]interface{}) error {
	data, ok := change["data"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("missing data for component_group_added")
	}

	existing, err := s.appRepo.GetComponentGroupByID(getString(data, "id"))
	if err := upsertTarget(appID, data, err, func() string { return existing.ApplicationID }); err != nil {
		return err
	}

	group := &application.ComponentGroup{
		ID:            getString(data, "id"),
		ApplicationID: appID,
		Name:          getString(data, "name"),
		Index:         getInt(data, "index"),
	}

	return s.appRepo.CreateComponentGroup(group)
}

// executeComponentDataDelta applies delta changes to a component from a structure change
func (s *EventService) executeComponentDataDelta(appID, componentID string, change map[string]interface{}) error {
	changedFieldsRaw, ok := change["changedFields"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("missing changedFields for component_data_changed")
	}

	// Get current component
	component, err := s.componentInApp(appID, componentID)
	if err != nil {
		return err
	}

	// Apply delta
	if component.Data == nil {
		component.Data = make(map[string]interface{})
	}

	for fieldName, changeRaw := range changedFieldsRaw {
		fieldChange, ok := changeRaw.(map[string]interface{})
		if !ok {
			continue
		}
		component.Data[fieldName] = fieldChange["newValue"]
	}

	return s.appRepo.UpdateComponentData(componentID, component.Data)
}

// Helper functions for safe type extraction
func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	v, _ := numberValue(m[key])
	return int(v)
}

// extractRecipients reads an optional "recipients" list from event data.
// []interface{} is the shape MarshalData/JSON always produces (recipients
// round-trips through json.Marshal/Unmarshal there); []string is accepted
// too so callers that build the map by hand (tests) don't need to care.
func extractRecipients(data map[string]interface{}) []string {
	switch v := data["recipients"].(type) {
	case []string:
		return v
	case []interface{}:
		keys := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				keys = append(keys, s)
			}
		}
		return keys
	default:
		return nil
	}
}

// getInt64Ptr extracts an optional int64 from event data, or nil when the key
// is absent. Unlike getInt, this has to handle two distinct shapes for the
// SAME field: the produce path (InvitationService.Join) puts a real int64
// straight into the map, while the replay/JSON path (events read back from
// storage, or from another space over the wire) always yields a float64,
// since encoding/json only ever decodes numbers into float64.
func getInt64Ptr(m map[string]interface{}, key string) *int64 {
	switch v := m[key].(type) {
	case int64:
		return &v
	case float64:
		i := int64(v)
		return &i
	default:
		return nil
	}
}
