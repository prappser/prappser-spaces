package event

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/prappser/prappser_server/internal/application"
	"github.com/prappser/prappser_server/internal/user"
	"github.com/rs/zerolog/log"
)

// EventBroadcaster broadcasts events to connected WebSocket clients
type EventBroadcaster interface {
	BroadcastToApplication(applicationID string, event *Event)
	BroadcastToUser(userPublicKey string, event *Event)
}

type EventService struct {
	repo        *EventRepository
	appRepo     application.ApplicationRepository
	broadcaster EventBroadcaster
}

func NewEventService(repo *EventRepository, appRepo application.ApplicationRepository, broadcaster EventBroadcaster) *EventService {
	return &EventService{
		repo:        repo,
		appRepo:     appRepo,
		broadcaster: broadcaster,
	}
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

	// User-scoped events bypass application lookup and use a separate authorization path
	if IsUserScoped(event.Type) {
		return s.acceptUserScopedEvent(ctx, event, submitter)
	}

	appID, ok := event.Data["applicationId"].(string)
	if !ok || appID == "" {
		return nil, fmt.Errorf("%w: applicationId not found in event data", ErrValidation)
	}

	// Set ApplicationID field from data
	event.ApplicationID = appID

	app, err := s.appRepo.GetApplicationByID(appID)
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

	seq, err := s.repo.GetNextSequence(appID)
	if err != nil {
		return nil, fmt.Errorf("sequence generation failed: %w", err)
	}
	event.SequenceNumber = seq

	event.CreatedAt = time.Now().Unix()

	log.Debug().
		Str("eventId", event.ID).
		Int64("sequence", event.SequenceNumber).
		Msg("[EVENT] Persisting to database")

	if err := s.repo.Create(event); err != nil {
		log.Error().
			Str("eventId", event.ID).
			Err(err).
			Msg("[EVENT] Persistence failed")
		return nil, fmt.Errorf("persistence failed: %w", err)
	}

	log.Debug().
		Str("eventId", event.ID).
		Str("type", string(event.Type)).
		Msg("[EVENT] Executing")

	// Execute event to update database state
	if err := s.executeEvent(ctx, event); err != nil {
		// Log error but don't fail event acceptance
		// Event is already persisted and sequenced
		log.Error().
			Str("eventId", event.ID).
			Str("type", string(event.Type)).
			Err(err).
			Msg("[EVENT] Execution failed - event persisted but database state not updated")
	} else {
		log.Debug().
			Str("eventId", event.ID).
			Str("type", string(event.Type)).
			Msg("[EVENT] Execution complete")
	}

	log.Info().
		Str("eventId", event.ID).
		Str("type", string(event.Type)).
		Int64("sequence", event.SequenceNumber).
		Msg("[EVENT] Accepted successfully")

	// Broadcast to WebSocket clients
	if s.broadcaster != nil {
		s.broadcaster.BroadcastToApplication(event.ApplicationID, event)
	}

	return event, nil
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

	// User-scoped events have no sequence number
	event.SequenceNumber = 0
	event.CreatedAt = time.Now().Unix()

	log.Debug().
		Str("eventId", event.ID).
		Msg("[EVENT] Persisting user-scoped event to database")

	if err := s.repo.Create(event); err != nil {
		log.Error().
			Str("eventId", event.ID).
			Err(err).
			Msg("[EVENT] Persistence failed")
		return nil, fmt.Errorf("persistence failed: %w", err)
	}

	log.Debug().
		Str("eventId", event.ID).
		Str("type", string(event.Type)).
		Msg("[EVENT] Executing")

	if err := s.executeEvent(ctx, event); err != nil {
		log.Error().
			Str("eventId", event.ID).
			Str("type", string(event.Type)).
			Err(err).
			Msg("[EVENT] Execution failed - event persisted but database state not updated")
	} else {
		log.Debug().
			Str("eventId", event.ID).
			Str("type", string(event.Type)).
			Msg("[EVENT] Execution complete")
	}

	log.Info().
		Str("eventId", event.ID).
		Str("type", string(event.Type)).
		Msg("[EVENT] User-scoped event accepted successfully")

	if s.broadcaster != nil {
		s.broadcaster.BroadcastToUser(event.CreatorPublicKey, event)
	}

	return event, nil
}

// ProduceEvent creates an event without authorization checks.
// Used for server-generated events where the action was already validated by the endpoint.
// The event is sequenced, persisted, and executed but authorization is skipped.
func (s *EventService) ProduceEvent(ctx context.Context, event *Event) (*Event, error) {
	log.Debug().
		Str("eventId", event.ID).
		Str("type", string(event.Type)).
		Msg("[EVENT] Server-produced event received")

	if err := ValidateEvent(event); err != nil {
		log.Debug().
			Str("eventId", event.ID).
			Err(err).
			Msg("[EVENT] Validation failed")
		return nil, fmt.Errorf("validation failed: %w", err)
	}
	log.Debug().Str("eventId", event.ID).Msg("[EVENT] Validation passed")

	// User-scoped events have no application context or sequence number
	if IsUserScoped(event.Type) {
		return s.produceUserScopedEvent(ctx, event)
	}

	appID, ok := event.Data["applicationId"].(string)
	if !ok || appID == "" {
		return nil, fmt.Errorf("%w: applicationId not found in event data", ErrValidation)
	}

	// Set ApplicationID field from data
	event.ApplicationID = appID

	seq, err := s.repo.GetNextSequence(appID)
	if err != nil {
		return nil, fmt.Errorf("sequence generation failed: %w", err)
	}
	event.SequenceNumber = seq

	event.CreatedAt = time.Now().Unix()

	log.Debug().
		Str("eventId", event.ID).
		Int64("sequence", event.SequenceNumber).
		Msg("[EVENT] Persisting to database")

	if err := s.repo.Create(event); err != nil {
		log.Error().
			Str("eventId", event.ID).
			Err(err).
			Msg("[EVENT] Persistence failed")
		return nil, fmt.Errorf("persistence failed: %w", err)
	}

	log.Debug().
		Str("eventId", event.ID).
		Str("type", string(event.Type)).
		Msg("[EVENT] Executing")

	// Execute event to update database state
	if err := s.executeEvent(ctx, event); err != nil {
		// Log error but don't fail event acceptance
		// Event is already persisted and sequenced
		log.Error().
			Str("eventId", event.ID).
			Str("type", string(event.Type)).
			Str("applicationId", event.ApplicationID).
			Err(err).
			Msg("[EVENT] Execution failed - event persisted but database state not updated")
	} else {
		log.Debug().
			Str("eventId", event.ID).
			Str("type", string(event.Type)).
			Str("applicationId", event.ApplicationID).
			Msg("[EVENT] Execution complete")
	}

	log.Info().
		Str("eventId", event.ID).
		Str("type", string(event.Type)).
		Int64("sequence", event.SequenceNumber).
		Msg("[EVENT] Server-produced event accepted successfully")

	// Broadcast to WebSocket clients
	if s.broadcaster != nil {
		s.broadcaster.BroadcastToApplication(event.ApplicationID, event)
	}

	return event, nil
}

// produceUserScopedEvent handles the user-scoped path for server-produced events.
func (s *EventService) produceUserScopedEvent(ctx context.Context, event *Event) (*Event, error) {
	event.SequenceNumber = 0
	event.CreatedAt = time.Now().Unix()

	log.Debug().
		Str("eventId", event.ID).
		Msg("[EVENT] Persisting user-scoped server-produced event to database")

	if err := s.repo.Create(event); err != nil {
		log.Error().
			Str("eventId", event.ID).
			Err(err).
			Msg("[EVENT] Persistence failed")
		return nil, fmt.Errorf("persistence failed: %w", err)
	}

	log.Debug().
		Str("eventId", event.ID).
		Str("type", string(event.Type)).
		Msg("[EVENT] Executing")

	if err := s.executeEvent(ctx, event); err != nil {
		log.Error().
			Str("eventId", event.ID).
			Str("type", string(event.Type)).
			Err(err).
			Msg("[EVENT] Execution failed - event persisted but database state not updated")
	} else {
		log.Debug().
			Str("eventId", event.ID).
			Str("type", string(event.Type)).
			Msg("[EVENT] Execution complete")
	}

	log.Info().
		Str("eventId", event.ID).
		Str("type", string(event.Type)).
		Msg("[EVENT] Server-produced user-scoped event accepted successfully")

	if s.broadcaster != nil {
		s.broadcaster.BroadcastToUser(event.CreatorPublicKey, event)
	}

	return event, nil
}

// GetEventsSince retrieves events since a given event ID for the authenticated user's applications
func (s *EventService) GetEventsSince(userPublicKey string, sinceEventID string, limit int) (*EventsResponse, error) {
	events, hasMore, err := s.repo.GetSince(userPublicKey, sinceEventID, limit)
	if err != nil {
		// Check if the error is because sinceEventID was not found (might have been cleaned up)
		if err.Error() == "since event not found" {
			return &EventsResponse{
				FullResyncRequired: true,
				Reason:             "Events expired or gap detected",
			}, nil
		}
		return nil, fmt.Errorf("failed to get events: %w", err)
	}

	return &EventsResponse{
		Events:  events,
		HasMore: hasMore,
	}, nil
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
	case "application_deleted":
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
	case "user_settings_changed":
		// No server-side state changes needed for v1 (avatar is in storage)
		log.Debug().Str("eventId", event.ID).Msg("[EVENT] Handler: user_settings_changed (no-op)")
		return nil
	case "member_details_changed":
		// Future: update member record
		log.Debug().Str("eventId", event.ID).Msg("[EVENT] Handler: member_details_changed (no-op)")
		return nil
	case "application_created":
		// No server-side state change: application was already registered by the creator device
		log.Debug().Str("eventId", event.ID).Msg("[EVENT] Handler: application_created (no-op)")
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

	memberName, ok := event.Data["memberName"].(string)
	if !ok || memberName == "" {
		return fmt.Errorf("missing memberName in member_added event")
	}

	roleStr, ok := event.Data["role"].(string)
	if !ok || roleStr == "" {
		roleStr = "member" // Default role
	}

	member := &application.Member{
		ID:            uuid.New().String(),
		ApplicationID: appID,
		Name:          memberName,
		Role:          application.MemberRole(roleStr),
		PublicKey:     memberPublicKey,
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

	log.Debug().
		Str("applicationId", appID).
		Str("memberPublicKey", memberPublicKey[:20]+"...").
		Msg("[MEMBER_REMOVED] Executing member_removed event - looking up member")

	// Get member by publicKey to get the member ID
	member, err := s.appRepo.GetMemberByPublicKey(appID, memberPublicKey)
	if err != nil {
		log.Error().
			Str("applicationId", appID).
			Str("memberPublicKey", memberPublicKey[:20]+"...").
			Err(err).
			Msg("[MEMBER_REMOVED] Failed to find member for deletion")
		return fmt.Errorf("member not found: %w", err)
	}

	log.Debug().
		Str("applicationId", appID).
		Str("memberId", member.ID).
		Str("memberPublicKey", memberPublicKey[:20]+"...").
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
		Str("memberPublicKey", memberPublicKey[:20]+"...").
		Msg("[MEMBER_REMOVED] Successfully deleted member from database")

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
	if err != nil {
		return fmt.Errorf("member not found: %w", err)
	}

	// Update role
	member.Role = application.MemberRole(newRole)
	return s.appRepo.UpdateMember(member)
}

// executeComponentDataChanged applies delta changes to a component's data
func (s *EventService) executeComponentDataChanged(ctx context.Context, event *Event) error {
	componentID, ok := event.Data["componentId"].(string)
	if !ok || componentID == "" {
		return fmt.Errorf("missing componentId in component_data_changed event")
	}

	changedFieldsRaw, ok := event.Data["changedFields"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("missing changedFields in component_data_changed event")
	}

	// Get current component
	component, err := s.appRepo.GetComponentByID(componentID)
	if err != nil {
		return fmt.Errorf("component not found: %w", err)
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

// executeApplicationAfterEditModeChanged applies a batch of structural changes
func (s *EventService) executeApplicationAfterEditModeChanged(ctx context.Context, event *Event) error {
	changesRaw, ok := event.Data["changes"].([]interface{})
	if !ok {
		return fmt.Errorf("missing changes in application_after_edit_mode_changed event")
	}

	for i, changeRaw := range changesRaw {
		change, ok := changeRaw.(map[string]interface{})
		if !ok {
			log.Warn().Int("index", i).Msg("[EDIT_MODE] Skipping invalid change entry")
			continue
		}

		changeType, _ := change["changeType"].(string)
		entityType, _ := change["entityType"].(string)
		entityID, _ := change["entityId"].(string)

		switch changeType {
		case "component_added":
			if err := s.executeComponentAdded(change); err != nil {
				log.Error().Err(err).Str("entityId", entityID).Msg("[EDIT_MODE] Failed to add component")
			}
		case "component_removed":
			if err := s.appRepo.DeleteComponent(entityID); err != nil {
				log.Error().Err(err).Str("entityId", entityID).Msg("[EDIT_MODE] Failed to remove component")
			}
		case "component_reordered":
			if indexRaw, ok := change["index"].(float64); ok {
				if err := s.appRepo.UpdateComponentIndex(entityID, int(indexRaw)); err != nil {
					log.Error().Err(err).Str("entityId", entityID).Msg("[EDIT_MODE] Failed to reorder component")
				}
			}
		case "component_data_changed":
			if err := s.executeComponentDataDelta(entityID, change); err != nil {
				log.Error().Err(err).Str("entityId", entityID).Msg("[EDIT_MODE] Failed to update component data")
			}
		case "component_group_added":
			if err := s.executeComponentGroupAdded(change); err != nil {
				log.Error().Err(err).Str("entityId", entityID).Msg("[EDIT_MODE] Failed to add component group")
			}
		case "component_group_removed":
			if err := s.appRepo.DeleteComponentGroup(entityID); err != nil {
				log.Error().Err(err).Str("entityId", entityID).Msg("[EDIT_MODE] Failed to remove component group")
			}
		case "component_group_reordered":
			if indexRaw, ok := change["index"].(float64); ok {
				if err := s.appRepo.UpdateComponentGroupIndex(entityID, int(indexRaw)); err != nil {
					log.Error().Err(err).Str("entityId", entityID).Msg("[EDIT_MODE] Failed to reorder component group")
				}
			}
		default:
			log.Warn().
				Str("changeType", changeType).
				Str("entityType", entityType).
				Msg("[EDIT_MODE] Unknown change type")
		}
	}

	return nil
}

// executeComponentAdded creates a new component from change data
func (s *EventService) executeComponentAdded(change map[string]interface{}) error {
	data, ok := change["data"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("missing data for component_added")
	}

	component := &application.Component{
		ID:               getString(data, "id"),
		ComponentGroupID: getString(data, "componentGroupId"),
		ApplicationID:    getString(data, "applicationId"),
		Name:             getString(data, "name"),
		Index:            getInt(data, "index"),
	}

	if componentData, ok := data["data"].(map[string]interface{}); ok {
		component.Data = componentData
	}

	return s.appRepo.CreateComponent(component)
}

// executeComponentGroupAdded creates a new component group from change data
func (s *EventService) executeComponentGroupAdded(change map[string]interface{}) error {
	data, ok := change["data"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("missing data for component_group_added")
	}

	group := &application.ComponentGroup{
		ID:            getString(data, "id"),
		ApplicationID: getString(data, "applicationId"),
		Name:          getString(data, "name"),
		Index:         getInt(data, "index"),
	}

	return s.appRepo.CreateComponentGroup(group)
}

// executeComponentDataDelta applies delta changes to a component from a structure change
func (s *EventService) executeComponentDataDelta(componentID string, change map[string]interface{}) error {
	changedFieldsRaw, ok := change["changedFields"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("missing changedFields for component_data_changed")
	}

	// Get current component
	component, err := s.appRepo.GetComponentByID(componentID)
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
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	return 0
}
