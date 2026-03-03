package event

import (
	"encoding/json"
)

// EventType represents the type of event
type EventType string

const (
	EventTypeMemberAdded                    EventType = "member_added"
	EventTypeMemberRemoved                  EventType = "member_removed"
	EventTypeMemberRoleChanged              EventType = "member_role_changed"
	EventTypeApplicationDataChanged         EventType = "application_data_changed"
	EventTypeApplicationDeleted             EventType = "application_deleted"
	EventTypeInviteRevoked                  EventType = "invite_revoked"
	EventTypeComponentDataChanged           EventType = "component_data_changed"
	EventTypeApplicationAfterEditModeChanged EventType = "application_after_edit_mode_changed"
	EventTypeUserSettingsChanged            EventType = "user_settings_changed"
	EventTypeMemberDetailsChanged           EventType = "member_details_changed"
	EventTypeApplicationCreated             EventType = "application_created"
)

// IsUserScoped returns true for event types that are user-scoped (no applicationId)
func IsUserScoped(eventType EventType) bool {
	return eventType == EventTypeUserSettingsChanged || eventType == EventTypeApplicationCreated
}

// Event represents a system event for application lifecycle changes
type Event struct {
	ID               string                 `json:"id"`
	CreatedAt        int64                  `json:"createdAt"`
	ApplicationID    string                 `json:"applicationId"`
	SequenceNumber   int64                  `json:"sequence_number"`
	Type             EventType              `json:"type"`
	CreatorPublicKey string                 `json:"creatorPublicKey"`
	Version          int                    `json:"version"`
	Data             map[string]interface{} `json:"data"`
}

// MemberAddedData represents the data for a member_added event
type MemberAddedData struct {
	Version         int    `json:"version"`
	ApplicationID   string `json:"applicationId"`
	MemberPublicKey string `json:"memberPublicKey"`
	MemberName      string `json:"memberName"`
	Role            string `json:"role"`
	InviteID        string `json:"inviteId"`
}

// MemberRemovedData represents the data for a member_removed event
type MemberRemovedData struct {
	Version         int    `json:"version"`
	ApplicationID   string `json:"applicationId"`
	MemberPublicKey string `json:"memberPublicKey"`
	Reason          string `json:"reason,omitempty"`
}

// MemberRoleChangedData represents the data for a member_role_changed event
type MemberRoleChangedData struct {
	Version         int    `json:"version"`
	ApplicationID   string `json:"applicationId"`
	MemberPublicKey string `json:"memberPublicKey"`
	OldRole         string `json:"oldRole"`
	NewRole         string `json:"newRole"`
}

// ApplicationDataChangedData represents the data for an application_data_changed event
type ApplicationDataChangedData struct {
	Version        int      `json:"version"`
	ApplicationID  string   `json:"applicationId"`
	ChangedFields  []string `json:"changedFields,omitempty"`
}

// ApplicationDeletedData represents the data for an application_deleted event
type ApplicationDeletedData struct {
	Version       int    `json:"version"`
	ApplicationID string `json:"applicationId"`
	DeletedAt     int64  `json:"deletedAt"`
}

// InviteRevokedData represents the data for an invite_revoked event
type InviteRevokedData struct {
	Version       int    `json:"version"`
	ApplicationID string `json:"applicationId"`
	InviteID      string `json:"inviteId"`
}

// FieldChange represents a change to a single field with old and new values
type FieldChange struct {
	OldValue interface{} `json:"oldValue"`
	NewValue interface{} `json:"newValue"`
}

// ComponentDataChangedData represents the data for a component_data_changed event
type ComponentDataChangedData struct {
	Version          int                    `json:"version"`
	ApplicationID    string                 `json:"applicationId"`
	ComponentID      string                 `json:"componentId"`
	ComponentGroupID string                 `json:"componentGroupId"`
	ChangedFields    map[string]FieldChange `json:"changedFields"`
}

// StructureChange represents a single change in the application structure
type StructureChange struct {
	ChangeType    string                 `json:"changeType"`
	EntityType    string                 `json:"entityType"`
	EntityID      string                 `json:"entityId"`
	Data          map[string]interface{} `json:"data,omitempty"`
	Index         *int                   `json:"index,omitempty"`
	ChangedFields map[string]FieldChange `json:"changedFields,omitempty"`
}

// ApplicationAfterEditModeChangedData represents the data for an application_after_edit_mode_changed event
type ApplicationAfterEditModeChangedData struct {
	Version       int               `json:"version"`
	ApplicationID string            `json:"applicationId"`
	Changes       []StructureChange `json:"changes"`
}

// UserSettingsChangedData represents the data for a user_settings_changed event
type UserSettingsChangedData struct {
	Version         int    `json:"version"`
	UserPublicKey   string `json:"userPublicKey"`
	AvatarStorageID string `json:"avatarStorageId,omitempty"`
}

// ApplicationCreatedData represents the data for an application_created event
type ApplicationCreatedData struct {
	Version         int    `json:"version"`
	UserPublicKey   string `json:"userPublicKey"`
	ApplicationID   string `json:"applicationId"`
	ApplicationName string `json:"applicationName"`
}

// MemberDetailsChangedData represents the data for a member_details_changed event (future use)
type MemberDetailsChangedData struct {
	Version         int    `json:"version"`
	ApplicationID   string `json:"applicationId"`
	MemberPublicKey string `json:"memberPublicKey"`
}

// EventsResponse represents the response for GET /events endpoint
type EventsResponse struct {
	Events             []*Event `json:"events,omitempty"`
	HasMore            bool     `json:"hasMore"`
	FullResyncRequired bool     `json:"fullResyncRequired,omitempty"`
	Reason             string   `json:"reason,omitempty"`
}

// NewEvent creates a new event with the given parameters
func NewEvent(id string, eventType EventType, creatorPublicKey string, data map[string]interface{}) *Event {
	return &Event{
		ID:               id,
		CreatedAt:        0, // Will be set by repository
		SequenceNumber:   0, // Will be set by repository
		Type:             eventType,
		CreatorPublicKey: creatorPublicKey,
		Version:          1,
		Data:             data,
	}
}

// MarshalData converts a typed data structure to map[string]interface{} for storage
func MarshalData(data interface{}) (map[string]interface{}, error) {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// UnmarshalData converts map[string]interface{} to a typed structure
func UnmarshalData(data map[string]interface{}, target interface{}) error {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return json.Unmarshal(jsonBytes, target)
}
