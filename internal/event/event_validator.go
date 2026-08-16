package event

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"time"
)

var (
	ErrValidation = errors.New("validation error")
)

func ValidateEvent(event *Event) error {
	if event.ID == "" {
		return fmt.Errorf("%w: event.id is required", ErrValidation)
	}
	if event.Type == "" {
		return fmt.Errorf("%w: event.type is required", ErrValidation)
	}
	if event.CreatorPublicKey == "" {
		return fmt.Errorf("%w: event.creatorPublicKey is required", ErrValidation)
	}
	if event.Data == nil {
		return fmt.Errorf("%w: event.data is required", ErrValidation)
	}

	switch event.Type {
	case EventTypeMemberAdded:
		return validateMemberAddedData(event.Data)
	case EventTypeMemberRemoved:
		return validateMemberRemovedData(event.Data)
	case EventTypeMemberRoleChanged:
		return validateMemberRoleChangedData(event.Data)
	case EventTypeApplicationDataChanged:
		return validateApplicationDataChangedData(event.Data)
	case EventTypeApplicationDeleted:
		return validateApplicationDeletedData(event.Data)
	case EventTypeInviteRevoked:
		return validateInviteRevokedData(event.Data)
	case EventTypeComponentDataChanged:
		return validateComponentDataChangedData(event.Data)
	case EventTypeApplicationAfterEditModeChanged:
		return validateApplicationAfterEditModeChangedData(event.Data)
	case EventTypeUserSettingsChanged:
		return validateUserSettingsChangedData(event.Data)
	case EventTypeMemberDetailsChanged:
		return validateMemberDetailsChangedData(event.Data)
	case EventTypeApplicationCreated:
		return validateApplicationCreatedData(event.Data)
	case EventTypeApplicationFileCreated:
		return validateApplicationFileCreatedData(event.Data)
	case EventTypeApplicationFileDeleted:
		return validateApplicationFileDeletedData(event.Data)
	case EventTypeReminderChanged:
		return validateReminderChangedData(event.Data)
	case EventTypeReminderFired:
		return validateReminderFiredData(event.Data)
	case EventTypeTemplateChanged:
		return validateTemplateChangedData(event.Data)
	default:
		return fmt.Errorf("%w: unknown event type: %s", ErrValidation, event.Type)
	}
}

func validateMemberAddedData(data map[string]interface{}) error {
	if _, ok := data["applicationId"].(string); !ok || data["applicationId"] == "" {
		return fmt.Errorf("%w: applicationId is required", ErrValidation)
	}
	if _, ok := data["memberPublicKey"].(string); !ok || data["memberPublicKey"] == "" {
		return fmt.Errorf("%w: memberPublicKey is required", ErrValidation)
	}
	if _, ok := data["userDisplayName"].(string); !ok || data["userDisplayName"] == "" {
		return fmt.Errorf("%w: userDisplayName is required", ErrValidation)
	}
	if _, ok := data["role"].(string); !ok || data["role"] == "" {
		return fmt.Errorf("%w: role is required", ErrValidation)
	}
	return nil
}

func validateMemberRemovedData(data map[string]interface{}) error {
	if _, ok := data["applicationId"].(string); !ok || data["applicationId"] == "" {
		return fmt.Errorf("%w: applicationId is required", ErrValidation)
	}
	if _, ok := data["memberPublicKey"].(string); !ok || data["memberPublicKey"] == "" {
		return fmt.Errorf("%w: memberPublicKey is required", ErrValidation)
	}
	return nil
}

func validateMemberRoleChangedData(data map[string]interface{}) error {
	if _, ok := data["applicationId"].(string); !ok || data["applicationId"] == "" {
		return fmt.Errorf("%w: applicationId is required", ErrValidation)
	}
	if _, ok := data["memberPublicKey"].(string); !ok || data["memberPublicKey"] == "" {
		return fmt.Errorf("%w: memberPublicKey is required", ErrValidation)
	}
	if _, ok := data["oldRole"].(string); !ok || data["oldRole"] == "" {
		return fmt.Errorf("%w: oldRole is required", ErrValidation)
	}
	if _, ok := data["newRole"].(string); !ok || data["newRole"] == "" {
		return fmt.Errorf("%w: newRole is required", ErrValidation)
	}
	return nil
}

func validateApplicationDataChangedData(data map[string]interface{}) error {
	if _, ok := data["applicationId"].(string); !ok || data["applicationId"] == "" {
		return fmt.Errorf("%w: applicationId is required", ErrValidation)
	}
	if _, ok := data["name"].(string); !ok || data["name"] == "" {
		return fmt.Errorf("%w: name is required", ErrValidation)
	}
	return nil
}

func validateApplicationDeletedData(data map[string]interface{}) error {
	if _, ok := data["applicationId"].(string); !ok || data["applicationId"] == "" {
		return fmt.Errorf("%w: applicationId is required", ErrValidation)
	}
	return nil
}

func validateInviteRevokedData(data map[string]interface{}) error {
	if _, ok := data["applicationId"].(string); !ok || data["applicationId"] == "" {
		return fmt.Errorf("%w: applicationId is required", ErrValidation)
	}
	if _, ok := data["inviteId"].(string); !ok || data["inviteId"] == "" {
		return fmt.Errorf("%w: inviteId is required", ErrValidation)
	}
	return nil
}

func validateComponentDataChangedData(data map[string]interface{}) error {
	// Client-side validation only - server trusts client data
	return nil
}

func validateApplicationAfterEditModeChangedData(data map[string]interface{}) error {
	// Client-side validation only - server trusts client data
	return nil
}

func validateUserSettingsChangedData(data map[string]interface{}) error {
	if _, ok := data["userPublicKey"].(string); !ok || data["userPublicKey"] == "" {
		return fmt.Errorf("%w: userPublicKey is required", ErrValidation)
	}
	return nil
}

func validateMemberDetailsChangedData(data map[string]interface{}) error {
	if _, ok := data["applicationId"].(string); !ok || data["applicationId"] == "" {
		return fmt.Errorf("%w: applicationId is required", ErrValidation)
	}
	if _, ok := data["memberPublicKey"].(string); !ok || data["memberPublicKey"] == "" {
		return fmt.Errorf("%w: memberPublicKey is required", ErrValidation)
	}
	return nil
}

func validateApplicationFileCreatedData(data map[string]interface{}) error {
	if _, ok := data["applicationId"].(string); !ok || data["applicationId"] == "" {
		return fmt.Errorf("%w: applicationId is required", ErrValidation)
	}
	if _, ok := data["fileId"].(string); !ok || data["fileId"] == "" {
		return fmt.Errorf("%w: fileId is required", ErrValidation)
	}
	if _, ok := data["filename"].(string); !ok || data["filename"] == "" {
		return fmt.Errorf("%w: filename is required", ErrValidation)
	}
	if _, ok := data["contentType"].(string); !ok || data["contentType"] == "" {
		return fmt.Errorf("%w: contentType is required", ErrValidation)
	}
	if _, ok := data["sizeBytes"].(int64); !ok {
		if _, ok := data["sizeBytes"].(float64); !ok {
			return fmt.Errorf("%w: sizeBytes is required", ErrValidation)
		}
	}
	if _, ok := data["remoteUrl"].(string); !ok || data["remoteUrl"] == "" {
		return fmt.Errorf("%w: remoteUrl is required", ErrValidation)
	}
	return nil
}

func validateApplicationFileDeletedData(data map[string]interface{}) error {
	if _, ok := data["applicationId"].(string); !ok || data["applicationId"] == "" {
		return fmt.Errorf("%w: applicationId is required", ErrValidation)
	}
	if _, ok := data["fileId"].(string); !ok || data["fileId"] == "" {
		return fmt.Errorf("%w: fileId is required", ErrValidation)
	}
	return nil
}

// offsetSpecPattern matches the small ISO-8601 duration subset used by
// reminder offsets: an optional leading '-', then either "PT" plus H/M/S
// components (e.g. "PT0S", "-PT30M") or "P<n>D" (e.g. "P1D").
var offsetSpecPattern = regexp.MustCompile(`^(-)?P(?:T(\d+H)?(\d+M)?(\d+S)?|(\d+)D)$`)

// isValidOffsetSpec is a syntactic check only, duplicated from
// internal/reminder's own parser rather than imported: internal/reminder
// imports internal/event for its wire types, so the reverse import would
// create a cycle.
func isValidOffsetSpec(spec string) bool {
	m := offsetSpecPattern.FindStringSubmatch(spec)
	if m == nil {
		return false
	}
	// Group 5 is the P<n>D form; groups 2-4 are the PT form's H/M/S parts.
	// "PT" with none of H/M/S present is not a valid duration.
	return m[5] != "" || m[2] != "" || m[3] != "" || m[4] != ""
}

// numberValue extracts a float64 from a JSON-decoded number (float64 on the
// replay/JSON path) or a Go-native int64/int (the produce path, which builds
// the map directly - see getInt64Ptr in event_service.go for the same split).
func numberValue(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	default:
		return 0, false
	}
}

// validateReminderChangedData validates for real, unlike most validators in
// this file: these rows drive a background scheduler, so an unparseable tz
// or offset here would otherwise fail silently later inside the scheduler
// where nobody sees it.
func validateReminderChangedData(data map[string]interface{}) error {
	if _, ok := data["id"].(string); !ok || data["id"] == "" {
		return fmt.Errorf("%w: id is required", ErrValidation)
	}
	if _, ok := data["componentId"].(string); !ok || data["componentId"] == "" {
		return fmt.Errorf("%w: componentId is required", ErrValidation)
	}
	if _, ok := data["targetKey"].(string); !ok || data["targetKey"] == "" {
		return fmt.Errorf("%w: targetKey is required", ErrValidation)
	}

	tz, ok := data["tz"].(string)
	if !ok || tz == "" {
		return fmt.Errorf("%w: tz is required", ErrValidation)
	}
	if _, err := time.LoadLocation(tz); err != nil {
		return fmt.Errorf("%w: tz %q is not a valid timezone: %v", ErrValidation, tz, err)
	}

	dueAt, ok := numberValue(data["dueAt"])
	if !ok || dueAt <= 0 {
		return fmt.Errorf("%w: dueAt must be a positive timestamp", ErrValidation)
	}

	offsetsRaw, ok := data["offsets"].([]interface{})
	if !ok || len(offsetsRaw) == 0 {
		return fmt.Errorf("%w: at least one offset is required", ErrValidation)
	}
	for _, o := range offsetsRaw {
		offsetStr, ok := o.(string)
		if !ok || !isValidOffsetSpec(offsetStr) {
			return fmt.Errorf("%w: invalid offset %v", ErrValidation, o)
		}
	}

	state, _ := data["state"].(string)
	if state != "pending" && state != "cancelled" {
		return fmt.Errorf("%w: state must be pending or cancelled", ErrValidation)
	}

	rev, ok := numberValue(data["rev"])
	if !ok || rev < 0 {
		return fmt.Errorf("%w: rev must be >= 0", ErrValidation)
	}

	return nil
}

// validateReminderFiredData is permissive by design: this event is
// space-produced only (see event_authorizer.go), so it never carries
// untrusted client input, but it must still pass ValidateEvent since
// ProduceEvent calls it too.
func validateReminderFiredData(data map[string]interface{}) error {
	if _, ok := data["applicationId"].(string); !ok || data["applicationId"] == "" {
		return fmt.Errorf("%w: applicationId is required", ErrValidation)
	}
	if _, ok := data["componentId"].(string); !ok || data["componentId"] == "" {
		return fmt.Errorf("%w: componentId is required", ErrValidation)
	}
	if _, ok := data["ruleId"].(string); !ok || data["ruleId"] == "" {
		return fmt.Errorf("%w: ruleId is required", ErrValidation)
	}
	return nil
}

func validateApplicationCreatedData(data map[string]interface{}) error {
	if _, ok := data["userPublicKey"].(string); !ok || data["userPublicKey"] == "" {
		return fmt.Errorf("%w: userPublicKey is required", ErrValidation)
	}
	if _, ok := data["applicationId"].(string); !ok || data["applicationId"] == "" {
		return fmt.Errorf("%w: applicationId is required", ErrValidation)
	}
	if _, ok := data["applicationName"].(string); !ok || data["applicationName"] == "" {
		return fmt.Errorf("%w: applicationName is required", ErrValidation)
	}
	return nil
}

// maxTemplateDocBytes caps the size of the opaque template "doc" blob. The
// client already caps the whole encoded payload at 64 KiB before sending
// (template_sync_service.dart), so this bound is strictly looser for the
// same event while still bounding the only field that matters for
// event-log growth.
const maxTemplateDocBytes = 64 * 1024

// validateTemplateChangedData validates the shipped flat wire shape
// (template_changed_event.dart / .g.dart): userPublicKey, id, doc, source,
// state and rev are the server's real gates. name/description/icon are
// deliberately NOT validated - the server never reads them, description and
// icon legitimately arrive as explicit JSON null, and pinning the client's
// UI limits here would create silent sync breakage if the app ever raises
// them. The document itself stays opaque JSON; only its size is checked.
func validateTemplateChangedData(data map[string]interface{}) error {
	if _, ok := data["userPublicKey"].(string); !ok || data["userPublicKey"] == "" {
		return fmt.Errorf("%w: userPublicKey is required", ErrValidation)
	}
	if _, ok := data["id"].(string); !ok || data["id"] == "" {
		return fmt.Errorf("%w: id is required", ErrValidation)
	}

	rev, ok := numberValue(data["rev"])
	if !ok || rev < 0 {
		return fmt.Errorf("%w: rev must be >= 0", ErrValidation)
	}
	if rev != math.Trunc(rev) {
		return fmt.Errorf("%w: rev must be an integer", ErrValidation)
	}

	state, _ := data["state"].(string)
	if state != "active" && state != "deleted" {
		return fmt.Errorf("%w: state must be active or deleted", ErrValidation)
	}

	source, _ := data["source"].(string)
	if source != "user" && source != "imported" {
		return fmt.Errorf("%w: source must be user or imported", ErrValidation)
	}

	doc, ok := data["doc"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("%w: doc is required and must be an object", ErrValidation)
	}
	docJSON, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("%w: doc could not be marshalled: %v", ErrValidation, err)
	}
	if len(docJSON) > maxTemplateDocBytes {
		return fmt.Errorf("%w: doc exceeds maximum size of %d bytes", ErrValidation, maxTemplateDocBytes)
	}

	createdAt, ok := numberValue(data["createdAt"])
	if !ok || createdAt < 0 {
		return fmt.Errorf("%w: createdAt must be a number >= 0", ErrValidation)
	}

	updatedAt, ok := numberValue(data["updatedAt"])
	if !ok || updatedAt < 0 {
		return fmt.Errorf("%w: updatedAt must be a number >= 0", ErrValidation)
	}

	return nil
}
