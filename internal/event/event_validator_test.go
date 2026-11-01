package event

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// ---- #42: reminder_changed drives a background scheduler, so validation
// here is real (not the permissive no-op most event types get) - an
// unparseable tz or offset must fail loudly at submission time, not
// silently inside the scheduler later. ----

func validReminderChangedData() map[string]interface{} {
	return map[string]interface{}{
		"version":       1,
		"id":            "rule-1",
		"applicationId": "app-1",
		"componentId":   "comp-1",
		"targetKey":     "item:1",
		"title":         "Buy milk",
		"dueAt":         float64(1700000000),
		"tz":            "Europe/Warsaw",
		"offsets":       []interface{}{"PT0S", "-PT30M"},
		"recipients":    []interface{}{"pk-1"},
		"state":         "pending",
		"rev":           float64(1),
	}
}

func TestValidateReminderChangedData_Valid(t *testing.T) {
	if err := validateReminderChangedData(validReminderChangedData()); err != nil {
		t.Fatalf("Expected valid data to pass, got: %v", err)
	}
}

func TestValidateReminderChangedData_MissingID(t *testing.T) {
	data := validReminderChangedData()
	delete(data, "id")
	if err := validateReminderChangedData(data); err == nil {
		t.Fatal("Expected error for missing id")
	}
}

func TestValidateReminderChangedData_InvalidTZ(t *testing.T) {
	data := validReminderChangedData()
	data["tz"] = "Not/A_Real_Zone"
	if err := validateReminderChangedData(data); err == nil {
		t.Fatal("Expected error for invalid tz")
	}
}

func TestValidateReminderChangedData_ZeroDueAt(t *testing.T) {
	data := validReminderChangedData()
	data["dueAt"] = float64(0)
	if err := validateReminderChangedData(data); err == nil {
		t.Fatal("Expected error for dueAt <= 0")
	}
}

func TestValidateReminderChangedData_NoOffsets(t *testing.T) {
	data := validReminderChangedData()
	data["offsets"] = []interface{}{}
	if err := validateReminderChangedData(data); err == nil {
		t.Fatal("Expected error for empty offsets")
	}
}

func TestValidateReminderChangedData_UnparseableOffset(t *testing.T) {
	data := validReminderChangedData()
	data["offsets"] = []interface{}{"tomorrow"}
	if err := validateReminderChangedData(data); err == nil {
		t.Fatal("Expected error for unparseable offset")
	}
}

func TestValidateReminderChangedData_InvalidState(t *testing.T) {
	data := validReminderChangedData()
	data["state"] = "archived"
	if err := validateReminderChangedData(data); err == nil {
		t.Fatal("Expected error for state outside pending/cancelled")
	}
}

func TestValidateReminderChangedData_NegativeRev(t *testing.T) {
	data := validReminderChangedData()
	data["rev"] = float64(-1)
	if err := validateReminderChangedData(data); err == nil {
		t.Fatal("Expected error for negative rev")
	}
}

func TestValidateReminderChangedData_CancelledStateAllowed(t *testing.T) {
	data := validReminderChangedData()
	data["state"] = "cancelled"
	if err := validateReminderChangedData(data); err != nil {
		t.Fatalf("Expected cancelled state to pass, got: %v", err)
	}
}

func TestValidateReminderFiredData_Valid(t *testing.T) {
	data := map[string]interface{}{
		"applicationId": "app-1",
		"componentId":   "comp-1",
		"ruleId":        "rule-1",
	}
	if err := validateReminderFiredData(data); err != nil {
		t.Fatalf("Expected valid data to pass, got: %v", err)
	}
}

func TestValidateReminderFiredData_MissingRuleID(t *testing.T) {
	data := map[string]interface{}{
		"applicationId": "app-1",
		"componentId":   "comp-1",
	}
	if err := validateReminderFiredData(data); err == nil {
		t.Fatal("Expected error for missing ruleId")
	}
}

// ---- #44: template_changed carries the current state of one account-owned
// template row between an account's own devices. The wire shape is the
// shipped flat shape (template_changed_event.dart / .g.dart), not the
// issue's nested "template" sketch: description/icon arrive as explicit
// JSON null, so validTemplateChangedData() carries them that way too. ----

func validTemplateChangedData() map[string]interface{} {
	return map[string]interface{}{
		"version":       float64(1),
		"userPublicKey": "pk-1",
		"id":            "template-1",
		"name":          "My Template",
		"description":   nil,
		"icon":          nil,
		"doc":           map[string]interface{}{"groups": []interface{}{}},
		"source":        "user",
		"state":         "active",
		"rev":           float64(1),
		"createdAt":     float64(1700000000),
		"updatedAt":     float64(1700000000),
	}
}

func TestValidateTemplateChangedData_Valid(t *testing.T) {
	if err := validateTemplateChangedData(validTemplateChangedData()); err != nil {
		t.Fatalf("Expected valid data to pass, got: %v", err)
	}
}

func TestValidateTemplateChangedData_MissingUserPublicKey(t *testing.T) {
	data := validTemplateChangedData()
	delete(data, "userPublicKey")
	if err := validateTemplateChangedData(data); err == nil {
		t.Fatal("Expected error for missing userPublicKey")
	}
}

func TestValidateTemplateChangedData_MissingID(t *testing.T) {
	data := validTemplateChangedData()
	delete(data, "id")
	if err := validateTemplateChangedData(data); err == nil {
		t.Fatal("Expected error for missing id")
	}
}

func TestValidateTemplateChangedData_InvalidSource(t *testing.T) {
	data := validTemplateChangedData()
	data["source"] = "builtin"
	if err := validateTemplateChangedData(data); err == nil {
		t.Fatal("Expected error for source outside user/imported")
	}
}

func TestValidateTemplateChangedData_SourceImportedAllowed(t *testing.T) {
	data := validTemplateChangedData()
	data["source"] = "imported"
	if err := validateTemplateChangedData(data); err != nil {
		t.Fatalf("Expected imported source to pass, got: %v", err)
	}
}

func TestValidateTemplateChangedData_InvalidState(t *testing.T) {
	data := validTemplateChangedData()
	data["state"] = "archived"
	if err := validateTemplateChangedData(data); err == nil {
		t.Fatal("Expected error for state outside active/deleted")
	}
}

func TestValidateTemplateChangedData_StateDeletedAllowed(t *testing.T) {
	data := validTemplateChangedData()
	data["state"] = "deleted"
	if err := validateTemplateChangedData(data); err != nil {
		t.Fatalf("Expected deleted state (tombstone) to pass, got: %v", err)
	}
}

func TestValidateTemplateChangedData_MissingRev(t *testing.T) {
	data := validTemplateChangedData()
	delete(data, "rev")
	if err := validateTemplateChangedData(data); err == nil {
		t.Fatal("Expected error for missing rev")
	}
}

func TestValidateTemplateChangedData_NegativeRev(t *testing.T) {
	data := validTemplateChangedData()
	data["rev"] = float64(-1)
	if err := validateTemplateChangedData(data); err == nil {
		t.Fatal("Expected error for negative rev")
	}
}

func TestValidateTemplateChangedData_NonNumericRev(t *testing.T) {
	data := validTemplateChangedData()
	data["rev"] = "1"
	if err := validateTemplateChangedData(data); err == nil {
		t.Fatal("Expected error for non-numeric rev")
	}
}

func TestValidateTemplateChangedData_FractionalRev(t *testing.T) {
	data := validTemplateChangedData()
	data["rev"] = float64(3.5)
	if err := validateTemplateChangedData(data); err == nil {
		t.Fatal("Expected error for fractional rev")
	}
}

func TestValidateTemplateChangedData_MissingDoc(t *testing.T) {
	data := validTemplateChangedData()
	delete(data, "doc")
	if err := validateTemplateChangedData(data); err == nil {
		t.Fatal("Expected error for missing doc")
	}
}

func TestValidateTemplateChangedData_DocNotAnObject(t *testing.T) {
	data := validTemplateChangedData()
	data["doc"] = "not-an-object"
	if err := validateTemplateChangedData(data); err == nil {
		t.Fatal("Expected error for doc not an object")
	}
}

func TestValidateTemplateChangedData_DocTooLarge(t *testing.T) {
	data := validTemplateChangedData()
	// Pad a single field well past maxTemplateDocBytes.
	data["doc"] = map[string]interface{}{
		"padding": strings.Repeat("a", maxTemplateDocBytes+1),
	}
	if err := validateTemplateChangedData(data); err == nil {
		t.Fatal("Expected error for doc exceeding the size cap")
	}
}

func TestValidateTemplateChangedData_DocAtLimitAllowed(t *testing.T) {
	data := validTemplateChangedData()
	// {"padding":"..."} wraps the padded string in 14 bytes of JSON
	// syntax; pad it so the marshalled doc lands exactly at the cap.
	emptyWrapper, err := json.Marshal(map[string]interface{}{"padding": ""})
	if err != nil {
		t.Fatalf("failed to marshal empty wrapper: %v", err)
	}
	padding := strings.Repeat("a", maxTemplateDocBytes-len(emptyWrapper))
	data["doc"] = map[string]interface{}{"padding": padding}
	docJSON, err := json.Marshal(data["doc"])
	if err != nil {
		t.Fatalf("failed to marshal test doc: %v", err)
	}
	if len(docJSON) != maxTemplateDocBytes {
		t.Fatalf("test setup error: expected marshalled doc to be exactly %d bytes, got %d", maxTemplateDocBytes, len(docJSON))
	}
	if err := validateTemplateChangedData(data); err != nil {
		t.Fatalf("Expected doc at the size limit to pass, got: %v", err)
	}
}

func TestValidateTemplateChangedData_NonNumericCreatedAt(t *testing.T) {
	data := validTemplateChangedData()
	data["createdAt"] = "not-a-number"
	if err := validateTemplateChangedData(data); err == nil {
		t.Fatal("Expected error for non-numeric createdAt")
	}
}

func TestValidateEvent_TemplateChanged_RoutesToTemplateValidator(t *testing.T) {
	event := &Event{
		ID:               "event-1",
		Type:             EventTypeTemplateChanged,
		CreatorPublicKey: "pk-1",
		Data:             validTemplateChangedData(),
	}
	if err := ValidateEvent(event); err != nil {
		t.Fatalf("Expected template_changed event to route to its validator and pass, got: %v", err)
	}
}

func TestIsUserScoped_TemplateChanged(t *testing.T) {
	if !IsUserScoped(EventTypeTemplateChanged) {
		t.Fatal("Expected template_changed to be user-scoped")
	}
}

func TestIsValidOffsetSpec(t *testing.T) {
	valid := []string{"PT0S", "-PT30M", "PT1H", "PT1H30M", "P1D", "-P1D"}
	for _, spec := range valid {
		if !isValidOffsetSpec(spec) {
			t.Errorf("Expected %q to be valid", spec)
		}
	}

	invalid := []string{"", "PT", "-PT", "P", "PDay", "30M", "PT-30M", "tomorrow"}
	for _, spec := range invalid {
		if isValidOffsetSpec(spec) {
			t.Errorf("Expected %q to be invalid", spec)
		}
	}
}

func memberRoleChangedData(newRole string) map[string]interface{} {
	return map[string]interface{}{"applicationId": "app-1", "memberPublicKey": "pk-1", "oldRole": "member", "newRole": newRole}
}

func TestValidateEvent_MemberRoleChanged_ShouldRejectOwnerNewRole(t *testing.T) {
	// given
	evt := &Event{ID: "e1", Type: EventTypeMemberRoleChanged, CreatorPublicKey: "pk-2", Data: memberRoleChangedData("owner")}

	// when
	err := ValidateEvent(evt)

	// then
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("Expected ErrValidation for newRole owner, got: %v", err)
	}
}

func TestValidateEvent_MemberRoleChanged_ShouldRejectUnknownNewRole(t *testing.T) {
	// given
	evt := &Event{ID: "e1", Type: EventTypeMemberRoleChanged, CreatorPublicKey: "pk-2", Data: memberRoleChangedData("superuser")}

	// when
	err := ValidateEvent(evt)

	// then
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("Expected ErrValidation for an unknown newRole, got: %v", err)
	}
}

func TestValidateEvent_MemberRoleChanged_ShouldAcceptAdminNewRole(t *testing.T) {
	// given
	evt := &Event{ID: "e1", Type: EventTypeMemberRoleChanged, CreatorPublicKey: "pk-2", Data: memberRoleChangedData("admin")}

	// when
	err := ValidateEvent(evt)

	// then
	if err != nil {
		t.Fatalf("Expected newRole admin to pass, got: %v", err)
	}
}

func TestValidateEvent_MemberAdded_ShouldRejectOwnerRole(t *testing.T) {
	// given
	evt := &Event{ID: "e1", Type: EventTypeMemberAdded, CreatorPublicKey: "pk-2", Data: map[string]interface{}{
		"applicationId": "app-1", "memberPublicKey": "pk-1", "userDisplayName": "Name", "role": "owner",
	}}

	// when
	err := ValidateEvent(evt)

	// then
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("Expected ErrValidation for member_added role owner, got: %v", err)
	}
}

func editModeData(changes ...interface{}) map[string]interface{} {
	return map[string]interface{}{"version": float64(1), "applicationId": "app-1", "changes": changes}
}

func TestValidateApplicationAfterEditModeChangedData_ShouldAcceptClientPayload(t *testing.T) {
	// given: the shapes the app's computeStructureChanges emits, nulls included
	data := editModeData(
		map[string]interface{}{"changeType": "component_group_removed", "entityType": "component_group", "entityId": "g-old", "data": nil, "index": nil, "changedFields": nil},
		map[string]interface{}{"changeType": "component_removed", "entityType": "component", "entityId": "c-old", "data": nil, "index": nil, "changedFields": nil},
		map[string]interface{}{"changeType": "component_group_added", "entityType": "component_group", "entityId": "g-1", "data": map[string]interface{}{"id": "g-1", "applicationId": nil, "index": float64(0), "name": "G"}, "index": nil},
		map[string]interface{}{"changeType": "component_group_changed", "entityType": "component_group", "entityId": "g-1", "data": map[string]interface{}{"name": "", "index": float64(1)}},
		map[string]interface{}{"changeType": "component_added", "entityType": "component", "entityId": "c-1", "data": map[string]interface{}{"id": "c-1", "componentGroupId": "g-1", "name": "C", "index": float64(0), "data": nil}},
		map[string]interface{}{"changeType": "component_reordered", "entityType": "component", "entityId": "c-1", "index": float64(2)},
		map[string]interface{}{"changeType": "component_group_reordered", "entityType": "component_group", "entityId": "g-1", "index": float64(0)},
		map[string]interface{}{"changeType": "component_data_changed", "entityType": "component", "entityId": "c-1", "changedFields": map[string]interface{}{"title": "x"}},
	)

	// when
	err := validateApplicationAfterEditModeChangedData(data)

	// then
	if err != nil {
		t.Fatalf("Expected the client payload to pass, got: %v", err)
	}
}

func TestValidateApplicationAfterEditModeChangedData_ShouldRejectNonMapChange(t *testing.T) {
	// given
	data := editModeData("component_removed")

	// when
	err := validateApplicationAfterEditModeChangedData(data)

	// then
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("Expected ErrValidation, got: %v", err)
	}
}

func TestValidateApplicationAfterEditModeChangedData_ShouldRejectUnknownChangeType(t *testing.T) {
	// given
	data := editModeData(map[string]interface{}{"changeType": "component_exploded", "entityId": "c-1"})

	// when
	err := validateApplicationAfterEditModeChangedData(data)

	// then
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("Expected ErrValidation, got: %v", err)
	}
}

func TestValidateApplicationAfterEditModeChangedData_ShouldRejectMissingEntityID(t *testing.T) {
	// given
	data := editModeData(map[string]interface{}{"changeType": "component_removed", "entityId": ""})

	// when
	err := validateApplicationAfterEditModeChangedData(data)

	// then
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("Expected ErrValidation, got: %v", err)
	}
}

func TestValidateApplicationAfterEditModeChangedData_ShouldRejectAddedWithoutData(t *testing.T) {
	// given
	data := editModeData(map[string]interface{}{"changeType": "component_added", "entityId": "c-1", "data": nil})

	// when
	err := validateApplicationAfterEditModeChangedData(data)

	// then
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("Expected ErrValidation, got: %v", err)
	}
}

func TestValidateApplicationAfterEditModeChangedData_ShouldRejectReorderedWithoutIndex(t *testing.T) {
	// given
	data := editModeData(map[string]interface{}{"changeType": "component_reordered", "entityId": "c-1", "index": "2"})

	// when
	err := validateApplicationAfterEditModeChangedData(data)

	// then
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("Expected ErrValidation, got: %v", err)
	}
}

func TestValidateApplicationAfterEditModeChangedData_ShouldRejectDataChangedWithoutChangedFields(t *testing.T) {
	// given
	data := editModeData(map[string]interface{}{"changeType": "component_data_changed", "entityId": "c-1"})

	// when
	err := validateApplicationAfterEditModeChangedData(data)

	// then
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("Expected ErrValidation, got: %v", err)
	}
}
