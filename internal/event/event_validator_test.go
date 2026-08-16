package event

import (
	"encoding/json"
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
