package event

import "testing"

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
