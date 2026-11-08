package event

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/prappser/prappser-spaces/internal/application"
)

func guardService(t *testing.T) *EventService {
	t.Helper()
	repo := application.NewMemoryRepository()
	require := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	require(repo.RegisterApplication(&application.Application{ID: "app-1", Name: "A"}))
	require(repo.CreateComponentGroup(&application.ComponentGroup{ID: "g", ApplicationID: "app-1", Name: "G"}))
	require(repo.CreateComponent(&application.Component{ID: "c", ComponentGroupID: "g", ApplicationID: "app-1", Name: "Checklist", Data: map[string]interface{}{}}))
	require(repo.CreateComponent(&application.Component{ID: "other", ComponentGroupID: "g", ApplicationID: "app-1", Name: "Mystery", Data: map[string]interface{}{}}))
	require(repo.RegisterApplication(&application.Application{ID: "app-2", Name: "B"}))
	require(repo.CreateComponentGroup(&application.ComponentGroup{ID: "g2", ApplicationID: "app-2", Name: "G"}))
	require(repo.CreateComponent(&application.Component{ID: "foreign", ComponentGroupID: "g2", ApplicationID: "app-2", Name: "Checklist", Data: map[string]interface{}{}}))
	svc := NewEventService(nil, repo, nil, nil)
	svc.SetEntryKeys(func(name, key string) bool { return name == "Checklist" && len(key) > 5 && key[:5] == "item_" })
	return svc
}

func guardFields(kv map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range kv {
		out[k] = map[string]interface{}{"oldValue": "x", "newValue": v}
	}
	return out
}

func guardEvent(componentID string, fields map[string]interface{}) *Event {
	return &Event{Type: EventTypeComponentDataChanged, ApplicationID: "app-1", Data: map[string]interface{}{"componentId": componentID, "changedFields": fields}}
}

func keysOf(m map[string]interface{}) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestDropEntryNullDeletes_ShouldDropOnlyNullEntryKeys(t *testing.T) {
	cases := []struct {
		name      string
		component string
		fields    map[string]interface{}
		want      []string
	}{
		{"entry null dropped", "c", map[string]interface{}{"item_a": nil}, nil},
		{"tombstone kept", "c", map[string]interface{}{"item_a": ""}, []string{"item_a"}},
		{"value kept", "c", map[string]interface{}{"item_a": map[string]interface{}{"title": "x"}}, []string{"item_a"}},
		{"non-entry null kept", "c", map[string]interface{}{"title": nil}, []string{"title"}},
		{"unknown type kept", "other", map[string]interface{}{"item_a": nil}, []string{"item_a"}},
		{"other app's component kept", "foreign", map[string]interface{}{"item_a": nil}, []string{"item_a"}},
		{"unknown component kept", "missing", map[string]interface{}{"item_a": nil}, []string{"item_a"}},
		{"mixed drops only the bad one", "c", map[string]interface{}{"item_a": nil, "item_b": "", "title": nil, "other": "v"}, []string{"item_b", "title", "other"}},
	}
	for _, c := range cases {
		// given
		svc := guardService(t)
		ev := guardEvent(c.component, guardFields(c.fields))

		// when
		svc.dropEntryNullDeletes(ev)

		// then
		assert.ElementsMatch(t, c.want, keysOf(ev.Data["changedFields"].(map[string]interface{})), c.name)
	}
}

func TestDropEntryNullDeletes_ShouldCoverEditModeBatchChanges(t *testing.T) {
	// given
	svc := guardService(t)
	fields := guardFields(map[string]interface{}{"item_a": nil, "item_b": ""})
	ev := &Event{Type: EventTypeApplicationAfterEditModeChanged, ApplicationID: "app-1", Data: map[string]interface{}{
		"changes": []interface{}{map[string]interface{}{"changeType": "component_data_changed", "entityId": "c", "changedFields": fields}},
	}}

	// when
	svc.dropEntryNullDeletes(ev)

	// then
	assert.ElementsMatch(t, []string{"item_b"}, keysOf(fields))
}

func TestDropEntryNullDeletes_ShouldPassThroughWithoutLookup(t *testing.T) {
	// given
	svc := NewEventService(nil, application.NewMemoryRepository(), nil, nil)
	ev := guardEvent("c", guardFields(map[string]interface{}{"item_a": nil}))

	// when
	svc.dropEntryNullDeletes(ev)

	// then
	assert.Len(t, ev.Data["changedFields"], 1)
}
