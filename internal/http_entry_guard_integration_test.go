//go:build integration

package internal

import (
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

func registerComponentApp(t *testing.T, f *moveFixture, componentName string, data map[string]any) {
	t.Helper()
	register := f.doJSON("POST", "/applications/register", moveOwnerPK, map[string]any{
		"id":   moveAppID,
		"name": "Guarded",
		"members": []map[string]any{
			{"id": "m-owner", "role": "owner", "publicKey": moveOwnerPK},
		},
		"componentGroups": []map[string]any{{
			"id": "group-1", "name": "Group", "index": 0,
			"components": []map[string]any{{"id": "comp-1", "name": componentName, "index": 0, "data": data}},
		}},
	})
	require.Equal(t, fasthttp.StatusCreated, register.Response.StatusCode(), string(register.Response.Body()))
}

func registerMapApp(t *testing.T, f *moveFixture, place map[string]any) {
	t.Helper()
	registerComponentApp(t, f, "Map", map[string]any{"place_x": place})
}

func storedMapData(t *testing.T, f *moveFixture) map[string]any {
	t.Helper()
	var raw string
	require.NoError(t, f.db.QueryRow(`SELECT data FROM components WHERE id = 'comp-1'`).Scan(&raw))
	var data map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &data))
	return data
}

func postEvent(f *moveFixture, typ string, data map[string]any) *fasthttp.RequestCtx {
	return f.doJSON("POST", "/events", moveOwnerPK, map[string]any{"event": map[string]any{
		"id":               uuid.NewString(),
		"type":             typ,
		"creatorPublicKey": moveOwnerPK,
		"createdAt":        time.Now().Unix(),
		"version":          1,
		"data":             data,
	}})
}

func TestEvents_ComponentDataChangedWithNullEntryKey_ShouldKeepEntryAndApplyOtherFields(t *testing.T) {
	// given
	f := newMoveFixture(t)
	registerComponentApp(t, f, "Checklist", map[string]any{"item_a": map[string]any{"title": "Milk", "order": 0}})

	// when
	resp := postEvent(f, "component_data_changed", map[string]any{
		"applicationId": moveAppID, "componentId": "comp-1", "componentGroupId": "group-1",
		"changedFields": map[string]any{
			"item_a": map[string]any{"oldValue": map[string]any{"title": "Milk", "order": 0}, "newValue": nil},
			"_note":  map[string]any{"oldValue": nil, "newValue": "hello"},
		},
	})

	// then
	require.Less(t, resp.Response.StatusCode(), 300, string(resp.Response.Body()))
	data := storedMapData(t, f)
	assert.Equal(t, map[string]any{"title": "Milk", "order": float64(0)}, data["item_a"])
	assert.Equal(t, "hello", data["_note"])
}

func TestEvents_ComponentDataChangedWithNullMapPlace_ShouldKeepPlace(t *testing.T) {
	// given
	f := newMoveFixture(t)
	place := map[string]any{"v": 2, "title": "Wieliczka", "latitude": 50.06, "longitude": 19.94, "order": 0}
	registerMapApp(t, f, place)

	// when
	resp := postEvent(f, "component_data_changed", map[string]any{
		"applicationId": moveAppID, "componentId": "comp-1", "componentGroupId": "group-1",
		"changedFields": map[string]any{
			"place_x": map[string]any{"oldValue": place, "newValue": nil},
			"_note":   map[string]any{"oldValue": nil, "newValue": "hello"},
		},
	})

	// then
	require.Less(t, resp.Response.StatusCode(), 300, string(resp.Response.Body()))
	data := storedMapData(t, f)
	assert.Equal(t, "Wieliczka", data["place_x"].(map[string]any)["title"])
	assert.Equal(t, "hello", data["_note"])
}

func TestEvents_EditModeBatchWithNullMapPlace_ShouldKeepPlace(t *testing.T) {
	// given
	f := newMoveFixture(t)
	place := map[string]any{"v": 2, "title": "Wieliczka", "latitude": 50.06, "longitude": 19.94, "order": 0}
	registerMapApp(t, f, place)

	// when
	resp := postEvent(f, "application_after_edit_mode_changed", map[string]any{
		"applicationId": moveAppID,
		"changes": []any{map[string]any{
			"changeType": "component_data_changed", "entityId": "comp-1",
			"changedFields": map[string]any{
				"place_x": map[string]any{"oldValue": place, "newValue": nil},
				"_note":   map[string]any{"oldValue": nil, "newValue": "hello"},
			},
		}},
	})

	// then
	require.Less(t, resp.Response.StatusCode(), 300, string(resp.Response.Body()))
	data := storedMapData(t, f)
	assert.Equal(t, "Wieliczka", data["place_x"].(map[string]any)["title"])
	assert.Equal(t, "hello", data["_note"])
}

func TestEvents_ComponentDataChangedWithOnlyNullEntryKey_ShouldSucceedAndKeepEntry(t *testing.T) {
	// given
	f := newMoveFixture(t)
	place := map[string]any{"v": 2, "title": "Wieliczka", "latitude": 50.06, "longitude": 19.94, "order": 0}
	registerMapApp(t, f, place)

	// when
	resp := postEvent(f, "component_data_changed", map[string]any{
		"applicationId": moveAppID, "componentId": "comp-1", "componentGroupId": "group-1",
		"changedFields": map[string]any{"place_x": map[string]any{"oldValue": place, "newValue": nil}},
	})

	// then
	require.Less(t, resp.Response.StatusCode(), 300, string(resp.Response.Body()))
	assert.Equal(t, "Wieliczka", storedMapData(t, f)["place_x"].(map[string]any)["title"])
}
