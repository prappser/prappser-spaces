package mcp

import (
	"errors"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/prappser/prappser-spaces/internal/component"
)

func ids(items []checklistItem) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.id
	}
	return out
}

func TestReadChecklist_ShouldReadLegacyItemsWithIndexAsDefaultOrder(t *testing.T) {
	// given
	data := map[string]any{"items": []any{
		map[string]any{"id": "a", "title": "A", "checked": false},
		map[string]any{"id": "b", "title": "B", "checked": true, "order": 9.0},
		map[string]any{"title": "no id"},
	}}

	// when
	items := readChecklist(data)

	// then
	assert.Equal(t, []string{"a", "b"}, ids(items))
	assert.Equal(t, 0.0, items[0].order)
	assert.Equal(t, 9.0, items[1].order)
}

func TestReadChecklist_ShouldLetKeyedItemOverrideLegacyAndTombstoneRemoveBoth(t *testing.T) {
	// given
	data := map[string]any{
		"items": []any{
			map[string]any{"id": "a", "title": "old"},
			map[string]any{"id": "b", "title": "gone"},
		},
		"item_a": map[string]any{"title": "new", "checked": true, "order": 2.0},
		"item_b": "",
		"item_c": "",
		"item_":  map[string]any{"title": "no id", "checked": false},
		"item_d": map[string]any{"title": "D", "checked": false, "order": 2.0},
		"other":  "x",
	}

	// when
	items := readChecklist(data)

	// then
	assert.Equal(t, []string{"a", "d"}, ids(items))
	assert.Equal(t, "new", items[0].value["title"])
}

func TestReadChecklist_ShouldSortByOrderThenID(t *testing.T) {
	// given
	data := map[string]any{
		"item_z": map[string]any{"order": 1.0},
		"item_b": map[string]any{"order": 2.0},
		"item_a": map[string]any{"order": 2.0},
	}

	// when
	items := readChecklist(data)

	// then
	assert.Equal(t, []string{"z", "a", "b"}, ids(items))
}

func TestNextOrder_ShouldBeZeroWhenEmptyElseMaxPlusOne(t *testing.T) {
	// given
	items := readChecklist(map[string]any{"item_a": map[string]any{"order": 4.5}, "item_b": map[string]any{"order": 1.0}})

	// then
	assert.Equal(t, 0.0, nextOrder(nil))
	assert.Equal(t, 5.5, nextOrder(items))
}

func TestReadChecklist_ShouldGiveLegacyPatchBaseWithoutIDAndWithOrder(t *testing.T) {
	// given
	data := map[string]any{"items": []any{map[string]any{"id": "x"}, map[string]any{"id": "a", "title": "t", "checked": false, "priority": "high"}}}

	// when
	items := readChecklist(data)

	// then
	assert.Equal(t, map[string]any{"title": "t", "checked": false, "priority": "high", "order": 1.0}, items[1].value)
}

func TestCleanTitle_ShouldCountUTF16Units(t *testing.T) {
	// given
	atLimit := strings.Repeat("a", 998) + "😀"
	overLimit := strings.Repeat("a", 999) + "😀"

	// when
	got, errOK := cleanTitle("  " + atLimit + " ")
	_, errOver := cleanTitle(overLimit)
	_, errEmpty := cleanTitle("   ")

	// then
	assert.NoError(t, errOK)
	assert.Equal(t, atLimit, got)
	assert.Error(t, errOver)
	assert.Error(t, errEmpty)
}

func TestChecklistSchema_ShouldMergeItemKeysPerEntry(t *testing.T) {
	// given
	v, err := component.NewValidator()
	require.NoError(t, err)

	// when
	mode, ok := v.MergeMode("Checklist", "item_x")

	// then
	assert.True(t, ok)
	assert.Equal(t, "per-entry", mode)
}

func TestValidationResult_ShouldWrapFieldsAsUntrusted(t *testing.T) {
	// given
	err := component.ValidationErrors{{Path: "/item_a", Message: "bad"}}

	// when
	res, ok := validationResult(err)
	_, other := validationResult(errors.New("boom"))

	// then
	require.True(t, ok)
	assert.False(t, other)
	assert.True(t, res.IsError)
	assert.JSONEq(t,
		`{"note":"`+untrustedNote+`","error":"invalid data","untrusted":{"fields":[{"path":"/item_a","message":"bad"}]}}`,
		res.Content[0].(*sdk.TextContent).Text)
}
