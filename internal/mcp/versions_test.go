package mcp

import (
	"encoding/json"
	"os"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/prappser/prappser-spaces/internal/component"
	"github.com/prappser/prappser-spaces/internal/component/lens"
)

func listValidator(t *testing.T) *component.Validator {
	t.Helper()
	v, err := component.NewValidatorFS(os.DirFS("testdata"))
	require.NoError(t, err)
	return v
}

func embeddedValidator(t *testing.T) *component.Validator {
	t.Helper()
	v, err := component.NewValidator()
	require.NoError(t, err)
	return v
}

func v2Item(title string, checked bool) map[string]any {
	return map[string]any{"v": float64(2), "title": title, "checked": checked}
}

func resultText(res *sdk.CallToolResult) string {
	return res.Content[0].(*sdk.TextContent).Text
}

func TestSteps_ShouldLoadFixtureMigrations(t *testing.T) {
	// given
	v := listValidator(t)

	// when
	item, lossyItem, errItem := lens.Migrate(v.Steps("List"), "item_a", map[string]any{"title": "x", "done": true}, 2)
	note, lossyNote, errNote := lens.Migrate(v.Steps("List"), "n_a", map[string]any{"title": "x", "tags": []any{"a", "b"}}, 2)

	// then
	require.NoError(t, errItem)
	require.NoError(t, errNote)
	assert.False(t, lossyItem)
	assert.True(t, lossyNote)
	assert.Equal(t, true, plain(item).(map[string]any)["checked"])
	assert.Equal(t, "a", plain(note).(map[string]any)["tags"])
}

func TestComponentData_ShouldMigrateFullEntriesToReaderVersion(t *testing.T) {
	// given
	v := listValidator(t)
	stored := map[string]any{
		"item_a": map[string]any{"title": "Milk", "done": true},
		"e_a":    `{"what":"Dinner","amt":10}`,
		"_title": "Shop",
	}

	// when
	view, states := componentData(v, "List", stored)

	// then
	assert.Equal(t, map[string]any{"v": float64(2), "title": "Milk", "checked": true}, view["item_a"])
	assert.JSONEq(t, `{"v":2,"what":"Dinner","amount":10}`, view["e_a"].(string))
	assert.Equal(t, "Shop", view["_title"])
	assert.Empty(t, states)
	assert.Equal(t, true, stored["item_a"].(map[string]any)["done"])
}

func TestComponentData_ShouldFlagNonFullEntries(t *testing.T) {
	// given
	v := listValidator(t)
	newer := map[string]any{"v": float64(3), "title": "Milk", "whatever": 1.0}
	stored := map[string]any{
		"n_ro":   map[string]any{"title": "t", "tags": []any{"a", "b"}},
		"item_n": newer,
		"item_b": map[string]any{"v": "x", "title": "t", "done": false},
		"item_z": map[string]any{"v": float64(0), "title": "t", "done": false},
		"item_f": v2Item("ok", false),
	}

	// when
	view, states := componentData(v, "List", stored)

	// then
	assert.Equal(t, map[string]string{"n_ro": "read-only", "item_n": "needs-update", "item_b": "bad-version", "item_z": "bad-version"}, states)
	assert.Equal(t, map[string]any{"v": float64(2), "title": "t", "tags": "a"}, view["n_ro"])
	assert.Equal(t, newer, view["item_n"])
	assert.Equal(t, stored["item_b"], view["item_b"])
	assert.Equal(t, v2Item("ok", false), view["item_f"])
}

func TestComponentData_ShouldReturnStoredDataForV1Types(t *testing.T) {
	// given
	v := embeddedValidator(t)
	stored := map[string]any{"vote_a": "opt", "vote_b": "", "_title": "x"}

	// when
	view, states := componentData(v, "Poll", stored)

	// then
	assert.Equal(t, stored, view)
	assert.Empty(t, states)
}

func TestComponentData_ShouldPassThroughUnknownTypesAndTombstones(t *testing.T) {
	// given
	v := listValidator(t)
	stored := map[string]any{"item_gone": "", "e_gone": ""}

	// when
	view, states := componentData(v, "List", stored)
	unknown, unknownStates := componentData(v, "Nope", map[string]any{"item_a": map[string]any{"done": true}})

	// then
	assert.Equal(t, stored, view)
	assert.Empty(t, states)
	assert.Equal(t, map[string]any{"item_a": map[string]any{"done": true}}, unknown)
	assert.Empty(t, unknownStates)
}

func plan(t *testing.T, v *component.Validator, typ string, stored, set map[string]any) (map[string]any, *sdk.CallToolResult, error) {
	t.Helper()
	return planWrite(v, typ, stored, set, "pk", true)
}

func TestPlanWrite_ShouldWriteV2ShapeWhenEditingV1Entry(t *testing.T) {
	// given
	v := listValidator(t)
	stored := map[string]any{"item_a": map[string]any{"title": "Milk", "done": false}}

	// when
	written, res, err := plan(t, v, "List", stored, map[string]any{"item_a": map[string]any{"title": "Milk", "checked": true}})

	// then
	require.NoError(t, err)
	require.Nil(t, res)
	assert.Equal(t, map[string]any{"item_a": v2Item("Milk", true)}, written)
}

func TestPlanWrite_ShouldWriteNothingWhenV2EntryIsUnchanged(t *testing.T) {
	// given
	v := listValidator(t)
	stored := map[string]any{"item_a": v2Item("Milk", false)}

	// when
	written, res, err := plan(t, v, "List", stored, map[string]any{"item_a": map[string]any{"title": "Milk", "checked": false}})

	// then
	require.NoError(t, err)
	require.Nil(t, res)
	assert.Empty(t, written)
}

func TestPlanWrite_ShouldWriteNothingWhenV1EntryIsEditedToItsMigratedView(t *testing.T) {
	// given
	v := listValidator(t)
	stored := map[string]any{"item_a": map[string]any{"title": "Milk", "done": false}}

	// when
	written, _, err := plan(t, v, "List", stored, map[string]any{"item_a": map[string]any{"title": "Milk", "checked": false}})

	// then
	require.NoError(t, err)
	assert.Empty(t, written)
}

func TestPlanWrite_ShouldDiffChangedValueIntoV2Original(t *testing.T) {
	// given
	v := listValidator(t)
	stored := map[string]any{"item_a": v2Item("Milk", false)}

	// when
	written, _, err := plan(t, v, "List", stored, map[string]any{"item_a": map[string]any{"title": "Milk", "checked": true, "order": 3.0}})

	// then
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"item_a": map[string]any{"v": float64(2), "title": "Milk", "checked": true, "order": float64(3)}}, written)
}

func TestPlanWrite_ShouldOnlyReportKeysThatWrote(t *testing.T) {
	// given
	v := listValidator(t)
	stored := map[string]any{"item_a": v2Item("Milk", false), "item_b": v2Item("Eggs", false)}

	// when
	written, _, err := plan(t, v, "List", stored, map[string]any{
		"item_a": map[string]any{"title": "Milk", "checked": false},
		"item_b": map[string]any{"title": "Eggs", "checked": true},
	})

	// then
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"item_b": v2Item("Eggs", true)}, written)
}

func TestPlanWrite_ShouldRefuseEditOfReadOnlyEntryButAllowDelete(t *testing.T) {
	// given
	v := listValidator(t)
	stored := map[string]any{"n_a": map[string]any{"title": "t", "tags": []any{"a", "b"}}}

	// when
	_, _, editErr := plan(t, v, "List", stored, map[string]any{"n_a": map[string]any{"title": "t", "tags": "a"}})
	written, _, delErr := plan(t, v, "List", stored, map[string]any{"n_a": ""})

	// then
	require.Error(t, editErr)
	assert.Contains(t, editErr.Error(), "read-only")
	require.NoError(t, delErr)
	assert.Equal(t, map[string]any{"n_a": ""}, written)
}

func TestPlanWrite_ShouldRefuseEditAndDeleteOfNewerEntry(t *testing.T) {
	// given
	v := listValidator(t)
	stored := map[string]any{"item_a": map[string]any{"v": float64(3), "title": "Milk", "checked": false}}

	// when
	_, _, editErr := plan(t, v, "List", stored, map[string]any{"item_a": map[string]any{"title": "Milk", "checked": true}})
	_, _, delErr := plan(t, v, "List", stored, map[string]any{"item_a": ""})

	// then
	require.Error(t, editErr)
	assert.Contains(t, editErr.Error(), "needs an app update")
	require.Error(t, delErr)
	assert.Contains(t, delErr.Error(), "needs an app update")
}

func TestPlanWrite_ShouldRefuseEntryWithBadVersion(t *testing.T) {
	// given
	v := listValidator(t)
	stored := map[string]any{"item_a": map[string]any{"v": "two", "title": "Milk", "checked": false}}

	// when
	_, _, editErr := plan(t, v, "List", stored, map[string]any{"item_a": map[string]any{"title": "Milk", "checked": true}})
	_, _, delErr := plan(t, v, "List", stored, map[string]any{"item_a": ""})

	// then
	require.Error(t, editErr)
	assert.Contains(t, editErr.Error(), "needs an app update")
	require.Error(t, delErr)
}

func TestPlanWrite_ShouldRejectVersionOutOfRange(t *testing.T) {
	// given
	v := listValidator(t)

	// when
	_, _, tooNew := plan(t, v, "List", nil, map[string]any{"item_a": map[string]any{"v": 3.0, "title": "x", "checked": false}})
	_, _, zero := plan(t, v, "List", nil, map[string]any{"item_b": map[string]any{"v": 0.0, "title": "x", "checked": false}})
	_, _, fraction := plan(t, v, "List", nil, map[string]any{"item_c": map[string]any{"v": 1.5, "title": "x", "checked": false}})

	// then
	for _, err := range []error{tooNew, zero, fraction} {
		require.Error(t, err)
		assert.Contains(t, err.Error(), "v must be an integer between 1 and 2")
	}
}

func TestPlanWrite_ShouldSetVersionToReaderWhenInRange(t *testing.T) {
	// given
	v := listValidator(t)

	// when
	written, _, err := plan(t, v, "List", nil, map[string]any{"item_a": map[string]any{"v": 1.0, "title": "x", "checked": false}})

	// then
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"item_a": v2Item("x", false)}, written)
}

func TestPlanWrite_ShouldInjectVersionOnNewEntryWhenReaderIsV2(t *testing.T) {
	// given
	v := listValidator(t)

	// when
	written, _, err := plan(t, v, "List", nil, map[string]any{"item_*": map[string]any{"title": "x", "checked": false}})

	// then
	require.NoError(t, err)
	require.Len(t, written, 1)
	for k, val := range written {
		assert.Contains(t, k, "item_")
		assert.Equal(t, v2Item("x", false), val)
	}
}

func TestPlanWrite_ShouldNotInjectVersionForV1Type(t *testing.T) {
	// given
	v := embeddedValidator(t)

	// when
	written, res, err := plan(t, v, "Poll", nil, map[string]any{"vote_pk": "a"})

	// then
	require.NoError(t, err)
	require.Nil(t, res)
	assert.Equal(t, map[string]any{"vote_pk": "a"}, written)
}

func TestPlanWrite_ShouldReencodeNewEncodedEntryWithSameDecodedValue(t *testing.T) {
	// given
	v := listValidator(t)
	raw := `{ "what": "A&B <c>", "amount": 10 }`

	// when
	written, res, err := plan(t, v, "List", nil, map[string]any{"e_a": raw})

	// then
	require.NoError(t, err)
	require.Nil(t, res)
	assert.JSONEq(t, `{"v":2,"what":"A&B <c>","amount":10}`, written["e_a"].(string))
	assert.Contains(t, written["e_a"], "A&B <c>")
}

func TestPlanWrite_ShouldWriteV2ShapeWhenEditingV1EncodedEntry(t *testing.T) {
	// given
	v := listValidator(t)
	stored := map[string]any{"e_a": `{"what":"Dinner","amt":10}`}

	// when
	written, _, err := plan(t, v, "List", stored, map[string]any{"e_a": `{"what":"Dinner","amount":12}`})
	same, _, sameErr := plan(t, v, "List", stored, map[string]any{"e_a": `{"what":"Dinner","amount":10}`})

	// then
	require.NoError(t, err)
	assert.JSONEq(t, `{"v":2,"what":"Dinner","amount":12}`, written["e_a"].(string))
	require.NoError(t, sameErr)
	assert.Empty(t, same)
}

func TestPlanWrite_ShouldDeleteFullEntry(t *testing.T) {
	// given
	v := listValidator(t)
	stored := map[string]any{"item_a": map[string]any{"title": "Milk", "done": false}}

	// when
	written, _, err := plan(t, v, "List", stored, map[string]any{"item_a": ""})

	// then
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"item_a": ""}, written)
}

func TestPlanWrite_ShouldRunAccessRulesOnTheMigratedOldValue(t *testing.T) {
	// given
	v := listValidator(t)
	stored := map[string]any{
		"allowToggleInUsage": false,
		"item_a":             map[string]any{"title": "Milk", "done": false},
	}

	// when
	_, _, toggle := planWrite(v, "List", stored, map[string]any{"item_a": map[string]any{"title": "Milk", "checked": true}}, "pk", false)
	_, _, retitle := planWrite(v, "List", stored, map[string]any{"item_a": map[string]any{"title": "Bread", "checked": false}}, "pk", false)

	// then
	require.Error(t, toggle)
	assert.Contains(t, toggle.Error(), "turned off by allowToggleInUsage")
	assert.NoError(t, retitle)
}

func TestPlanWrite_ShouldExplainV2ShapeWhenDataIsInvalid(t *testing.T) {
	// given
	v := listValidator(t)

	// when
	_, res, err := plan(t, v, "List", nil, map[string]any{"item_a": map[string]any{"title": 5, "checked": false}})
	_, resEncoded, errEncoded := plan(t, v, "List", nil, map[string]any{"e_a": `{"what":"x","amt":1}`})

	// then
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Contains(t, resultText(res), "invalid data: values must use the v2 shape, see describe_component")
	require.NoError(t, errEncoded)
	require.NotNil(t, resEncoded)
	assert.Contains(t, resultText(resEncoded), "v2 shape")
}

func TestPlanWrite_ShouldKeepErrorWordingForV1Types(t *testing.T) {
	// given
	v := embeddedValidator(t)

	// when
	_, res, err := plan(t, v, "Poll", nil, map[string]any{"vote_pk": 5})

	// then
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Contains(t, resultText(res), `"error":"invalid data"`)
	assert.NotContains(t, resultText(res), "shape")
}

func TestPlanWrite_ShouldNotSeeVersionDiffWhenMemberTogglesWithoutV(t *testing.T) {
	// given
	v := listValidator(t)
	flags := map[string]any{"allowAddInUsage": false, "allowToggleInUsage": true}
	cases := map[string]any{
		"v1": map[string]any{"title": "Milk", "done": false},
		"v2": v2Item("Milk", false),
	}
	for name, entry := range cases {
		stored := map[string]any{"item_a": entry}
		for k, f := range flags {
			stored[k] = f
		}

		// when
		written, _, toggle := planWrite(v, "List", stored, map[string]any{"item_a": map[string]any{"title": "Milk", "checked": true}}, "pk", false)
		_, _, retitle := planWrite(v, "List", stored, map[string]any{"item_a": map[string]any{"title": "Bread", "checked": false}}, "pk", false)

		// then
		require.NoError(t, toggle, name)
		assert.Equal(t, map[string]any{"item_a": v2Item("Milk", true)}, written, name)
		require.Error(t, retitle, name)
		assert.Contains(t, retitle.Error(), "turned off by allowAddInUsage", name)
	}
}

func TestPlanWrite_ShouldNotSeeVersionDiffForV1TypeEntryWithExplicitV(t *testing.T) {
	// given
	v := embeddedValidator(t)
	stored := map[string]any{"allowAddInUsage": false, "item_a": map[string]any{"v": float64(1), "title": "Milk", "checked": false}}

	// when
	written, _, err := planWrite(v, "Checklist", stored, map[string]any{"item_a": map[string]any{"title": "Milk", "checked": true}}, "pk", false)

	// then
	require.NoError(t, err)
	assert.Len(t, written, 1)
}

func TestPlanWrite_ShouldRefuseWholeBatchWhenOneKeyIsRefused(t *testing.T) {
	// given
	v := listValidator(t)
	stored := map[string]any{"item_a": v2Item("Milk", false), "item_n": map[string]any{"v": float64(3), "title": "x"}}

	// when
	written, _, err := plan(t, v, "List", stored, map[string]any{
		"item_a": map[string]any{"title": "Milk", "checked": true},
		"item_n": map[string]any{"title": "x", "checked": true},
	})

	// then
	require.Error(t, err)
	assert.Empty(t, written)
}

func TestComponentData_ShouldFlagMalformedEntriesAsBadVersion(t *testing.T) {
	// given
	v := listValidator(t)
	stored := map[string]any{
		"item_a": "oops",
		"n_a":    float64(7),
		"e_a":    "not json",
		"e_b":    "[1]",
		"e_c":    float64(7),
		"item_g": "",
		"e_g":    "",
	}

	// when
	view, states := componentData(v, "List", stored)

	// then
	assert.Equal(t, map[string]string{"item_a": "bad-version", "n_a": "bad-version", "e_a": "bad-version", "e_b": "bad-version", "e_c": "bad-version"}, states)
	assert.Equal(t, stored, view)
}

func TestPlanWrite_ShouldRefuseEditAndDeleteOfMalformedEntry(t *testing.T) {
	// given
	v := listValidator(t)
	for _, tc := range []struct {
		key string
		raw any
		set any
	}{
		{"item_a", "oops", map[string]any{"title": "x", "checked": true}},
		{"e_a", "not json", `{"v":2,"what":"x","amount":1}`},
		{"e_b", "[1]", `{"v":2,"what":"x","amount":1}`},
	} {
		stored := map[string]any{tc.key: tc.raw}

		// when
		_, _, editErr := plan(t, v, "List", stored, map[string]any{tc.key: tc.set})
		_, _, delErr := plan(t, v, "List", stored, map[string]any{tc.key: ""})

		// then
		require.Error(t, editErr, tc.key)
		assert.Contains(t, editErr.Error(), "needs an app update")
		require.Error(t, delErr, tc.key)
		assert.Contains(t, delErr.Error(), "needs an app update")
	}
}

func TestPlanWrite_ShouldTreatTombstoneAsNewEntry(t *testing.T) {
	// given
	v := listValidator(t)
	stored := map[string]any{"item_a": ""}

	// when
	written, res, err := plan(t, v, "List", stored, map[string]any{"item_a": map[string]any{"title": "Milk", "checked": false}})

	// then
	require.NoError(t, err)
	require.Nil(t, res)
	assert.Equal(t, map[string]any{"item_a": v2Item("Milk", false)}, written)
}

func TestPlanWrite_ShouldWriteNothingWhenDeletingAbsentOrDeletedEntry(t *testing.T) {
	// given
	v := listValidator(t)
	stored := map[string]any{"item_b": "", "e_b": ""}

	// when
	written, res, err := plan(t, v, "List", stored, map[string]any{"item_a": "", "item_b": "", "e_a": "", "e_b": ""})
	mixed, _, mixedErr := plan(t, v, "List", stored, map[string]any{"item_a": "", "item_c": map[string]any{"title": "Eggs", "checked": true}})

	// then
	require.NoError(t, err)
	require.Nil(t, res)
	assert.Empty(t, written)
	require.NoError(t, mixedErr)
	assert.Equal(t, map[string]any{"item_c": v2Item("Eggs", true)}, mixed)
}

func TestPlanWrite_ShouldStillDeleteExistingEntry(t *testing.T) {
	// given
	v := listValidator(t)
	stored := map[string]any{"item_a": v2Item("Milk", false)}

	// when
	written, _, err := plan(t, v, "List", stored, map[string]any{"item_a": ""})

	// then
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"item_a": ""}, written)
}

func TestComponentData_ShouldClassifyVersionLikeLens(t *testing.T) {
	// given
	v := listValidator(t)
	for _, raw := range []string{"2.0000000000000001", "2", "2.0", "1e0", "0", "1.5", `"2"`} {
		obj := map[string]any{"title": "t", "checked": false, "v": json.Number(raw)}
		if raw == `"2"` {
			obj["v"] = "2"
		}
		_, lensErr := lens.Version(obj)
		stored := map[string]any{"item_a": obj, "e_a": `{"what":"t","amount":1,"v":` + raw + `}`}

		// when
		_, states := componentData(v, "List", stored)

		// then
		if lensErr != nil {
			assert.Equal(t, "bad-version", states["item_a"], raw)
			assert.Equal(t, "bad-version", states["e_a"], raw)
		} else {
			assert.NotEqual(t, "bad-version", states["item_a"], raw)
			assert.NotEqual(t, "bad-version", states["e_a"], raw)
		}
	}
}

func TestComponentData_ShouldFlagNullEntriesAsBadVersion(t *testing.T) {
	// given
	v := listValidator(t)
	stored := map[string]any{"item_a": nil, "e_a": nil}

	// when
	view, states := componentData(v, "List", stored)

	// then
	assert.Equal(t, map[string]string{"item_a": "bad-version", "e_a": "bad-version"}, states)
	assert.Equal(t, stored, view)
}

func TestPlanWrite_ShouldRefuseEditAndDeleteOfNullEntry(t *testing.T) {
	// given
	v := listValidator(t)
	stored := map[string]any{"item_a": nil, "e_a": nil}

	// when
	_, _, editObj := plan(t, v, "List", stored, map[string]any{"item_a": map[string]any{"title": "x", "checked": true}})
	_, _, deleteObj := plan(t, v, "List", stored, map[string]any{"item_a": ""})
	_, _, editEnc := plan(t, v, "List", stored, map[string]any{"e_a": `{"v":2,"what":"x","amount":1}`})
	_, _, deleteEnc := plan(t, v, "List", stored, map[string]any{"e_a": ""})

	// then
	for _, err := range []error{editObj, deleteObj, editEnc, deleteEnc} {
		require.Error(t, err)
		assert.Contains(t, err.Error(), "needs an app update")
	}
}

func TestComponentData_ShouldPassNonObjectEntriesThroughForUnversionedType(t *testing.T) {
	// given
	v := listValidator(t)
	stored := map[string]any{"e_a": "not json", "n_a": "oops", "item_a": nil, "item_b": float64(3)}

	// when
	view, states := componentData(v, "Nope", stored)

	// then
	assert.Equal(t, stored, view)
	assert.Empty(t, states)
}

func TestComponentData_ShouldMigrateV1ChecklistItemToAssigneePublicKey(t *testing.T) {
	// given
	v := embeddedValidator(t)
	stored := map[string]any{"item_a": map[string]any{"title": "Milk", "checked": false, "assignedMemberId": "pk2"}}

	// when
	view, states := componentData(v, "Checklist", stored)

	// then
	assert.Equal(t, map[string]any{"v": float64(2), "title": "Milk", "checked": false, "assigneePublicKey": "pk2"}, view["item_a"])
	assert.Empty(t, states)
}

func TestPlanWrite_ShouldWriteChecklistV1ItemBackAtV2(t *testing.T) {
	// given
	v := embeddedValidator(t)
	stored := map[string]any{"item_a": map[string]any{"title": "Milk", "checked": false, "assignedMemberId": "pk2"}}

	// when
	written, res, err := plan(t, v, "Checklist", stored, map[string]any{"item_a": map[string]any{"title": "Milk", "checked": true, "assigneePublicKey": "pk2"}})

	// then
	require.NoError(t, err)
	require.Nil(t, res)
	assert.Equal(t, map[string]any{"item_a": map[string]any{"v": float64(2), "title": "Milk", "checked": true, "assigneePublicKey": "pk2"}}, written)
}

func TestPlanWrite_ShouldInjectVersionOnNewChecklistItem(t *testing.T) {
	// given
	v := embeddedValidator(t)

	// when
	written, res, err := plan(t, v, "Checklist", nil, map[string]any{"item_*": map[string]any{"title": "x", "checked": false}})

	// then
	require.NoError(t, err)
	require.Nil(t, res)
	require.Len(t, written, 1)
	for _, val := range written {
		assert.Equal(t, v2Item("x", false), val)
	}
}

func TestPlanWrite_ShouldRejectOldAssigneeNameOnChecklistV2Item(t *testing.T) {
	// given
	v := embeddedValidator(t)
	item := map[string]any{"v": float64(2), "title": "x", "checked": false, "assignedMemberId": "pk2"}

	// when
	_, res, err := plan(t, v, "Checklist", nil, map[string]any{"item_a": item})

	// then
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Contains(t, resultText(res), "assignedMemberId")
}

func TestComponentData_ShouldMigrateV1ChecklistItemWithNullAssignee(t *testing.T) {
	// given
	v := embeddedValidator(t)
	stored := map[string]any{"item_a": map[string]any{"title": "Milk", "checked": false, "assignedMemberId": nil}}

	// when
	view, states := componentData(v, "Checklist", stored)

	// then
	assert.Equal(t, map[string]any{"v": float64(2), "title": "Milk", "checked": false, "assigneePublicKey": nil}, view["item_a"])
	assert.Empty(t, states)
}

func TestPlanWrite_ShouldWriteChecklistV1ItemWithNullAssigneeBackAtV2(t *testing.T) {
	// given
	v := embeddedValidator(t)
	stored := map[string]any{"item_a": map[string]any{"title": "Milk", "checked": false, "assignedMemberId": nil}}

	// when
	written, res, err := plan(t, v, "Checklist", stored, map[string]any{"item_a": map[string]any{"title": "Milk", "checked": true, "assigneePublicKey": nil}})

	// then
	require.NoError(t, err)
	require.Nil(t, res)
	assert.Equal(t, map[string]any{"item_a": map[string]any{"v": float64(2), "title": "Milk", "checked": true, "assigneePublicKey": nil}}, written)
}
