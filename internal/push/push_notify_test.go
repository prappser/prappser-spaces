package push

import (
	"encoding/json"
	"io/fs"
	"os"
	"testing"
	"testing/fstest"

	"github.com/prappser/prappser-spaces/internal/component"
	"github.com/prappser/prappser-spaces/internal/component/lens"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validatorWith loads the embedded schemas with the x-notify rule of one schema file rewritten.
// mutate gets the rule (the first one of a list) as a map and returns the replacement; nil removes the annotation.
func validatorWith(t *testing.T, file string, mutate func(rule map[string]any) any) *component.Validator {
	t.Helper()
	fsys := fstest.MapFS{}
	root := os.DirFS("../component")
	err := fs.WalkDir(root, "schemas", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(root, p)
		if err != nil {
			return err
		}
		if p == "schemas/component/"+file {
			data = rewriteNotify(t, data, mutate)
		}
		fsys[p] = &fstest.MapFile{Data: data}
		return nil
	})
	require.NoError(t, err)
	v, err := component.NewValidatorFS(fsys)
	require.NoError(t, err)
	return v
}

func rewriteNotify(t *testing.T, data []byte, mutate func(map[string]any) any) []byte {
	t.Helper()
	var doc map[string]any
	require.NoError(t, json.Unmarshal(data, &doc))
	found := false
	for _, section := range []string{"properties", "patternProperties"} {
		entries, _ := doc[section].(map[string]any)
		for _, e := range entries {
			entry := e.(map[string]any)
			list, isList := entry["x-notify"].([]any)
			rule, ok := entry["x-notify"].(map[string]any)
			if isList && len(list) > 0 {
				rule, ok = list[0].(map[string]any)
			}
			if !ok {
				continue
			}
			found = true
			out := mutate(rule)
			switch {
			case out == nil:
				delete(entry, "x-notify")
			case isList:
				list[0] = out
			default:
				entry["x-notify"] = out
			}
		}
	}
	require.True(t, found, "schema has no x-notify to rewrite")
	out, err := json.Marshal(doc)
	require.NoError(t, err)
	return out
}

func chatBody(t *testing.T, v *component.Validator, key, value string) (notice, bool) {
	t.Helper()
	svc := &PushService{validator: v}
	return svc.describe(gComp("chat-1", gChange(key, nil, value)), goldenApp(), "Ann", false, "en")
}

func TestDescribe_ShouldPushChatMessageWithUnchangedSchema(t *testing.T) {
	// given
	v := validatorWith(t, "chat.v1.schema.json", func(rule map[string]any) any { return rule })

	// when
	n, ok := chatBody(t, v, gChatA, `{"body":"hi"}`)

	// then
	assert.True(t, ok)
	assert.Equal(t, "Ann: hi", n.body)
	assert.Equal(t, KindChat, n.kind)
	assert.Equal(t, "chat-1", n.scope)
	assert.Equal(t, "chat", n.view)
}

func TestDescribe_ShouldSendNothingWhenTypeHasNoNotifyRule(t *testing.T) {
	// given
	v := validatorWith(t, "chat.v1.schema.json", func(map[string]any) any { return nil })

	// when
	_, ok := chatBody(t, v, gChatA, `{"body":"hi"}`)

	// then
	assert.False(t, ok)
}

func identity(r map[string]any) any { return r }

func chatRule(t *testing.T, v *component.Validator) any {
	t.Helper()
	_, raw, ok := v.Notify("Chat", gChatA)
	require.True(t, ok)
	return raw
}

func TestDescribe_ShouldRejectInvalidChatRuleAndPushWithRepairedRule(t *testing.T) {
	// given
	photo := []any{map[string]any{"id": "photo"}}
	body := []any{map[string]any{"field": "body"}}
	cases := []struct {
		name       string
		bad, good  func(map[string]any) any
		oldV, newV any
	}{
		{"not an object", func(map[string]any) any { return "oops" }, identity, nil, `{"body":"hi"}`},
		{"unknown on", func(r map[string]any) any { r["on"] = "weekly"; return r }, identity, nil, `{"body":"hi"}`},
		{"unknown kind", func(r map[string]any) any { r["kind"] = "banner"; return r }, identity, nil, `{"body":"hi"}`},
		{"unknown scope", func(r map[string]any) any { r["scope"] = "app"; return r }, identity, nil, `{"body":"hi"}`},
		{"unknown text id", func(r map[string]any) any { r["text"] = []any{map[string]any{"id": "banner"}}; return r }, func(r map[string]any) any { r["text"] = photo; return r }, nil, `{"body":"hi"}`},
		{"unknown member", func(r map[string]any) any { r["extra"] = true; return r }, identity, nil, `{"body":"hi"}`},
		{"bad view", func(r map[string]any) any { r["view"] = "feed"; return r }, identity, nil, `{"body":"hi"}`},
		{"empty text", func(r map[string]any) any { r["text"] = []any{}; return r }, identity, nil, `{"body":"hi"}`},
		{"field and id", func(r map[string]any) any {
			r["text"] = []any{map[string]any{"field": "body", "id": "photo"}}
			return r
		}, func(r map[string]any) any { r["text"] = body; return r }, nil, `{"body":"hi"}`},
	}

	for _, c := range cases {
		bad := validatorWith(t, "chat.v1.schema.json", c.bad)
		good := validatorWith(t, "chat.v1.schema.json", c.good)
		ev := gComp("chat-1", gChange(gChatA, c.oldV, c.newV))

		// when
		_, parseErr := parseNotifyRules(chatRule(t, bad))
		_, badOK := (&PushService{validator: bad}).describe(ev, goldenApp(), "Ann", false, "en")
		_, goodOK := (&PushService{validator: good}).describe(ev, goldenApp(), "Ann", false, "en")

		// then
		assert.Error(t, parseErr, c.name)
		assert.False(t, badOK, c.name)
		assert.True(t, goodOK, c.name)
	}
}

func checklistEvent(fields map[string]any) *event.Event { return gComp("list-1", fields) }

func TestDescribe_ShouldRejectInvalidChecklistRuleAndPushWithUnchangedRule(t *testing.T) {
	// given
	set := func(path string, val any) func(map[string]any) any {
		return func(r map[string]any) any {
			switch path {
			case "join.show":
				r["join"].(map[string]any)["show"] = val
			case "join.more":
				r["join"].(map[string]any)["more"] = val
			case "join.extra":
				r["join"].(map[string]any)["extra"] = val
			case "skipListed.list":
				r["skipListed"].(map[string]any)["list"] = val
			case "skipListed.extra":
				r["skipListed"].(map[string]any)["extra"] = val
			case "text":
				r["text"] = val
			case "on":
				r["on"] = val
			}
			return r
		}
	}
	title := func(extra map[string]any) []any {
		c := map[string]any{"field": "title"}
		for k, v := range extra {
			c[k] = v
		}
		return []any{c}
	}
	cases := map[string]func(map[string]any) any{
		"join show below 1":          set("join.show", 0),
		"join more not itemsMore":    set("join.more", "elsewhere"),
		"join nested unknown member": set("join.extra", 1),
		"skipListed empty list":      set("skipListed.list", ""),
		"skipListed unknown member":  set("skipListed.extra", 1),
		"skipListed on non-new":      set("on", "added"),
		"when without field":         set("text", title(map[string]any{"when": map[string]any{"startsWith": "x"}})),
		"suffix without component":   set("text", title(map[string]any{"suffix": map[string]any{"sep": " "}})),
		"unknown empty id":           set("text", title(map[string]any{"empty": "nope"})),
		"empty without field":        set("text", []any{map[string]any{"id": "photo", "empty": "file"}}),
	}
	ev := checklistEvent(gChange("item_abc", nil, gItem("Milk")))
	control := validatorWith(t, "checklist.v2.schema.json", identity)
	n, controlOK := (&PushService{validator: control}).describe(ev, goldenApp(), "Ann", false, "en")
	require.True(t, controlOK)
	assert.Equal(t, "Ann: + Milk", n.body)

	for name, mutate := range cases {
		v := validatorWith(t, "checklist.v2.schema.json", mutate)
		_, raw, _ := v.Notify("Checklist", "item_abc")

		// when
		_, parseErr := parseNotifyRules(raw)
		_, ok := (&PushService{validator: v}).describe(ev, goldenApp(), "Ann", false, "en")

		// then
		assert.Error(t, parseErr, name)
		assert.False(t, ok, name)
	}
}

func TestDescribe_ShouldSkipListedItemsWithJoin(t *testing.T) {
	// given
	v := validatorWith(t, "checklist.v2.schema.json", identity)
	svc := &PushService{validator: v}
	onlyListed := checklistEvent(gChange("item_legacy-1", nil, gItem("Dup")))
	mixed := checklistEvent(gMerge(gChange("item_legacy-1", nil, gItem("Dup")), gChange("item_new", nil, gItem("Fresh"))))

	// when
	_, listedOK := svc.describe(onlyListed, goldenApp(), "Ann", false, "en")
	n, mixedOK := svc.describe(mixed, goldenApp(), "Ann", false, "en")

	// then
	assert.False(t, listedOK)
	assert.True(t, mixedOK)
	assert.Equal(t, "Ann: + Fresh", n.body)
}

func TestDescribe_ShouldSkipListedItemsWithoutJoin(t *testing.T) {
	// given
	v := validatorWith(t, "checklist.v2.schema.json", func(r map[string]any) any { delete(r, "join"); return r })
	svc := &PushService{validator: v}
	onlyListed := checklistEvent(gChange("item_legacy-1", nil, gItem("Dup")))
	listedSortsLast := checklistEvent(gMerge(gChange("item_a", nil, gItem("Alpha")), gChange("item_legacy-1", nil, gItem("Dup"))))

	// when
	_, listedOK := svc.describe(onlyListed, goldenApp(), "Ann", false, "en")
	n, mixedOK := svc.describe(listedSortsLast, goldenApp(), "Ann", false, "en")

	// then
	assert.False(t, listedOK)
	assert.True(t, mixedOK)
	assert.Equal(t, "Ann: Alpha", n.body)
}

func TestDescribe_ShouldMigrateNewValueBeforeReadingText(t *testing.T) {
	// given
	v := validatorWith(t, "checklist.v2.schema.json", func(r map[string]any) any {
		r["text"] = []any{map[string]any{"field": "assigneePublicKey"}}
		delete(r, "join")
		delete(r, "skipListed")
		return r
	})
	svc := &PushService{validator: v}
	old := checklistEvent(gChange("item_abc", nil, map[string]any{"v": 1, "title": "t", "assignedMemberId": "u1"}))
	current := checklistEvent(gChange("item_abc", nil, map[string]any{"v": 2, "title": "t", "assigneePublicKey": "u2"}))
	oldValueSet := checklistEvent(gChange("item_abc", map[string]any{"v": 1, "assignedMemberId": "u0"}, map[string]any{"v": 1, "assignedMemberId": "u1"}))

	// when
	migrated, migratedOK := svc.describe(old, goldenApp(), "Ann", false, "en")
	untouched, currentOK := svc.describe(current, goldenApp(), "Ann", false, "en")
	_, oldOK := svc.describe(oldValueSet, goldenApp(), "Ann", false, "en")

	// then
	assert.True(t, migratedOK)
	assert.Equal(t, "Ann: u1", migrated.body)
	assert.True(t, currentOK)
	assert.Equal(t, "Ann: u2", untouched.body)
	assert.False(t, oldOK)
}

func TestDescribe_ShouldSendNothingWhenLastFiredChatKeyHasNoStringValue(t *testing.T) {
	// given
	v, err := component.NewValidator()
	require.NoError(t, err)
	svc := &PushService{validator: v}
	nonStringLast := gComp("chat-1", gMerge(gChange(gChatA, nil, `{"body":"first"}`), gChange(gChatB, nil, 42)))
	nonStringFirst := gComp("chat-1", gMerge(gChange(gChatA, nil, 42), gChange(gChatB, nil, `{"body":"second"}`)))

	// when
	_, lastOK := svc.describe(nonStringLast, goldenApp(), "Ann", false, "en")
	n, firstOK := svc.describe(nonStringFirst, goldenApp(), "Ann", false, "en")

	// then
	assert.False(t, lastOK)
	assert.True(t, firstOK)
	assert.Equal(t, "Ann: second", n.body)
}

func TestDescribe_ShouldSendNothingForComponentEventWithoutValidator(t *testing.T) {
	// given
	svc := NewPushService(nil, nil, nil, nil)

	// when
	_, ok := svc.describe(gComp("chat-1", gChange(gChatA, nil, `{"body":"hi"}`)), goldenApp(), "Ann", false, "en")

	// then
	assert.False(t, ok)
}

func TestDescribe_ShouldSendNothingForKeyOutsideChatPattern(t *testing.T) {
	// given
	v, err := component.NewValidator()
	require.NoError(t, err)

	// when
	_, ok := chatBody(t, v, "m_1", `{"body":"hi"}`)

	// then
	assert.False(t, ok)
}

func TestDescribe_ShouldUseStoredValueWhenMigrationFails(t *testing.T) {
	// given
	v, err := component.NewValidator()
	require.NoError(t, err)
	stored := map[string]any{"v": 99, "body": "hi"}
	_, cur, _ := v.Versions("Chat")
	_, _, migrateErr := lens.Migrate(v.Steps("Chat"), gChatA, stored, cur)
	require.Error(t, migrateErr)

	// when
	n, ok := chatBody(t, v, gChatA, `{"v":99,"body":"hi"}`)

	// then
	assert.True(t, ok)
	assert.Equal(t, "Ann: hi", n.body)
}

func TestDescribe_ShouldUseFiredValueForValueCandidateAndIncludeComponentTitle(t *testing.T) {
	// given
	svc := &PushService{validator: validatorWith(t, "poll.v1.schema.json", identity)}
	ev := gComp("poll-2", gChange("question", nil, " Where? "))

	// when
	n, ok := svc.describe(ev, goldenApp(), "Ann", false, "en")

	// then
	assert.True(t, ok)
	assert.Equal(t, "Ann: 📊 Where?", n.body)
	assert.Equal(t, "polls", n.view)
}

func TestDescribe_ShouldAppendMinorUnitsAmountFromSuffixField(t *testing.T) {
	// given
	svc := &PushService{validator: validatorWith(t, "expenses.v1.schema.json", identity)}
	key := "e_0b7e5c1a-3f2d-4a9e-8c11-5d6e7f8a9b0c"
	dinner := gComp("expenses-2", gChange(key, nil, `{"what":"Dinner","amount":4500}`))
	refund := gComp("expenses-2", gChange(key, nil, `{"what":"Refund","amount":-50}`))
	noAmount := gComp("expenses-2", gChange(key, nil, `{"what":"Gift"}`))

	// when
	d, okD := svc.describe(dinner, goldenApp(), "Ann", false, "en")
	r, okR := svc.describe(refund, goldenApp(), "Ann", false, "en")
	g, okG := svc.describe(noAmount, goldenApp(), "Ann", false, "en")

	// then
	assert.True(t, okD && okR && okG)
	assert.Equal(t, "Ann: Dinner · 45.00", d.body)
	assert.Equal(t, "Ann: Refund · -0.50", r.body)
	assert.Equal(t, "Ann: Gift", g.body)
	assert.Equal(t, "Costs", d.componentTitle)
	assert.Equal(t, "expenses-2", d.scope)
}

func TestParseNotifyRule_ShouldRejectBadSuffix(t *testing.T) {
	// given
	rule := func(suffix map[string]any) map[string]any {
		return map[string]any{"on": "new", "kind": "item", "scope": "component", "text": []any{map[string]any{"field": "what", "suffix": suffix}}}
	}
	cases := map[string]map[string]any{
		"component and field":   {"component": "_title", "field": "amount"},
		"neither":               {"sep": " "},
		"unknown format":        {"field": "amount", "format": "euros"},
		"format with component": {"component": "_title", "format": "minorUnits"},
	}

	for name, suffix := range cases {
		// when
		_, err := parseNotifyRule(rule(suffix))

		// then
		assert.Error(t, err, name)
	}
}

func TestDescribe_ShouldNameMemberRemovedAndLeft(t *testing.T) {
	// given
	svc := &PushService{}
	removed := gMemberRemoved("Bo", "bo-pk")
	left := gMemberRemoved("Bo", "creator-pk")
	unnamed := gMemberRemoved("", "bo-pk")

	// when
	r, _ := svc.describe(removed, goldenApp(), "Ann", false, "pl")
	l, _ := svc.describe(left, goldenApp(), "Bo", false, "en")
	u, _ := svc.describe(unnamed, goldenApp(), "Ann", false, "en")

	// then
	assert.Equal(t, "Usunięto: Bo", r.body)
	assert.Equal(t, "Left: Bo", l.body)
	assert.Equal(t, "Removed: Someone", u.body)
	assert.Equal(t, KindMember, r.kind)
	assert.Equal(t, "evt-1", r.scope)
}

func TestDescribe_ShouldEvaluateChecklistRuleList(t *testing.T) {
	// given
	svc := &PushService{validator: validatorWith(t, "checklist.v2.schema.json", identity)}
	checked := func(title string) map[string]any { return map[string]any{"title": title, "checked": true} }
	unchecked := func(title string) map[string]any { return map[string]any{"title": title, "checked": false} }
	cases := []struct {
		name   string
		fields map[string]any
		want   string
	}{
		{"becomesTrue", gChange("item_a", unchecked("Milk"), checked("Milk")), "Ann: ✓ Milk"},
		{"becomesTrue from absent flag", gChange("item_a", gItem("Milk"), checked("Milk")), "Ann: ✓ Milk"},
		{"becomesFalse", gChange("item_a", checked("Milk"), unchecked("Milk")), "Ann: ☐ Milk"},
		{"new checked item is only added", gChange("item_a", nil, checked("Milk")), "Ann: + Milk"},
		{"tombstone of checked item is only removed", gChange("item_a", checked("Milk"), ""), "Ann: − Milk"},
		{"tombstone of absent key", gChange("item_a", nil, ""), ""},
		{"rename fires nothing", gChange("item_a", gItem("Milk"), gItem("Oat milk")), ""},
		{"multi delete joins", gMerge(gChange("item_a", gItem("A"), ""), gChange("item_b", gItem("B"), ""), gChange("item_c", gItem("C"), "")), "Ann: − A, B and 1 more"},
		{"multi tick joins", gMerge(gChange("item_a", gItem("A"), checked("A")), gChange("item_b", gItem("B"), checked("B"))), "Ann: ✓ A, B"},
	}

	for _, c := range cases {
		// when
		n, ok := svc.describe(checklistEvent(c.fields), goldenApp(), "Ann", false, "en")

		// then
		assert.Equal(t, c.want != "", ok, c.name)
		assert.Equal(t, c.want, n.body, c.name)
	}
}

func TestDescribe_ShouldIgnoreWholeRuleListWhenOneMemberIsInvalid(t *testing.T) {
	// given
	svc := &PushService{validator: validatorWith(t, "checklist.v2.schema.json", func(r map[string]any) any { r["on"] = "weekly"; return r })}
	ev := checklistEvent(gChange("item_a", map[string]any{"title": "Milk", "checked": false}, map[string]any{"title": "Milk", "checked": true}))

	// when
	_, ok := svc.describe(ev, goldenApp(), "Ann", false, "en")

	// then
	assert.False(t, ok)
}
