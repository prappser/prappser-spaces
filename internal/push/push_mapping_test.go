package push

import (
	"strings"
	"testing"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/stretchr/testify/assert"
)

func testApp() *application.Application {
	return &application.Application{
		ID:   "app-1",
		Name: "Trip",
		ComponentGroups: []application.ComponentGroup{{
			ID: "g1",
			Components: []application.Component{
				{ID: "chat-1", Name: "Chat"},
				{ID: "list-1", Name: "Checklist", Data: map[string]any{"items": []any{map[string]any{"id": "legacy-1", "title": "Old"}}}},
				{ID: "poll-1", Name: "Poll", Data: map[string]any{"question": "Where do we eat?"}},
				{ID: "poll-2", Name: "Poll"},
				{ID: "files-1", Name: "Files"},
				{ID: "gallery-1", Name: "Gallery"},
				{ID: "text-1", Name: "Text"},
			},
		}},
	}
}

func change1(key string, oldV, newV any) map[string]any {
	return map[string]any{key: map[string]any{"oldValue": oldV, "newValue": newV}}
}

func merge(ms ...map[string]any) map[string]any {
	out := map[string]any{}
	for _, m := range ms {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func compEvent(componentID string, fields map[string]any) *event.Event {
	return &event.Event{
		ID:               "evt-1",
		Type:             event.EventTypeComponentDataChanged,
		CreatorPublicKey: "creator-pk",
		ApplicationID:    "app-1",
		Data:             map[string]any{"applicationId": "app-1", "componentId": componentID, "changedFields": fields},
	}
}

func bodyOf(t *testing.T, ev *event.Event, name string, agent bool, lang string) notice {
	t.Helper()
	n, ok := describe(ev, testApp(), name, agent, lang)
	assert.True(t, ok)
	return n
}

func TestDescribe_ShouldUseChatBodyAndViewChat(t *testing.T) {
	// given
	ev := compEvent("chat-1", change1("m_1", nil, `{"v":1,"body":"hi there","sender":"x","ts":1}`))

	// when
	n := bodyOf(t, ev, "Ann", false, "en")

	// then
	assert.Equal(t, "Ann: hi there", n.body)
	assert.Equal(t, KindChat, n.kind)
	assert.Equal(t, "chat", n.view)
	assert.Equal(t, "chat-1", n.scope)
}

func TestDescribe_ShouldUseLastChatKey(t *testing.T) {
	// given
	ev := compEvent("chat-1", merge(
		change1("m_0001", "", `{"body":"first"}`),
		change1("m_0003", nil, `{"body":"third"}`),
		change1("m_0002", nil, `{"body":"second"}`),
	))

	// when
	n := bodyOf(t, ev, "Ann", false, "en")

	// then
	assert.Equal(t, "Ann: third", n.body)
}

func TestDescribe_ShouldShowPhotoForImageAttachmentOnlyMessage(t *testing.T) {
	// given
	ev := compEvent("chat-1", change1("m_1", nil, `{"body":"","attachments":[{"id":"i","name":"a.jpg","mime":"image/jpeg"}]}`))

	// when
	en := bodyOf(t, ev, "Ann", false, "en")
	pl := bodyOf(t, ev, "Ann", false, "pl")

	// then
	assert.Equal(t, "Ann: 📷 Photo", en.body)
	assert.Equal(t, "Ann: 📷 Zdjęcie", pl.body)
}

func TestDescribe_ShouldShowFilenameForNonImageAttachment(t *testing.T) {
	// given
	ev := compEvent("chat-1", change1("m_1", nil, `{"body":"","attachments":[{"id":"i","name":"plan.pdf","mime":"application/pdf"}]}`))
	unnamed := compEvent("chat-1", change1("m_1", nil, `{"body":"","attachments":[{"id":"i","name":"","mime":"application/pdf"}]}`))

	// when
	n := bodyOf(t, ev, "Ann", false, "en")
	u := bodyOf(t, unnamed, "Ann", false, "pl")

	// then
	assert.Equal(t, "Ann: 📎 plan.pdf", n.body)
	assert.Equal(t, "Ann: 📎 Plik", u.body)
}

func TestDescribe_ShouldIgnorePlaceholderBodyWhenBodyFallback(t *testing.T) {
	// given
	ev := compEvent("chat-1", change1("m_1", nil, `{"body":"[photo]","bodyFallback":true,"attachments":[{"id":"i","name":"a.png","mime":"image/png"}]}`))

	// when
	n := bodyOf(t, ev, "Ann", false, "en")

	// then
	assert.Equal(t, "Ann: 📷 Photo", n.body)
}

func TestDescribe_ShouldDescribeSingleChecklistItem(t *testing.T) {
	// given
	ev := compEvent("list-1", change1("item_a", nil, map[string]any{"title": " Milk ", "checked": false}))

	// when
	n := bodyOf(t, ev, "Ann", false, "en")

	// then
	assert.Equal(t, "Ann: + Milk", n.body)
	assert.Equal(t, KindItem, n.kind)
	assert.Equal(t, "list-1", n.scope)
	assert.Equal(t, "list-1", n.componentID)
}

func TestDescribe_ShouldJoinChecklistItemsInBothLanguages(t *testing.T) {
	// given
	item := func(title string) map[string]any { return map[string]any{"title": title} }
	two := compEvent("list-1", merge(change1("item_b", nil, item("B")), change1("item_a", "", item("A"))))
	four := compEvent("list-1", merge(
		change1("item_a", nil, item("A")), change1("item_b", nil, item("B")),
		change1("item_c", nil, item("C")), change1("item_d", nil, item("D")),
	))

	// when / then
	assert.Equal(t, "Ann: + A, B", bodyOf(t, two, "Ann", false, "en").body)
	assert.Equal(t, "Ann: + A, B and 2 more", bodyOf(t, four, "Ann", false, "en").body)
	assert.Equal(t, "Ann: + A, B i 2 innych", bodyOf(t, four, "Ann", false, "pl").body)
}

func TestDescribe_ShouldDescribePollClosed(t *testing.T) {
	// given
	ev := compEvent("poll-1", change1("closed", false, true))
	noQuestion := compEvent("poll-2", change1("closed", nil, true))

	// when / then
	assert.Equal(t, "Ann: Poll closed: Where do we eat?", bodyOf(t, ev, "Ann", false, "en").body)
	assert.Equal(t, "Ann: Ankieta zamknięta: Where do we eat?", bodyOf(t, ev, "Ann", false, "pl").body)
	assert.Equal(t, "Ann: Poll closed", bodyOf(t, noQuestion, "Ann", false, "en").body)
	assert.Equal(t, KindPoll, bodyOf(t, ev, "Ann", false, "en").kind)
	assert.Equal(t, "evt-1", bodyOf(t, ev, "Ann", false, "en").scope)
}

func TestDescribe_ShouldDescribeNewFileInFilesAndGallery(t *testing.T) {
	// given
	old := []any{map[string]any{"id": "f1", "filename": "a.pdf"}}
	grown := []any{old[0], map[string]any{"id": "f2", "filename": "b.pdf"}, map[string]any{"id": "f3", "filename": "c.pdf"}}
	files := compEvent("files-1", change1("items", old, grown))
	gallery := compEvent("gallery-1", change1("items", nil, []any{map[string]any{"id": "f9", "filename": ""}}))

	// when / then
	assert.Equal(t, "Ann: 📎 c.pdf", bodyOf(t, files, "Ann", false, "en").body)
	assert.Equal(t, "Ann: 📎 Plik", bodyOf(t, gallery, "Ann", false, "pl").body)
	assert.Equal(t, KindFile, bodyOf(t, files, "Ann", false, "en").kind)
}

func TestDescribe_ShouldDescribeMemberAddedWithoutPersonPrefix(t *testing.T) {
	// given
	ev := &event.Event{ID: "evt-m", Type: event.EventTypeMemberAdded, ApplicationID: "app-1", Data: map[string]any{"userDisplayName": "Bo"}}
	empty := &event.Event{ID: "evt-m", Type: event.EventTypeMemberAdded, ApplicationID: "app-1", Data: map[string]any{}}

	// when / then
	assert.Equal(t, "New member: Bo", bodyOf(t, ev, "Ann", false, "en").body)
	assert.Equal(t, "Nowa osoba: Bo", bodyOf(t, ev, "Ann", false, "pl").body)
	assert.Equal(t, "Nowa osoba: Ktoś", bodyOf(t, empty, "Ann", false, "pl").body)
	assert.Equal(t, KindMember, bodyOf(t, ev, "Ann", false, "en").kind)
	assert.Equal(t, "evt-m", bodyOf(t, ev, "Ann", false, "en").scope)
}

func TestDescribe_ShouldLocalizeRoleChange(t *testing.T) {
	// given
	roles := map[string][2]string{
		"owner":  {"Owner", "Właściciel"},
		"admin":  {"Admin", "Administrator"},
		"member": {"Member", "Członek"},
		"viewer": {"Viewer", "Obserwator"},
	}

	for role, labels := range roles {
		ev := &event.Event{ID: "e", Type: event.EventTypeMemberRoleChanged, ApplicationID: "app-1", Data: map[string]any{"newRole": role}}

		// when / then
		assert.Equal(t, "Your role is now: "+labels[0], bodyOf(t, ev, "", false, "en").body)
		assert.Equal(t, "Twoja rola: "+labels[1], bodyOf(t, ev, "", false, "pl").body)
	}
	custom := &event.Event{ID: "e", Type: event.EventTypeMemberRoleChanged, Data: map[string]any{"newRole": "weird"}}
	assert.Equal(t, "Your role is now: weird", bodyOf(t, custom, "", false, "en").body)
	assert.Equal(t, KindRole, bodyOf(t, custom, "", false, "en").kind)
}

func TestDescribe_ShouldDescribeReminder(t *testing.T) {
	// given
	ev := &event.Event{ID: "e", Type: event.EventTypeReminderFired, ApplicationID: "app-1", Data: map[string]any{"itemTitle": "Call mom"}}
	empty := &event.Event{ID: "e", Type: event.EventTypeReminderFired, ApplicationID: "app-1", Data: map[string]any{}}

	// when / then
	assert.Equal(t, "⏰ Call mom", bodyOf(t, ev, "", false, "en").body)
	assert.Equal(t, "⏰ Reminder", bodyOf(t, empty, "", false, "en").body)
	assert.Equal(t, "⏰ Przypomnienie", bodyOf(t, empty, "", false, "pl").body)
	assert.Equal(t, KindReminder, bodyOf(t, ev, "", false, "en").kind)
}

func TestDescribe_ShouldSendNothing(t *testing.T) {
	// given
	item := map[string]any{"title": "Milk"}
	typed := func(tp event.EventType) *event.Event {
		return &event.Event{ID: "e", Type: tp, ApplicationID: "app-1", Data: map[string]any{}}
	}
	cases := map[string]*event.Event{
		"chat reaction":           compEvent("chat-1", change1("react_m_1_pk", nil, "👍")),
		"chat edit of old msg":    compEvent("chat-1", change1("m_1", `{"body":"a"}`, `{"body":"b"}`)),
		"chat non-json value":     compEvent("chat-1", change1("m_1", nil, "not json")),
		"chat empty message":      compEvent("chat-1", change1("m_1", nil, `{"body":"  "}`)),
		"chat layout key":         compEvent("chat-1", change1("_title", nil, "x")),
		"checklist tick":          compEvent("list-1", change1("item_a", map[string]any{"title": "Milk"}, map[string]any{"title": "Milk", "checked": true})),
		"checklist tombstone":     compEvent("list-1", change1("item_a", item, "")),
		"checklist legacy id":     compEvent("list-1", change1("item_legacy-1", nil, item)),
		"checklist items key":     compEvent("list-1", change1("items", nil, []any{item})),
		"checklist blank title":   compEvent("list-1", change1("item_a", nil, map[string]any{"title": "  "})),
		"poll closed again":       compEvent("poll-1", change1("closed", true, true)),
		"poll reopened":           compEvent("poll-1", change1("closed", true, false)),
		"poll vote":               compEvent("poll-1", change1("vote_pk", nil, "a")),
		"files without new id":    compEvent("files-1", change1("items", []any{map[string]any{"id": "f1"}}, []any{map[string]any{"id": "f1"}})),
		"files garbage":           compEvent("files-1", change1("items", nil, "garbage")),
		"text component":          compEvent("text-1", change1("content", "a", "b")),
		"unknown component":       compEvent("nope", change1("m_1", nil, `{"body":"x"}`)),
		"member_removed":          typed(event.EventTypeMemberRemoved),
		"invite_revoked":          typed(event.EventTypeInviteRevoked),
		"application_data":        typed(event.EventTypeApplicationDataChanged),
		"after_edit_mode":         typed(event.EventTypeApplicationAfterEditModeChanged),
		"application_file_create": typed(event.EventTypeApplicationFileCreated),
		"application_file_delete": typed(event.EventTypeApplicationFileDeleted),
		"application_created":     typed(event.EventTypeApplicationCreated),
	}

	for name, ev := range cases {
		// when
		_, ok := describe(ev, testApp(), "Ann", false, "en")

		// then
		assert.False(t, ok, name)
	}
}

func TestDescribe_ShouldSendNothingForComponentEventWhenAppNil(t *testing.T) {
	// given
	ev := compEvent("chat-1", change1("m_1", nil, `{"body":"x"}`))

	// when
	_, ok := describe(ev, nil, "Ann", false, "en")

	// then
	assert.False(t, ok)
}

func TestDescribe_ShouldDescribeNonComponentEventWhenAppNil(t *testing.T) {
	// given
	ev := &event.Event{ID: "e", Type: event.EventTypeMemberAdded, Data: map[string]any{"userDisplayName": "Bo"}}

	// when
	n, ok := describe(ev, nil, "", false, "en")

	// then
	assert.True(t, ok)
	assert.Equal(t, "New member: Bo", n.body)
}

func TestDescribe_ShouldLabelAgentWriteInBothLanguages(t *testing.T) {
	// given
	ev := compEvent("chat-1", change1("m_1", nil, `{"body":"hi"}`))

	// when / then
	assert.Equal(t, "Ann (agent): hi", bodyOf(t, ev, "Ann", true, "en").body)
	assert.Equal(t, "Ann (agent): hi", bodyOf(t, ev, "Ann", true, "pl").body)
}

func TestDescribe_ShouldUseSomeoneWhenNameEmpty(t *testing.T) {
	// given
	ev := compEvent("chat-1", change1("m_1", nil, `{"body":"hi"}`))

	// when / then
	assert.Equal(t, "Someone: hi", bodyOf(t, ev, "", false, "en").body)
	assert.Equal(t, "Ktoś: hi", bodyOf(t, ev, "  ", false, "pl").body)
	assert.Equal(t, "Someone (agent): hi", bodyOf(t, ev, "", true, "en").body)
}

func TestCut_ShouldKeep120RunesAndAddEllipsisBeyond(t *testing.T) {
	// given
	exact := strings.Repeat("a", 120)
	over := strings.Repeat("a", 121)

	// when / then
	assert.Equal(t, exact, cut(exact))
	assert.Equal(t, exact+"…", cut(over))
	assert.Len(t, []rune(cut(over)), 121)
}

func TestCut_ShouldCollapseWhitespaceAndCountRunes(t *testing.T) {
	// given
	multi := strings.Repeat("ą", 121)

	// when / then
	assert.Equal(t, "a b c", cut("a\n\n b\t c "))
	assert.Equal(t, strings.Repeat("ą", 120)+"…", cut(multi))
}

func TestLangOf_ShouldFallBackToEnglish(t *testing.T) {
	// when / then
	assert.Equal(t, "pl", langOf("pl"))
	assert.Equal(t, "en", langOf(""))
	assert.Equal(t, "en", langOf("de"))
	assert.Equal(t, "en", langOf("en"))
}
