package push

import (
	"bytes"
	"encoding/json"
	"flag"
	"maps"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/component"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/stretchr/testify/assert"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/push_golden.json")

const goldenFile = "testdata/push_golden.json"

const (
	gChatA = "m_0b7e5c1a-3f2d-4a9e-8c11-5d6e7f8a9b0c"
	gChatB = "m_1c8f6d2b-4a3e-4b0f-9d22-6e7f8a9b0c1d"
	gChatC = "m_2d907e3c-5b4f-4c10-8e33-7f8a9b0c1d2e"
)

type goldenCase struct {
	name    string
	ev      *event.Event
	creator string
	agent   bool
	app     *application.Application
	noApp   bool
}

type goldenDelivery struct {
	Subscription string         `json:"subscription"`
	Payload      map[string]any `json:"payload"`
	Urgency      string         `json:"urgency"`
	TTL          int            `json:"ttl"`
	Topic        string         `json:"topic"`
}

// newGoldenService is the single construction point of the service under test.
func newGoldenService(repo PushRepository, sender WebpushSender) *PushService {
	v, err := component.NewValidator()
	if err != nil {
		panic(err)
	}
	return NewPushService(repo, sender, newMockSpaceVapidService("pub", "priv"), v)
}

func goldenApp() *application.Application {
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
				{ID: "map-1", Name: "Map", Data: map[string]any{"markers": []any{map[string]any{"id": "listed", "title": "Wieliczka"}}}},
				{ID: "countdown-1", Name: "Countdown"},
				{ID: "expenses-1", Name: "Expenses"},
				{ID: "list-2", Name: "Checklist", Data: map[string]any{"_title": "Groceries"}},
				{ID: "expenses-2", Name: "Expenses", Data: map[string]any{"_title": "Costs"}},
			},
		}},
	}
}

func gChange(key string, oldV, newV any) map[string]any {
	return map[string]any{key: map[string]any{"oldValue": oldV, "newValue": newV}}
}

func gMerge(ms ...map[string]any) map[string]any {
	out := map[string]any{}
	for _, m := range ms {
		maps.Copy(out, m)
	}
	return out
}

func gComp(componentID string, fields map[string]any) *event.Event {
	return &event.Event{
		ID:               "evt-1",
		Type:             event.EventTypeComponentDataChanged,
		CreatorPublicKey: "creator-pk",
		ApplicationID:    "app-1",
		CreatedAt:        1700000000,
		Data:             map[string]any{"applicationId": "app-1", "componentId": componentID, "changedFields": fields},
	}
}

func gTyped(tp event.EventType, data map[string]any) *event.Event {
	return &event.Event{
		ID:               "evt-1",
		Type:             tp,
		CreatorPublicKey: "creator-pk",
		ApplicationID:    "app-1",
		CreatedAt:        1700000000,
		Data:             data,
	}
}

func gMemberRemoved(name, memberPublicKey string) *event.Event {
	data := map[string]any{"memberPublicKey": memberPublicKey}
	if name != "" {
		data["userDisplayName"] = name
	}
	return gTyped(event.EventTypeMemberRemoved, data)
}

func gItem(title string) map[string]any { return map[string]any{"title": title} }

func goldenCases() []goldenCase {
	var cs []goldenCase
	add := func(name string, ev *event.Event) {
		cs = append(cs, goldenCase{name: name, ev: ev, creator: "Ann"})
	}

	// chat
	add("chat plain text", gComp("chat-1", gChange(gChatA, nil, `{"v":1,"body":"hi there","sender":"x","ts":1}`)))
	add("chat last key wins", gComp("chat-1", gMerge(
		gChange(gChatA, "", `{"body":"first"}`),
		gChange(gChatC, nil, `{"body":"third"}`),
		gChange(gChatB, nil, `{"body":"second"}`),
	)))
	add("chat image attachment only", gComp("chat-1", gChange(gChatA, nil, `{"body":"","attachments":[{"id":"i","name":"a.jpg","mime":"image/jpeg"}]}`)))
	add("chat image attachment body fallback", gComp("chat-1", gChange(gChatA, nil, `{"body":"[photo]","bodyFallback":true,"attachments":[{"id":"i","name":"a.png","mime":"image/png"}]}`)))
	add("chat named file attachment", gComp("chat-1", gChange(gChatA, nil, `{"body":"","attachments":[{"id":"i","name":"plan.pdf","mime":"application/pdf"}]}`)))
	add("chat blank name file attachment", gComp("chat-1", gChange(gChatA, nil, `{"body":"","attachments":[{"id":"i","name":"","mime":"application/pdf"}]}`)))
	add("chat file attachment with real body", gComp("chat-1", gChange(gChatA, nil, `{"body":"see this","attachments":[{"id":"i","name":"plan.pdf","mime":"application/pdf"}]}`)))
	add("chat body fallback without attachment", gComp("chat-1", gChange(gChatA, nil, `{"body":"[photo]","bodyFallback":true}`)))
	add("chat long body truncated", gComp("chat-1", gChange(gChatA, nil, `{"body":"`+strings.Repeat("a", 121)+`"}`)))
	add("chat body exactly 120 runes", gComp("chat-1", gChange(gChatA, nil, `{"body":"`+strings.Repeat("ą", 120)+`"}`)))
	add("chat body whitespace collapsed", gComp("chat-1", gChange(gChatA, nil, `{"body":"a\n\n b\t c "}`)))
	add("chat value is an object", gComp("chat-1", gChange(gChatA, nil, map[string]any{"body": "hi"})))
	add("chat value is a number", gComp("chat-1", gChange(gChatA, nil, 42)))
	add("chat reaction", gComp("chat-1", gChange("react_"+gChatA+"_pk", nil, "👍")))
	add("chat edit of old message", gComp("chat-1", gChange(gChatA, `{"body":"a"}`, `{"body":"b"}`)))
	add("chat non json value", gComp("chat-1", gChange(gChatA, nil, "not json")))
	add("chat blank body", gComp("chat-1", gChange(gChatA, nil, `{"body":"  "}`)))
	add("chat layout key", gComp("chat-1", gChange("_title", nil, "x")))

	// checklist
	add("checklist one item", gComp("list-1", gChange("item_a", nil, map[string]any{"title": " Milk ", "checked": false})))
	add("checklist two items", gComp("list-1", gMerge(gChange("item_b", nil, gItem("B")), gChange("item_a", "", gItem("A")))))
	add("checklist three items", gComp("list-1", gMerge(
		gChange("item_a", nil, gItem("A")), gChange("item_b", nil, gItem("B")), gChange("item_c", nil, gItem("C")),
	)))
	add("checklist four items", gComp("list-1", gMerge(
		gChange("item_a", nil, gItem("A")), gChange("item_b", nil, gItem("B")),
		gChange("item_c", nil, gItem("C")), gChange("item_d", nil, gItem("D")),
	)))
	add("checklist blank title", gComp("list-1", gChange("item_a", nil, gItem("  "))))
	add("checklist legacy id skipped", gComp("list-1", gChange("item_legacy-1", nil, gItem("Milk"))))
	add("checklist legacy id beside new item", gComp("list-1", gMerge(gChange("item_legacy-1", nil, gItem("Milk")), gChange("item_a", nil, gItem("Eggs")))))
	add("checklist tick", gComp("list-1", gChange("item_a", gItem("Milk"), map[string]any{"title": "Milk", "checked": true})))
	add("checklist rename", gComp("list-1", gChange("item_a", gItem("Milk"), gItem("Oat milk"))))
	add("checklist tombstone", gComp("list-1", gChange("item_a", gItem("Milk"), "")))
	checked := func(title string) map[string]any { return map[string]any{"title": title, "checked": true} }
	add("checklist new item already checked", gComp("list-1", gChange("item_a", nil, checked("Milk"))))
	add("checklist untick", gComp("list-1", gChange("item_a", checked("Milk"), map[string]any{"title": "Milk", "checked": false})))
	add("checklist two ticks", gComp("list-1", gMerge(gChange("item_a", gItem("A"), checked("A")), gChange("item_b", gItem("B"), checked("B")))))
	add("checklist tombstone of checked item", gComp("list-1", gChange("item_a", checked("Milk"), "")))
	add("checklist tombstone of absent key", gComp("list-1", gChange("item_a", nil, "")))
	add("checklist three deletes", gComp("list-1", gMerge(gChange("item_a", gItem("A"), ""), gChange("item_b", gItem("B"), ""), gChange("item_c", gItem("C"), ""))))
	add("checklist one item with component title", gComp("list-2", gChange("item_a", nil, gItem("Milk"))))
	add("checklist three items with component title", gComp("list-2", gMerge(
		gChange("item_a", nil, gItem("Milk")), gChange("item_b", nil, gItem("Eggs")), gChange("item_c", nil, gItem("Bread")),
	)))
	add("checklist items key", gComp("list-1", gChange("items", nil, []any{gItem("Milk")})))

	// poll
	add("poll closed with question", gComp("poll-1", gChange("closed", false, true)))
	add("poll closed without question", gComp("poll-2", gChange("closed", nil, true)))
	add("poll closed again", gComp("poll-1", gChange("closed", true, true)))
	add("poll reopened", gComp("poll-1", gChange("closed", true, false)))
	add("poll created", gComp("poll-1", gMerge(gChange("v", nil, 1), gChange("question", nil, "Where do we eat?"))))
	add("poll vote", gComp("poll-1", gChange("vote_pk", nil, "a")))

	// files and gallery
	old := []any{map[string]any{"id": "f1", "filename": "a.pdf"}}
	grown := []any{old[0], map[string]any{"id": "f2", "filename": "b.pdf"}, map[string]any{"id": "f3", "filename": "c.pdf"}}
	add("files item added", gComp("files-1", gChange("items", old, grown)))
	add("files item added blank filename", gComp("files-1", gChange("items", nil, []any{map[string]any{"id": "f9", "filename": ""}})))
	add("gallery item added", gComp("gallery-1", gChange("items", nil, []any{map[string]any{"id": "f9", "filename": "p.jpg"}})))
	add("gallery item added blank filename", gComp("gallery-1", gChange("items", nil, []any{map[string]any{"id": "f9", "filename": ""}})))
	add("files item removed", gComp("files-1", gChange("items", grown, old)))
	add("files without new id", gComp("files-1", gChange("items", []any{map[string]any{"id": "f1"}}, []any{map[string]any{"id": "f1"}})))
	add("files garbage", gComp("files-1", gChange("items", nil, "garbage")))

	// map
	place := func(title string, extra map[string]any) map[string]any {
		return gMerge(map[string]any{"v": 2, "latitude": 50.06, "longitude": 20.05, "title": title, "order": 1}, extra)
	}
	leg := func(fields map[string]any) map[string]any { return gMerge(map[string]any{"v": 2}, fields) }
	kv := func(k string, v any) map[string]any { return map[string]any{k: v} }
	add("map place new", gComp("map-1", gChange("place_a", nil, place("Wieliczka", nil))))
	cs = append(cs, goldenCase{name: "map place new by agent", ev: gComp("map-1", gChange("place_a", nil, place("Wieliczka", nil))), creator: "Ann", agent: true})
	add("map three places new", gComp("map-1", gMerge(
		gChange("place_a", nil, place("Wieliczka", nil)), gChange("place_b", nil, place("Krakow", nil)), gChange("place_c", nil, place("Zakopane", nil)),
	)))
	add("map place time changed", gComp("map-1", gChange("place_a", place("Wieliczka", kv("time", "10:00")), place("Wieliczka", kv("time", "11:30")))))
	add("map place date changed", gComp("map-1", gChange("place_a", place("Wieliczka", kv("date", "2026-07-04")), place("Wieliczka", kv("date", "2026-07-05")))))
	add("map place reordered", gComp("map-1", gChange("place_a", place("Wieliczka", nil), place("Wieliczka", kv("order", 2)))))
	add("map place note only", gComp("map-1", gChange("place_a", place("Wieliczka", nil), place("Wieliczka", kv("description", "Book tickets")))))
	timed := map[string]any{"date": "2026-07-04", "time": "10:00"}
	add("map place remind before only", gComp("map-1", gChange("place_a", place("Wieliczka", timed), place("Wieliczka", gMerge(timed, kv("remindBefore", 60))))))
	add("map place time and date changed", gComp("map-1", gChange("place_a", place("Wieliczka", gMerge(kv("time", "10:00"), kv("date", "2026-07-04"))), place("Wieliczka", gMerge(kv("time", "11:30"), kv("date", "2026-07-05"))))))
	add("map place new already listed", gComp("map-1", gChange("place_listed", nil, place("Wieliczka", nil))))
	add("map place deleted", gComp("map-1", gChange("place_a", place("Wieliczka", nil), "")))
	s1 := map[string]any{"mode": "train", "line": "S1"}
	add("map leg new foot", gComp("map-1", gChange("leg_a__b", nil, leg(kv("mode", "foot")))))
	add("map leg new car", gComp("map-1", gChange("leg_a__b", nil, leg(kv("mode", "car")))))
	add("map leg new train with line", gComp("map-1", gChange("leg_a__b", nil, leg(s1))))
	add("map leg new bus with line", gComp("map-1", gChange("leg_a__b", nil, leg(map[string]any{"mode": "bus", "line": "304"}))))
	add("map leg new bus without line", gComp("map-1", gChange("leg_a__b", nil, leg(kv("mode", "bus")))))
	add("map leg mode changed", gComp("map-1", gChange("leg_a__b", leg(kv("mode", "car")), leg(map[string]any{"mode": "bus", "line": "304"}))))
	add("map leg line changed", gComp("map-1", gChange("leg_a__b", leg(s1), leg(map[string]any{"mode": "train", "line": "S2"}))))
	add("map leg departure changed", gComp("map-1", gChange("leg_a__b", leg(gMerge(s1, kv("departure", "08:15"))), leg(gMerge(s1, kv("departure", "08:45"))))))
	add("map leg arrival only changed", gComp("map-1", gChange("leg_a__b", leg(gMerge(s1, kv("arrival", "09:40"))), leg(gMerge(s1, kv("arrival", "09:55"))))))
	add("map leg note only changed", gComp("map-1", gChange("leg_a__b", leg(s1), leg(gMerge(s1, kv("description", "Platform 2"))))))

	// components without a rule
	add("text component", gComp("text-1", gChange("content", "a", "b")))
	add("map component", gComp("map-1", gChange("pin_a", nil, map[string]any{"lat": 1.5, "lng": 2.5})))
	add("countdown component", gComp("countdown-1", gChange("target", nil, "2030-01-01")))
	add("expenses component", gComp("expenses-1", gChange("expense_a", nil, map[string]any{"title": "Dinner", "amount": 10})))
	add("expense with component title", gComp("expenses-2", gChange("e_0b7e5c1a-3f2d-4a9e-8c11-5d6e7f8a9b0c", nil, `{"what":"Dinner","payer":"pk","amount":4500}`)))
	add("expense refund", gComp("expenses-2", gChange("e_0b7e5c1a-3f2d-4a9e-8c11-5d6e7f8a9b0c", nil, `{"what":"Refund","payer":"pk","amount":-50}`)))
	add("unknown component", gComp("nope", gChange(gChatA, nil, `{"body":"x"}`)))

	// person label
	cs = append(cs,
		goldenCase{name: "chat by agent", ev: gComp("chat-1", gChange(gChatA, nil, `{"body":"hi"}`)), creator: "Ann", agent: true},
		goldenCase{name: "chat by unnamed person", ev: gComp("chat-1", gChange(gChatA, nil, `{"body":"hi"}`)), creator: ""},
		goldenCase{name: "chat by blank named person", ev: gComp("chat-1", gChange(gChatA, nil, `{"body":"hi"}`)), creator: "  "},
		goldenCase{name: "chat by unnamed agent", ev: gComp("chat-1", gChange(gChatA, nil, `{"body":"hi"}`)), creator: "", agent: true},
		goldenCase{name: "checklist by agent", ev: gComp("list-1", gChange("item_a", nil, gItem("Milk"))), creator: "Ann", agent: true},
		goldenCase{name: "poll closed by unnamed person", ev: gComp("poll-1", gChange("closed", false, true)), creator: ""},
		goldenCase{name: "files item added by agent", ev: gComp("files-1", gChange("items", nil, []any{map[string]any{"id": "f9", "filename": "b.pdf"}})), creator: "Ann", agent: true},
		goldenCase{name: "chat in app without name", ev: gComp("chat-1", gChange(gChatA, nil, `{"body":"hi"}`)), creator: "Ann", app: &application.Application{ID: "app-1", ComponentGroups: goldenApp().ComponentGroups}},
		goldenCase{name: "chat in app with long name", ev: gComp("chat-1", gChange(gChatA, nil, `{"body":"hi"}`)), creator: "Ann", app: &application.Application{ID: "app-1", Name: strings.Repeat("N", 121), ComponentGroups: goldenApp().ComponentGroups}},
		goldenCase{name: "chat without application", ev: gComp("chat-1", gChange(gChatA, nil, `{"body":"x"}`)), creator: "Ann", noApp: true},
	)

	// member_added
	for _, agent := range []bool{false, true} {
		suffix := ""
		if agent {
			suffix = " by agent"
		}
		cs = append(cs,
			goldenCase{name: "member added" + suffix, ev: gTyped(event.EventTypeMemberAdded, map[string]any{"userDisplayName": "Bo"}), creator: "Ann", agent: agent},
			goldenCase{name: "member added without name" + suffix, ev: gTyped(event.EventTypeMemberAdded, map[string]any{}), creator: "Ann", agent: agent},
			goldenCase{name: "member added long name" + suffix, ev: gTyped(event.EventTypeMemberAdded, map[string]any{"userDisplayName": strings.Repeat("B", 121)}), creator: "Ann", agent: agent},
			goldenCase{name: "member added without application" + suffix, ev: gTyped(event.EventTypeMemberAdded, map[string]any{"userDisplayName": "Bo"}), creator: "Ann", agent: agent, noApp: true},
		)
		for _, role := range []string{"owner", "admin", "member", "viewer", "weird", ""} {
			cs = append(cs, goldenCase{name: "role changed to " + role + suffix, ev: gTyped(event.EventTypeMemberRoleChanged, map[string]any{"newRole": role}), creator: "Ann", agent: agent})
		}
		reminder := func(offset string) map[string]any {
			return map[string]any{"itemTitle": "Call mom", "componentId": "list-2", "targetKey": "place_1", "ruleId": "rule-1", "occurrenceAt": int64(1794070800), "offset": offset, "tz": "Europe/Warsaw"}
		}
		cs = append(cs,
			goldenCase{name: "member removed by owner" + suffix, ev: gMemberRemoved("Bo", "bo-pk"), creator: "Ann", agent: agent},
			goldenCase{name: "member left" + suffix, ev: gMemberRemoved("Bo", "creator-pk"), creator: "Bo", agent: agent},
			goldenCase{name: "member removed without name" + suffix, ev: gMemberRemoved("", "bo-pk"), creator: "Ann", agent: agent},
			goldenCase{name: "reminder 15 minutes before" + suffix, ev: gTyped(event.EventTypeReminderFired, reminder("-PT15M")), creator: "Ann", agent: agent},
			goldenCase{name: "reminder due now" + suffix, ev: gTyped(event.EventTypeReminderFired, reminder("PT0S")), creator: "Ann", agent: agent},
			goldenCase{name: "reminder 2 hours before" + suffix, ev: gTyped(event.EventTypeReminderFired, reminder("-PT2H")), creator: "Ann", agent: agent},
			goldenCase{name: "reminder 1 day before" + suffix, ev: gTyped(event.EventTypeReminderFired, reminder("-P1D")), creator: "Ann", agent: agent},
			goldenCase{name: "reminder without target" + suffix, ev: gTyped(event.EventTypeReminderFired, gMerge(reminder("-PT15M"), map[string]any{"targetKey": ""})), creator: "Ann", agent: agent},
			goldenCase{name: "reminder without tz" + suffix, ev: gTyped(event.EventTypeReminderFired, gMerge(reminder("-PT15M"), map[string]any{"tz": ""})), creator: "Ann", agent: agent},
			goldenCase{name: "reminder fired with text" + suffix, ev: gTyped(event.EventTypeReminderFired, map[string]any{"itemTitle": "Call mom"}), creator: "Ann", agent: agent},
			goldenCase{name: "reminder fired without text" + suffix, ev: gTyped(event.EventTypeReminderFired, map[string]any{}), creator: "Ann", agent: agent},
			goldenCase{name: "reminder fired long text" + suffix, ev: gTyped(event.EventTypeReminderFired, map[string]any{"itemTitle": strings.Repeat("r", 121)}), creator: "Ann", agent: agent},
		)
	}

	// event types without a rule
	for _, tp := range []event.EventType{
		event.EventTypeInviteRevoked,
		event.EventTypeApplicationDataChanged,
		event.EventTypeApplicationAfterEditModeChanged,
		event.EventTypeApplicationFileCreated,
		event.EventTypeApplicationFileDeleted,
		event.EventTypeApplicationCreated,
	} {
		add("event type "+string(tp), gTyped(tp, map[string]any{}))
	}
	return cs
}

func runGoldenCase(t *testing.T, c goldenCase) []goldenDelivery {
	t.Helper()
	repo := newMockPushRepository()
	sender := newMockWebpushSender(SendResult{StatusCode: 201})
	svc := newGoldenService(repo, sender)

	repo.subscriptions["sub-en"] = &Subscription{ID: "sub-en", DevicePublicKey: "dk-en", Locale: "en"}
	repo.subscriptions["sub-pl"] = &Subscription{ID: "sub-pl", DevicePublicKey: "dk-pl", Locale: "pl"}
	repo.subscriptions["sub-pl-muted"] = &Subscription{ID: "sub-pl-muted", DevicePublicKey: "dk-pl-muted", Locale: "pl", MutedApplicationIDs: []string{"app-1"}}
	repo.subscriptions["sub-en-muted"] = &Subscription{ID: "sub-en-muted", DevicePublicKey: "dk-en-muted", Locale: "en", MutedApplicationIDs: []string{"app-1"}}
	repo.subscriptions["sub-de-other-muted"] = &Subscription{ID: "sub-de-other-muted", DevicePublicKey: "dk-de", Locale: "de", MutedApplicationIDs: []string{"app-2"}}

	app := c.app
	if app == nil {
		app = goldenApp()
	}
	if c.noApp {
		app = nil
	}

	svc.fanout(c.ev, app, c.creator, c.agent, []string{"dk-en", "dk-pl", "dk-pl-muted", "dk-en-muted", "dk-de"})

	out := []goldenDelivery{}
	for _, call := range sender.calls {
		var payload map[string]any
		if err := json.Unmarshal(call.payload, &payload); err != nil {
			t.Fatalf("payload is not json: %v", err)
		}
		out = append(out, goldenDelivery{
			Subscription: call.sub.ID,
			Payload:      payload,
			Urgency:      string(call.opts.Urgency),
			TTL:          call.opts.TTL,
			Topic:        call.opts.Topic,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subscription < out[j].Subscription })
	return out
}

func renderGolden(t *testing.T) []byte {
	t.Helper()
	cases := map[string]any{}
	for _, c := range goldenCases() {
		if _, dup := cases[c.name]; dup {
			t.Fatalf("duplicate golden case name %q", c.name)
		}
		var deliveries any = "none"
		if d := runGoldenCase(t, c); len(d) > 0 {
			deliveries = d
		}
		cases[c.name] = map[string]any{
			"input": map[string]any{
				"event": map[string]any{
					"id": c.ev.ID, "type": c.ev.Type, "creatorPublicKey": c.ev.CreatorPublicKey, "data": c.ev.Data,
				},
				"creatorName": c.creator,
				"agent":       c.agent,
			},
			"deliveries": deliveries,
		}
	}
	all := map[string]any{"app": goldenApp(), "cases": cases}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(all); err != nil {
		t.Fatalf("encode golden: %v", err)
	}
	return buf.Bytes()
}

func TestPushService_Fanout_ShouldMatchGoldenFile(t *testing.T) {
	// given
	got := renderGolden(t)

	// when
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenFile, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenFile)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}

	// then
	if !bytes.Equal(want, got) {
		assert.Equal(t, string(want), string(got), "golden mismatch, rerun with -update only if the change is intended")
	}
}
