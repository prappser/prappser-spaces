package push

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
)

// Fixed event-to-text table. Stage 2 replaces it with schema notify rules and
// deletes this file; nothing outside the push package may depend on its types.

const maxWhatRunes = 120

type notice struct {
	kind        Kind
	scope       string
	componentID string
	body        string
	view        string
}

type texts struct {
	someone     string
	agentSuffix string
	photo       string
	file        string
	pollClosed  string
	itemsMore   string
	newMember   string
	roleNow     string
	reminder    string
	roleLabels  map[string]string
}

var textsEN = texts{
	someone:     "Someone",
	agentSuffix: " (agent)",
	photo:       "📷 Photo",
	file:        "File",
	pollClosed:  "Poll closed",
	itemsMore:   "and %d more",
	newMember:   "New member: %s",
	roleNow:     "Your role is now: %s",
	reminder:    "Reminder",
	roleLabels:  map[string]string{"owner": "Owner", "admin": "Admin", "member": "Member", "viewer": "Viewer"},
}

var textsPL = texts{
	someone:     "Ktoś",
	agentSuffix: " (agent)",
	photo:       "📷 Zdjęcie",
	file:        "Plik",
	pollClosed:  "Ankieta zamknięta",
	itemsMore:   "i %d innych",
	newMember:   "Nowa osoba: %s",
	roleNow:     "Twoja rola: %s",
	reminder:    "Przypomnienie",
	roleLabels:  map[string]string{"owner": "Właściciel", "admin": "Administrator", "member": "Członek", "viewer": "Obserwator"},
}

func textsFor(lang string) texts {
	if lang == "pl" {
		return textsPL
	}
	return textsEN
}

func langOf(locale string) string {
	if locale == "pl" {
		return "pl"
	}
	return "en"
}

// cut collapses whitespace and keeps at most maxWhatRunes runes plus an ellipsis.
func cut(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= maxWhatRunes {
		return s
	}
	return string(r[:maxWhatRunes]) + "…"
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func isEmpty(v any) bool {
	return v == nil || v == ""
}

func (t texts) person(name string, agent bool) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = t.someone
	}
	if agent {
		name += t.agentSuffix
	}
	return name
}

// describe returns the notification for ev in lang, or false when the event has no rule.
func describe(ev *event.Event, app *application.Application, creatorName string, agent bool, lang string) (notice, bool) {
	t := textsFor(lang)
	switch ev.Type {
	case event.EventTypeMemberAdded:
		name := cut(str(ev.Data["userDisplayName"]))
		if name == "" {
			name = t.someone
		}
		return notice{kind: KindMember, scope: ev.ID, body: fmt.Sprintf(t.newMember, name)}, true

	case event.EventTypeMemberRoleChanged:
		role := str(ev.Data["newRole"])
		if label, ok := t.roleLabels[role]; ok {
			role = label
		}
		return notice{kind: KindRole, scope: ev.ID, body: fmt.Sprintf(t.roleNow, cut(role))}, true

	case event.EventTypeReminderFired:
		title := cut(str(ev.Data["itemTitle"]))
		if title == "" {
			title = t.reminder
		}
		return notice{kind: KindReminder, scope: ev.ID, body: "⏰ " + title}, true

	case event.EventTypeComponentDataChanged:
		return describeComponent(ev, app, t, t.person(creatorName, agent))
	}
	return notice{}, false
}

func findComponent(app *application.Application, id string) *application.Component {
	if app == nil || id == "" {
		return nil
	}
	for gi := range app.ComponentGroups {
		for ci := range app.ComponentGroups[gi].Components {
			if c := &app.ComponentGroups[gi].Components[ci]; c.ID == id {
				return c
			}
		}
	}
	return nil
}

func describeComponent(ev *event.Event, app *application.Application, t texts, person string) (notice, bool) {
	componentID := str(ev.Data["componentId"])
	comp := findComponent(app, componentID)
	fields, _ := ev.Data["changedFields"].(map[string]any)
	if comp == nil || fields == nil {
		return notice{}, false
	}

	var what string
	var n notice
	var ok bool
	switch comp.Name {
	case "Chat":
		n = notice{kind: KindChat, scope: componentID, view: "chat"}
		what, ok = chatWhat(fields, t)
	case "Checklist":
		n = notice{kind: KindItem, scope: componentID, componentID: componentID}
		what, ok = checklistWhat(fields, comp, t)
	case "Poll":
		n = notice{kind: KindPoll, scope: ev.ID}
		what, ok = pollWhat(fields, comp, t)
	case "Files", "Gallery":
		n = notice{kind: KindFile, scope: ev.ID}
		what, ok = filesWhat(fields, t)
	}
	if !ok {
		return notice{}, false
	}
	n.body = person + ": " + cut(what)
	return n, true
}

func change(fields map[string]any, key string) (oldV, newV any) {
	m, _ := fields[key].(map[string]any)
	return m["oldValue"], m["newValue"]
}

// addedKeys returns, sorted, the keys with the prefix that went from empty to non-empty.
// ponytail: oldValue is supplied by the submitting client, so a forged one can
// trigger or suppress a push; capture the old value server-side inside
// executeComponentDataChanged if that ever matters.
func addedKeys(fields map[string]any, prefix string) []string {
	var keys []string
	for k := range fields {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		o, n := change(fields, k)
		if isEmpty(o) && !isEmpty(n) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func chatWhat(fields map[string]any, t texts) (string, bool) {
	keys := addedKeys(fields, "m_")
	if len(keys) == 0 {
		return "", false
	}
	_, v := change(fields, keys[len(keys)-1])
	raw, isStr := v.(string)
	if !isStr {
		return "", false
	}
	var msg struct {
		Body         string `json:"body"`
		BodyFallback bool   `json:"bodyFallback"`
		Attachments  []struct {
			Name string `json:"name"`
			Mime string `json:"mime"`
		} `json:"attachments"`
	}
	if json.Unmarshal([]byte(raw), &msg) != nil {
		return "", false
	}
	hasBody := strings.TrimSpace(msg.Body) != ""
	if hasBody && !msg.BodyFallback {
		return msg.Body, true
	}
	if len(msg.Attachments) > 0 {
		a := msg.Attachments[0]
		if strings.HasPrefix(a.Mime, "image/") {
			return t.photo, true
		}
		name := strings.TrimSpace(a.Name)
		if name == "" {
			name = t.file
		}
		return "📎 " + name, true
	}
	if hasBody {
		return msg.Body, true
	}
	return "", false
}

func checklistWhat(fields map[string]any, comp *application.Component, t texts) (string, bool) {
	legacy := map[string]bool{}
	legacyItems, _ := comp.Data["items"].([]any)
	for _, it := range legacyItems {
		if m, ok := it.(map[string]any); ok {
			legacy[str(m["id"])] = true
		}
	}

	var titles []string
	for _, k := range addedKeys(fields, "item_") {
		if legacy[strings.TrimPrefix(k, "item_")] {
			continue
		}
		_, v := change(fields, k)
		m, _ := v.(map[string]any)
		if title := strings.TrimSpace(str(m["title"])); title != "" {
			titles = append(titles, title)
		}
	}
	switch len(titles) {
	case 0:
		return "", false
	case 1:
		return "+ " + titles[0], true
	case 2:
		return "+ " + titles[0] + ", " + titles[1], true
	}
	return "+ " + titles[0] + ", " + titles[1] + " " + fmt.Sprintf(t.itemsMore, len(titles)-2), true
}

func pollWhat(fields map[string]any, comp *application.Component, t texts) (string, bool) {
	o, n := change(fields, "closed")
	if o == true || n != true {
		return "", false
	}
	if q := strings.TrimSpace(str(comp.Data["question"])); q != "" {
		return t.pollClosed + ": " + q, true
	}
	return t.pollClosed, true
}

func filesWhat(fields map[string]any, t texts) (string, bool) {
	o, n := change(fields, "items")
	oldIDs := map[string]bool{}
	oldList, _ := o.([]any)
	for _, it := range oldList {
		if m, ok := it.(map[string]any); ok {
			oldIDs[str(m["id"])] = true
		}
	}
	newList, _ := n.([]any)
	var added map[string]any
	for _, it := range newList {
		m, ok := it.(map[string]any)
		if id := str(m["id"]); ok && id != "" && !oldIDs[id] {
			added = m
		}
	}
	if added == nil {
		return "", false
	}
	name := strings.TrimSpace(str(added["filename"]))
	if name == "" {
		name = t.file
	}
	return "📎 " + name, true
}
