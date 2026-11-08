package push

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/component/lens"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/reminder"
	"github.com/rs/zerolog/log"
)

type notifyRule struct {
	On         string          `json:"on"`
	Field      string          `json:"field"`
	Kind       string          `json:"kind"`
	Scope      string          `json:"scope"`
	View       string          `json:"view"`
	Text       []textCandidate `json:"text"`
	Join       *joinSpec       `json:"join"`
	SkipListed *skipListedSpec `json:"skipListed"`
}

type textCandidate struct {
	Field  string      `json:"field"`
	ID     string      `json:"id"`
	When   *whenSpec   `json:"when"`
	Unless string      `json:"unless"`
	Prefix string      `json:"prefix"`
	Empty  string      `json:"empty"`
	Suffix *suffixSpec `json:"suffix"`
}

type whenSpec struct {
	Field      string `json:"field"`
	StartsWith string `json:"startsWith"`
}

type suffixSpec struct {
	Component string `json:"component"`
	Field     string `json:"field"`
	Format    string `json:"format"`
	Sep       string `json:"sep"`
}

type joinSpec struct {
	Prefix string `json:"prefix"`
	Sep    string `json:"sep"`
	Show   int    `json:"show"`
	More   string `json:"more"`
}

type skipListedSpec struct {
	List   string `json:"list"`
	Prefix string `json:"prefix"`
}

var ruleKinds = map[string]Kind{"chat": KindChat, "item": KindItem, "poll": KindPoll, "file": KindFile}

func parseNotifyRules(raw any) ([]*notifyRule, error) {
	list, isList := raw.([]any)
	if !isList {
		list = []any{raw}
	}
	rules := make([]*notifyRule, 0, len(list))
	for i, r := range list {
		rule, err := parseNotifyRule(r)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func parseNotifyRule(raw any) (*notifyRule, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to encode rule: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r notifyRule
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("failed to decode rule: %w", err)
	}
	if err := r.check(); err != nil {
		return nil, err
	}
	return &r, nil
}

func (r *notifyRule) check() error {
	switch r.On {
	case "new", "becomesTrue", "becomesFalse", "added", "removed":
	case "changed":
		if r.Field == "" {
			return errors.New("changed needs field")
		}
	default:
		return fmt.Errorf("unknown on %q", r.On)
	}
	if _, ok := ruleKinds[r.Kind]; !ok {
		return fmt.Errorf("unknown kind %q", r.Kind)
	}
	if r.Scope != "component" && r.Scope != "event" {
		return fmt.Errorf("unknown scope %q", r.Scope)
	}
	if r.View != "" && r.View != "chat" && r.View != "polls" {
		return fmt.Errorf("unknown view %q", r.View)
	}
	if len(r.Text) == 0 {
		return errors.New("text is empty")
	}
	for i, c := range r.Text {
		if err := c.check(); err != nil {
			return fmt.Errorf("text[%d]: %w", i, err)
		}
	}
	if r.On != "new" && r.SkipListed != nil {
		return errors.New("skipListed needs on new")
	}
	if j := r.Join; j != nil && (j.Show < 1 || j.More != "itemsMore") {
		return errors.New("invalid join")
	}
	if s := r.SkipListed; s != nil && s.List == "" {
		return errors.New("invalid skipListed")
	}
	return nil
}

func (c textCandidate) check() error {
	if c.Field != "" && c.ID != "" {
		return errors.New("takes at most one of field and id")
	}
	if _, ok := textsEN.textByID(c.ID); c.ID != "" && !ok {
		return fmt.Errorf("unknown text id %q", c.ID)
	}
	if c.Empty != "" {
		if c.Field == "" {
			return errors.New("empty needs field")
		}
		if _, ok := textsEN.textByID(c.Empty); !ok {
			return fmt.Errorf("unknown text id %q", c.Empty)
		}
	}
	if c.When != nil && c.When.Field == "" {
		return errors.New("when needs field")
	}
	if sx := c.Suffix; sx != nil {
		if (sx.Component == "") == (sx.Field == "") {
			return errors.New("suffix needs exactly one of component and field")
		}
		if sx.Format != "" && (sx.Field == "" || sx.Format != "minorUnits") {
			return fmt.Errorf("invalid suffix format %q", sx.Format)
		}
	}
	return nil
}

// fired is one changed key that matched a rule; hasValue is false when its new value could not be read, which still makes it the last fired key.
type fired struct {
	key      string
	value    any
	hasValue bool
}

type ruleGroup struct {
	raw  any
	keys []string
}

func (s *PushService) describe(ev *event.Event, app *application.Application, creatorName string, agent bool, lang string) (notice, bool) {
	t := textsFor(lang)
	switch ev.Type {
	case event.EventTypeMemberAdded:
		name := cut(str(ev.Data["userDisplayName"]))
		if name == "" {
			name = t.someone
		}
		return notice{kind: KindMember, scope: ev.ID, body: fmt.Sprintf(t.newMember, name)}, true

	case event.EventTypeMemberRemoved:
		name := cut(str(ev.Data["userDisplayName"]))
		if name == "" {
			name = t.someone
		}
		format := t.memberRemoved
		if ev.CreatorPublicKey == str(ev.Data["memberPublicKey"]) {
			format = t.memberLeft
		}
		return notice{kind: KindMember, scope: ev.ID, body: fmt.Sprintf(format, name)}, true

	case event.EventTypeMemberRoleChanged:
		role := str(ev.Data["newRole"])
		if label, ok := t.roleLabels[role]; ok {
			role = label
		}
		return notice{kind: KindRole, scope: ev.ID, body: t.person(creatorName, agent) + ": " + fmt.Sprintf(t.roleNow, cut(role))}, true

	case event.EventTypeReminderFired:
		return describeReminder(ev, app, t), true

	case event.EventTypeComponentDataChanged:
		return s.describeComponent(ev, app, t, t.person(creatorName, agent))
	}
	return notice{}, false
}

func describeReminder(ev *event.Event, app *application.Application, t texts) notice {
	title := cut(str(ev.Data["itemTitle"]))
	if title == "" {
		title = t.reminder
	}
	offsetSpec := str(ev.Data["offset"])
	offset, err := reminder.ParseOffsetDuration(offsetSpec)
	if err != nil {
		offset = 0
	}
	icon := "⏰ "
	if offset < 0 {
		icon = "🔔 "
	}
	loc := time.UTC
	if l, err := time.LoadLocation(str(ev.Data["tz"])); err == nil {
		loc = l
	}
	occurrenceAt, _ := intOf(ev.Data["occurrenceAt"])
	body := ""
	if occurrenceAt > 0 {
		body = t.clock(time.Unix(occurrenceAt, 0).In(loc))
	}
	if lead := -offset; occurrenceAt > 0 && lead > 0 {
		switch {
		case lead%(24*time.Hour) == 0:
			body = t.inDays(body, int(lead/(24*time.Hour)))
		case lead%time.Hour == 0:
			body = t.inHours(body, int(lead/time.Hour))
		default:
			body = t.inMinutes(body, max(1, int(lead/time.Minute)))
		}
	}
	if comp := findComponent(app, str(ev.Data["componentId"])); comp != nil {
		if ct := cut(str(comp.Data["_title"])); ct != "" {
			if body != "" {
				body += " · "
			}
			body += ct
		}
	}
	scope := ev.ID
	if ruleID := str(ev.Data["ruleId"]); ruleID != "" {
		scope = fmt.Sprintf("%s:%d:%s", ruleID, occurrenceAt, offsetSpec)
	}
	return notice{kind: KindReminder, scope: scope, title: icon + title, body: body}
}

func intOf(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		return int64(n), n == math.Trunc(n)
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
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

func schemaType(name string) string {
	// the only sanctioned component-name switch; every other mapping comes from the schema
	if name == "Gallery" {
		return "Files"
	}
	return name
}

func (s *PushService) describeComponent(ev *event.Event, app *application.Application, t texts, person string) (notice, bool) {
	componentID := str(ev.Data["componentId"])
	comp := findComponent(app, componentID)
	fields, _ := ev.Data["changedFields"].(map[string]any)
	if s.validator == nil || comp == nil || fields == nil {
		return notice{}, false
	}
	typ := schemaType(comp.Name)

	groups := map[string]*ruleGroup{}
	for k := range fields {
		ruleKey, raw, ok := s.validator.Notify(typ, k)
		if !ok {
			continue
		}
		g := groups[ruleKey]
		if g == nil {
			g = &ruleGroup{raw: raw}
			groups[ruleKey] = g
		}
		g.keys = append(g.keys, k)
	}
	ruleKeys := make([]string, 0, len(groups))
	for rk := range groups {
		ruleKeys = append(ruleKeys, rk)
	}
	sort.Strings(ruleKeys)

	for _, rk := range ruleKeys {
		g := groups[rk]
		rules, err := parseNotifyRules(g.raw)
		if err != nil {
			log.Warn().Err(err).Str("type", typ).Str("rule", rk).Msg("[PUSH] Ignoring invalid x-notify rule")
			continue
		}
		sort.Strings(g.keys)
		for _, rule := range rules {
			what, hits, ok := s.evalRule(rule, typ, comp, fields, g.keys, t)
			if !ok {
				continue
			}
			n := notice{kind: ruleKinds[rule.Kind], scope: ev.ID, componentID: componentID, view: rule.View}
			if rule.Scope == "component" {
				n.scope = componentID
			}
			n.componentTitle = cut(str(comp.Data["_title"]))
			n.body = person + ": " + cut(what)
			if rule.On == "becomesFalse" && rule.Field != "" && len(hits) == 1 && len(fields) == 1 {
				n.revertKey, n.revertField = hits[0].key, rule.Field
			}
			return n, true
		}
	}
	return notice{}, false
}

func change(fields map[string]any, key string) (oldV, newV any) {
	m, _ := fields[key].(map[string]any)
	return m["oldValue"], m["newValue"]
}

// firedKeys returns the (key, value) pairs of keys that fire the rule's `on` trigger, in key order.
// oldValue is supplied by the submitting client, so a forged one can trigger or suppress a push (ponytail: capture it server-side in executeComponentDataChanged if that ever matters)
func (s *PushService) firedKeys(r *notifyRule, typ string, fields map[string]any, keys []string) []fired {
	var out []fired
	for _, k := range keys {
		o, n := change(fields, k)
		entryOld, entryNew := o, n
		if r.Field != "" {
			if isEmpty(o) || isEmpty(n) {
				continue
			}
			dn, okN := s.newValue(typ, k, n)
			dold, okO := s.newValue(typ, k, o)
			if !okN || !okO {
				continue
			}
			entryOld, entryNew = dold, dn
			o, _ = dotted(dold, r.Field)
			n, _ = dotted(dn, r.Field)
		}
		switch r.On {
		case "new":
			if !isEmpty(o) || isEmpty(n) {
				continue
			}
			v, ok := s.newValue(typ, k, n)
			out = append(out, fired{k, v, ok})
		case "becomesTrue":
			if n == true && o != true {
				out = append(out, fired{k, entryNew, true})
			}
		case "becomesFalse":
			if o == true && n != true {
				out = append(out, fired{k, entryNew, true})
			}
		case "removed":
			if !isEmpty(o) && isEmpty(n) {
				v, ok := entryOld, true
				if r.Field == "" {
					v, ok = s.newValue(typ, k, o)
				}
				out = append(out, fired{k, v, ok})
			}
		case "changed":
			if !isEmpty(n) && !reflect.DeepEqual(o, n) {
				out = append(out, fired{k, entryNew, true})
			}
		case "added":
			if el := lastAdded(o, n); el != nil {
				out = append(out, fired{k, el, true})
			}
		}
	}
	return out
}

func (s *PushService) newValue(typ, key string, n any) (any, bool) {
	encoded, entry := s.validator.Entry(typ, key)
	if encoded {
		raw, isStr := n.(string)
		if !isStr {
			return nil, false
		}
		n = lens.DecodeEncoded(raw)
	}
	if entry {
		if _, cur, ok := s.validator.Versions(typ); ok {
			if m, _, err := lens.Migrate(s.validator.Steps(typ), key, n, cur); err == nil {
				return m, true
			}
		}
	}
	// an unmigratable value is used as stored so a push is never dropped
	return n, true
}

func lastAdded(o, n any) map[string]any {
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
	return added
}

func (s *PushService) evalRule(r *notifyRule, typ string, comp *application.Component, fields map[string]any, keys []string, t texts) (string, []fired, bool) {
	hits := r.dropListed(s.firedKeys(r, typ, fields, keys), comp)
	if r.Join == nil {
		if len(hits) == 0 || !hits[len(hits)-1].hasValue {
			return "", nil, false
		}
		what := r.evalText(hits[len(hits)-1].value, comp, t)
		return what, hits, what != ""
	}

	var parts []string
	for _, h := range hits {
		if !h.hasValue {
			continue
		}
		if what := r.evalText(h.value, comp, t); what != "" {
			parts = append(parts, what)
		}
	}
	if len(parts) == 0 {
		return "", nil, false
	}
	j := r.Join
	shown := parts[:min(len(parts), j.Show)]
	out := j.Prefix + strings.Join(shown, j.Sep)
	if more := len(parts) - len(shown); more > 0 {
		out += " " + fmt.Sprintf(t.itemsMore, more)
	}
	return out, hits, true
}

func (r *notifyRule) dropListed(hits []fired, comp *application.Component) []fired {
	sl := r.SkipListed
	if sl == nil {
		return hits
	}
	listed := map[string]bool{}
	items, _ := comp.Data[sl.List].([]any)
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			listed[str(m["id"])] = true
		}
	}
	var out []fired
	for _, h := range hits {
		if !listed[strings.TrimPrefix(h.key, sl.Prefix)] {
			out = append(out, h)
		}
	}
	return out
}

func (r *notifyRule) evalText(value any, comp *application.Component, t texts) string {
	for _, c := range r.Text {
		if s := c.eval(value, comp, t); s != "" {
			return s
		}
	}
	return ""
}

func (c textCandidate) eval(value any, comp *application.Component, t texts) string {
	if w := c.When; w != nil {
		v, ok := dotted(value, w.Field)
		if !ok || (w.StartsWith != "" && !strings.HasPrefix(str(v), w.StartsWith)) {
			return ""
		}
	}
	if c.Unless != "" {
		if v, _ := dotted(value, c.Unless); v == true {
			return ""
		}
	}
	var text string
	if c.ID != "" {
		text, _ = t.textByID(c.ID)
	} else {
		v := value
		if c.Field != "" {
			v, _ = dotted(value, c.Field)
		}
		text = strings.TrimSpace(str(v))
		if text == "" {
			if c.Empty == "" {
				return ""
			}
			text, _ = t.textByID(c.Empty)
		}
	}
	text = c.Prefix + text
	if sx := c.Suffix; sx != nil {
		if extra := sx.eval(value, comp); extra != "" {
			text += sx.Sep + extra
		}
	}
	return text
}

func (sx *suffixSpec) eval(value any, comp *application.Component) string {
	if sx.Component != "" {
		return strings.TrimSpace(str(comp.Data[sx.Component]))
	}
	v, _ := dotted(value, sx.Field)
	if sx.Format != "minorUnits" {
		return strings.TrimSpace(str(v))
	}
	if n, ok := intOf(v); ok {
		return minorUnits(n)
	}
	return ""
}

func dotted(v any, path string) (any, bool) {
	for _, seg := range strings.Split(path, ".") {
		switch x := v.(type) {
		case map[string]any:
			next, ok := x[seg]
			if !ok {
				return nil, false
			}
			v = next
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(x) {
				return nil, false
			}
			v = x[i]
		default:
			return nil, false
		}
	}
	return v, true
}
