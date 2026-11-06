package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/prappser/prappser-spaces/internal/component"
	"github.com/prappser/prappser-spaces/internal/component/lens"
)

const (
	stateFull        = "full"
	stateReadOnly    = "read-only"
	stateNeedsUpdate = "needs-update"
	stateBadVersion  = "bad-version"
)

type reader struct {
	lo, cur int
	steps   any
}

func readerFor(v *component.Validator, typ string) (reader, bool) {
	lo, cur, ok := v.Versions(typ)
	return reader{lo: lo, cur: cur, steps: v.Steps(typ)}, ok
}

func plain(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if json.Unmarshal(b, &out) != nil {
		return v
	}
	return out
}

func encode(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return strings.TrimRight(buf.String(), "\n")
}

func entryVersion(m map[string]any) (int, bool) {
	raw, ok := m["v"]
	if !ok {
		return 1, true
	}
	var f float64
	switch n := raw.(type) {
	case float64:
		f = n
	case json.Number:
		f, _ = n.Float64()
	default:
		return 0, false
	}
	if f < 1 || f != math.Trunc(f) || f > 1<<53-1 {
		return 0, false
	}
	return int(f), true
}

func entryMap(encoded bool, raw any) (map[string]any, bool) {
	if encoded {
		s, ok := raw.(string)
		if !ok {
			return nil, false
		}
		raw = lens.DecodeEncoded(s)
	}
	m, ok := raw.(map[string]any)
	return m, ok
}

func (r reader) classify(key string, m map[string]any) (map[string]any, string) {
	e, ok := entryVersion(m)
	if !ok {
		return nil, stateBadVersion
	}
	if e > r.cur {
		return nil, stateNeedsUpdate
	}
	out, lossy, err := lens.Migrate(r.steps, key, m, r.cur)
	if err != nil {
		return nil, stateBadVersion
	}
	view, _ := plain(out).(map[string]any)
	if lossy {
		return view, stateReadOnly
	}
	return view, stateFull
}

func (r reader) entryRead(encoded bool, key string, raw any) (any, string) {
	m, ok := entryMap(encoded, raw)
	if !ok {
		return raw, stateFull
	}
	view, state := r.classify(key, m)
	if state == stateNeedsUpdate || state == stateBadVersion {
		return raw, state
	}
	if encoded {
		s, _, err := lens.MigrateEncoded(r.steps, key, raw.(string), r.cur)
		if err != nil {
			return raw, stateBadVersion
		}
		return s, state
	}
	return view, state
}

func componentData(v *component.Validator, typ string, data map[string]any) (map[string]any, map[string]string) {
	r, ok := readerFor(v, typ)
	if !ok {
		return data, nil
	}
	out := make(map[string]any, len(data))
	var states map[string]string
	for k, raw := range data {
		encoded, isEntry := v.Entry(typ, k)
		if !isEntry {
			out[k] = raw
			continue
		}
		val, state := r.entryRead(encoded, k, raw)
		out[k] = val
		if state != stateFull {
			if states == nil {
				states = map[string]string{}
			}
			states[k] = state
		}
	}
	return out, states
}

func (r reader) shape(encoded bool, val any, inject bool) (any, error) {
	m, ok := entryMap(encoded, val)
	if !ok {
		return val, nil
	}
	if _, has := m["v"]; has {
		n, ok := entryVersion(m)
		if !ok || n < r.lo || n > r.cur {
			return nil, fmt.Errorf("v must be an integer between %d and %d", r.lo, r.cur)
		}
		if n == r.cur {
			return val, nil
		}
	} else if !inject {
		return val, nil
	}
	out := maps.Clone(m)
	out["v"] = float64(r.cur)
	if encoded {
		return encode(out), nil
	}
	return out, nil
}

func (r reader) prepare(v *component.Validator, typ string, stored, data map[string]any) (map[string]any, error) {
	out := maps.Clone(data)
	for _, k := range slices.Sorted(maps.Keys(data)) {
		encoded, isEntry := v.Entry(typ, k)
		if !isEntry {
			continue
		}
		fail := func(why string) error { return errors.New("key " + k + ": " + why) }
		val := data[k]
		orig, exists := entryMap(encoded, stored[k])
		state := stateFull
		inject := r.cur >= 2
		if exists {
			var view map[string]any
			view, state = r.classify(k, orig)
			_, inject = view["v"]
		}
		blocked := state == stateNeedsUpdate || state == stateBadVersion
		if val == "" {
			if blocked {
				return nil, fail("needs an app update, so it cannot be deleted")
			}
			continue
		}
		switch {
		case blocked:
			return nil, fail("needs an app update before it can be edited")
		case state == stateReadOnly:
			return nil, fail("read-only in this version (lossy), so it cannot be edited")
		}
		shaped, err := r.shape(encoded, val, inject)
		if err != nil {
			return nil, fail(err.Error())
		}
		out[k] = shaped
	}
	return out, nil
}

func (r reader) apply(v *component.Validator, typ string, stored, data map[string]any) (map[string]any, error) {
	out := make(map[string]any, len(data))
	for _, k := range slices.Sorted(maps.Keys(data)) {
		val := data[k]
		encoded, isEntry := v.Entry(typ, k)
		orig, exists := entryMap(encoded, stored[k])
		if !isEntry || !exists || val == "" {
			out[k] = val
			continue
		}
		edited, ok := entryMap(encoded, val)
		if !ok {
			return nil, errors.New("key " + k + ": value must be an object")
		}
		var (
			next  any
			wrote bool
			err   error
		)
		if encoded {
			next, wrote, err = lens.WriteBackEncoded(r.steps, k, stored[k].(string), r.cur, edited)
		} else {
			next, wrote, err = lens.WriteBack(r.steps, k, orig, r.cur, edited)
			next = plain(next)
		}
		if err != nil {
			return nil, errors.New("key " + k + ": the edit does not fit the stored value")
		}
		if wrote {
			out[k] = next
		}
	}
	return out, nil
}

func shapeHint(v *component.Validator, typ string) string {
	if _, cur, ok := v.Versions(typ); ok && cur >= 2 {
		return fmt.Sprintf(": values must use the v%d shape, see describe_component", cur)
	}
	return ""
}

func planWrite(v *component.Validator, typ string, stored, set map[string]any, publicKey string, privileged bool) (map[string]any, *sdk.CallToolResult, error) {
	data := mintKeys(set)
	r, versioned := readerFor(v, typ)
	old := stored
	if versioned {
		old, _ = componentData(v, typ, stored)
		var err error
		if data, err = r.prepare(v, typ, stored, data); err != nil {
			return nil, nil, err
		}
	}
	if _, res, err := checkWrite(v, typ, old, data, publicKey, privileged, v.ValidateComponentKeys); res != nil || err != nil {
		return nil, res, err
	}
	if !versioned {
		return data, nil, nil
	}
	written, err := r.apply(v, typ, stored, data)
	return written, nil, err
}
