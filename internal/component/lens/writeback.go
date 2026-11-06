package lens

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

type State int

const (
	StateFull State = iota
	StateReadOnly
	StateNeedsUpdate
)

func (s State) String() string {
	switch s {
	case StateReadOnly:
		return "read-only"
	case StateNeedsUpdate:
		return "needs-update"
	}
	return "full"
}

type Entry struct {
	Key   string
	Value any
}

func WriteBack(steps any, key string, original any, reader int, edited map[string]any) (out any, wrote bool, err error) {
	if err := checkArg("reader", reader); err != nil {
		return nil, false, err
	}
	o, ok := original.(map[string]any)
	if !ok {
		return nil, false, fmt.Errorf("write-back needs an entry object, got %T", original)
	}
	r := int64(reader)
	view, lossy, err := migrate(steps, key, o, r)
	if err != nil {
		return nil, false, err
	}
	if lossy {
		return nil, false, fmt.Errorf("%w: entry %s is lossy at version %d", ErrReadOnly, key, r)
	}
	e, _ := version(o)
	if e < r {
		a, b := cloneMap(view), cloneMap(edited)
		delete(a, "v")
		delete(b, "v")
		if equal(a, b) {
			return original, false, nil
		}
		b = cloneMap(edited)
		b["v"] = num(r)
		return b, true, nil
	}
	w := cloneMap(edited)
	w["v"] = num(r)
	u, u2 := view, w
	if e > r {
		if u, _, err = migrate(steps, key, view, e); err != nil {
			return nil, false, err
		}
		if u2, _, err = migrate(steps, key, w, e); err != nil {
			return nil, false, err
		}
	}
	res := cloneMap(o)
	diffApply(res, u, u2, nil)
	if _, ok := res["v"]; ok {
		res["v"] = num(e)
	}
	if equal(res, o) {
		return original, false, nil
	}
	return res, true, nil
}

func diffApply(res, u, u2 map[string]any, prefix []string) {
	for k, a := range u {
		if prefix == nil && k == "v" {
			continue
		}
		p := append(prefix[:len(prefix):len(prefix)], k)
		b, ok := u2[k]
		if !ok {
			removePath(res, p, false)
			continue
		}
		diffValue(res, a, b, p)
	}
	for k, b := range u2 {
		if _, ok := u[k]; ok || prefix == nil && k == "v" {
			continue
		}
		setPath(res, append(prefix[:len(prefix):len(prefix)], k), clone(b))
	}
}

func diffValue(res map[string]any, a, b any, p []string) {
	if equal(a, b) {
		return
	}
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		diffApply(res, am, bm, p)
		return
	}
	setPath(res, p, clone(b))
}

func ComponentState(steps any, reader int, entries []Entry) (State, error) {
	if err := checkArg("reader", reader); err != nil {
		return StateFull, err
	}
	state := StateFull
	for _, en := range entries {
		m, ok := en.Value.(map[string]any)
		if !ok {
			continue
		}
		if _, err := version(m); err != nil {
			continue
		}
		_, lossy, err := migrate(steps, en.Key, m, int64(reader))
		if err != nil {
			return StateNeedsUpdate, nil
		}
		if lossy {
			state = StateReadOnly
		}
	}
	return state, nil
}

func DecodeEncoded(raw string) any {
	v, err := decodeJSON([]byte(raw))
	if m, ok := v.(map[string]any); err == nil && ok {
		return m
	}
	return raw
}

func encode(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", fmt.Errorf("failed to encode entry: %w", err)
	}
	return string(bytes.TrimRight(buf.Bytes(), "\n")), nil
}

func MigrateEncoded(steps any, key, raw string, to int) (string, bool, error) {
	m, ok := DecodeEncoded(raw).(map[string]any)
	if !ok {
		return raw, false, nil
	}
	if err := checkArg("to", to); err != nil {
		return "", false, err
	}
	if v, err := version(m); err == nil && v == int64(to) {
		return raw, false, nil
	}
	out, lossy, err := migrate(steps, key, m, int64(to))
	if err != nil {
		return "", false, err
	}
	if equal(out, m) {
		return raw, lossy, nil
	}
	s, err := encode(out)
	return s, lossy, err
}

func WriteBackEncoded(steps any, key, original string, reader int, edited map[string]any) (string, bool, error) {
	if err := checkArg("reader", reader); err != nil {
		return "", false, err
	}
	m, ok := DecodeEncoded(original).(map[string]any)
	if !ok {
		return "", false, errors.New("write-back needs an encoded entry object")
	}
	out, wrote, err := WriteBack(steps, key, m, reader, edited)
	if err != nil || !wrote {
		return original, false, err
	}
	s, err := encode(out)
	return s, true, err
}
