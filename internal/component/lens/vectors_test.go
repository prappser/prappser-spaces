package lens

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const lensDir = "../schemas/vectors/lens"

var sentinels = map[string]error{
	"bad-version":  ErrBadVersion,
	"missing-step": ErrMissingStep,
	"unsupported":  ErrUnsupported,
	"breaking":     ErrBreaking,
	"read-only":    ErrReadOnly,
}

var kindMembers = map[string][]string{
	"migrate":   {"steps", "key", "in", "to", "out", "lossy", "error"},
	"writeback": {"steps", "key", "original", "reader", "view", "edited", "result", "error"},
	"state":     {"steps", "reader", "entries", "expect"},
}

type vectorFile struct {
	name  string
	cases []map[string]any
}

func loadVectors(t *testing.T) []vectorFile {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(lensDir, "*.json"))
	require.NoError(t, err)
	var out []vectorFile
	for _, f := range files {
		file := filepath.Base(f)
		raw, err := os.ReadFile(f)
		require.NoError(t, err, file)
		doc, err := decodeJSON(raw)
		require.NoError(t, err, "%s: unparseable", file)
		root, _ := doc.(map[string]any)
		list, _ := root["cases"].([]any)
		require.NotEmpty(t, list, "%s: no cases", file)
		vf := vectorFile{name: file}
		for i, rc := range list {
			c, ok := rc.(map[string]any)
			require.True(t, ok, "%s: case %d is not an object", file, i)
			vf.cases = append(vf.cases, c)
		}
		out = append(out, vf)
	}
	return out
}

func smallInt(v any) (int, bool) {
	n, ok := intVal(v)
	if !ok || !n.IsInt64() || n.Int64() > maxSafe || n.Int64() < -maxSafe {
		return 0, false
	}
	return int(n.Int64()), true
}

func has(c map[string]any, name string) bool {
	_, ok := c[name]
	return ok
}

func checkShape(c map[string]any) string {
	if _, ok := c["name"].(string); !ok {
		return "name is missing or not a string"
	}
	kind, _ := c["kind"].(string)
	members, ok := kindMembers[kind]
	if !ok {
		return fmt.Sprintf("unknown kind %v", c["kind"])
	}
	allowed := map[string]bool{"name": true, "kind": true, "note": true}
	for _, m := range members {
		allowed[m] = true
	}
	for m := range c {
		if !allowed[m] {
			return fmt.Sprintf("unknown member %q", m)
		}
	}
	if has(c, "error") {
		code, _ := c["error"].(string)
		sentinel, known := sentinels[code]
		if !known || (sentinel == ErrReadOnly) != (kind == "writeback" && code == "read-only") {
			return fmt.Sprintf("error %v not allowed for kind %s", c["error"], kind)
		}
	}
	for _, m := range []string{"steps"} {
		if !has(c, m) {
			return "missing member " + m
		}
	}
	if _, ok := c["key"].(string); !ok && kind != "state" {
		return "key is missing or not a string"
	}
	switch kind {
	case "migrate":
		if !has(c, "in") {
			return "missing member in"
		}
		if _, ok := smallInt(c["to"]); !ok {
			return "to is missing or not an integer"
		}
		_, isBool := c["lossy"].(bool)
		if has(c, "error") == (has(c, "out") || has(c, "lossy")) || has(c, "out") != has(c, "lossy") || has(c, "lossy") && !isBool {
			return "migrate case needs error, or out and a boolean lossy"
		}
	case "writeback":
		if _, ok := smallInt(c["reader"]); !ok {
			return "reader is missing or not an integer"
		}
		if !has(c, "original") || !has(c, "view") {
			return "missing original or view"
		}
		if _, ok := c["edited"].(map[string]any); !ok {
			return "edited is missing or not an object"
		}
		if has(c, "error") == has(c, "result") {
			return "writeback case needs result or error"
		}
	case "state":
		if _, ok := smallInt(c["reader"]); !ok {
			return "reader is missing or not an integer"
		}
		if msg := checkEntries(c["entries"]); msg != "" {
			return msg
		}
		switch c["expect"] {
		case "full", "read-only", "needs-update":
		default:
			return fmt.Sprintf("bad expect %v", c["expect"])
		}
	}
	return ""
}

func checkEntries(raw any) string {
	list, ok := raw.([]any)
	if !ok {
		return "entries is missing or not a list"
	}
	for _, r := range list {
		m, ok := r.(map[string]any)
		if !ok {
			return "entry is not an object"
		}
		if _, ok := m["key"].(string); !ok || !has(m, "value") || len(m) != 2 {
			return "entry needs exactly key (string) and value"
		}
	}
	return ""
}

func expectErr(c map[string]any, err error) string {
	want, hasErr := c["error"].(string)
	switch {
	case !hasErr && err != nil:
		return fmt.Sprintf("unexpected error %v", err)
	case hasErr && err == nil:
		return fmt.Sprintf("expected error %s", want)
	case hasErr && !errors.Is(err, sentinels[want]):
		return fmt.Sprintf("expected error %s, got %v", want, err)
	}
	return ""
}

func runCase(c map[string]any) string {
	if msg := checkShape(c); msg != "" {
		return msg
	}
	steps := c["steps"]
	switch c["kind"] {
	case "migrate":
		to, _ := smallInt(c["to"])
		out, lossy, err := Migrate(steps, c["key"].(string), c["in"], to)
		if msg := expectErr(c, err); msg != "" || err != nil {
			return msg
		}
		if !equal(out, c["out"]) || lossy != c["lossy"] {
			return fmt.Sprintf("got %v lossy=%v, want %v lossy=%v", out, lossy, c["out"], c["lossy"])
		}
	case "writeback":
		key, _ := c["key"].(string)
		reader, _ := smallInt(c["reader"])
		view, _, err := Migrate(steps, key, c["original"], reader)
		if err == nil && !equal(view, c["view"]) {
			return fmt.Sprintf("view is %v, want %v", view, c["view"])
		}
		edited, _ := c["edited"].(map[string]any)
		out, wrote, err := WriteBack(steps, key, c["original"], reader, edited)
		if msg := expectErr(c, err); msg != "" || err != nil {
			return msg
		}
		if !equal(out, c["result"]) {
			return fmt.Sprintf("got %v, want %v", out, c["result"])
		}
		if wrote == equal(c["result"], c["original"]) {
			return fmt.Sprintf("wrote=%v but result equals original is %v", wrote, !wrote)
		}
	case "state":
		var entries []Entry
		list, _ := c["entries"].([]any)
		for _, re := range list {
			m, _ := re.(map[string]any)
			key, _ := m["key"].(string)
			entries = append(entries, Entry{Key: key, Value: m["value"]})
		}
		reader, _ := smallInt(c["reader"])
		got, err := ComponentState(steps, reader, entries)
		if err != nil {
			return fmt.Sprintf("unexpected error %v", err)
		}
		if got.String() != c["expect"] {
			return fmt.Sprintf("state is %s, want %v", got, c["expect"])
		}
	}
	return ""
}

func TestLensVectors_ShouldPassEveryCase(t *testing.T) {
	// given the vector files on disk
	files := loadVectors(t)

	// when every case runs once
	for _, f := range files {
		for _, c := range f.cases {
			// then a failure names its file and case
			if msg := runCase(c); msg != "" {
				t.Errorf("%s: %v: %s", f.name, c["name"], msg)
			}
		}
	}
}

func TestLensVectors_ShouldRunEveryFile(t *testing.T) {
	// given
	matches, err := filepath.Glob(filepath.Join(lensDir, "*.json"))
	require.NoError(t, err)
	var globbed []string
	for _, f := range matches {
		globbed = append(globbed, strings.TrimSuffix(filepath.Base(f), ".json"))
	}
	sort.Strings(globbed)

	// when
	files := loadVectors(t)

	// then
	var loaded []string
	kinds := map[string]bool{}
	for _, f := range files {
		assert.NotEmpty(t, f.cases, f.name)
		loaded = append(loaded, strings.TrimSuffix(f.name, ".json"))
		for _, c := range f.cases {
			kinds[fmt.Sprint(c["kind"])] = true
		}
	}
	sort.Strings(loaded)
	assert.Equal(t, globbed, loaded)
	for _, want := range []string{"rename", "move", "add", "map", "wrap", "unwrap", "chain"} {
		assert.Contains(t, loaded, want)
	}
	for kind := range kindMembers {
		assert.True(t, kinds[kind], "no %s case", kind)
	}
}

func TestRunCase_ShouldFailMalformedCasesWithoutPanicking(t *testing.T) {
	// given
	bad := []string{
		`{"name":"a","kind":"state","steps":[],"reader":1,"entries":[{"key":5,"value":1}],"expect":"full"}`,
		`{"name":"a","kind":"state","steps":[],"reader":1,"entries":"x","expect":"full"}`,
		`{"name":"a","kind":"migrate","steps":[],"key":7,"in":{},"to":1,"out":{},"lossy":false}`,
		`{"name":"a","kind":"migrate","steps":[],"key":"k","in":{},"to":1.5,"out":{},"lossy":false}`,
		`{"name":"a","kind":"writeback","steps":[],"key":"k","original":{},"reader":1,"view":{},"edited":5,"result":{}}`,
		`{"name":"a","kind":"nope"}`,
	}

	for _, s := range bad {
		// when
		msg := runCase(obj(t, s))

		// then
		assert.NotEmpty(t, msg, s)
	}
}
