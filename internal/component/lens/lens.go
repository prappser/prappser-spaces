package lens

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"sync"
)

var (
	ErrBadVersion  = errors.New("bad-version")
	ErrMissingStep = errors.New("missing-step")
	ErrUnsupported = errors.New("unsupported")
	ErrBreaking    = errors.New("breaking")
	ErrReadOnly    = errors.New("read-only")
)

type op struct {
	kind        string
	from, to    []string
	path        []string
	def         any
	pairs       [][2]any
	fallback    any
	hasFallback bool
}

func unsupported(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrUnsupported}, a...)...)
}

func checkArg(name string, n int) error {
	if n < 1 || int64(n) > maxSafe {
		return fmt.Errorf("%s must be an integer between 1 and %d, got %d", name, int64(maxSafe), n)
	}
	return nil
}

func num(n int64) json.Number { return json.Number(strconv.FormatInt(n, 10)) }

func version(m map[string]any) (int64, error) {
	v, ok := m["v"]
	if !ok {
		return 1, nil
	}
	n, ok := intVal(v)
	if !ok || n.Sign() < 1 || n.Cmp(maxSafeBig) > 0 {
		return 0, fmt.Errorf("%w: v must be an integer between 1 and %d", ErrBadVersion, int64(maxSafe))
	}
	return n.Int64(), nil
}

// A valid to below int64 range is reported as MinInt64, which no walk matches (N6); it is not malformed.
func stepTo(el any) (to int64, valid bool) {
	m, ok := el.(map[string]any)
	if !ok {
		return 0, false
	}
	raw, ok := m["to"]
	if !ok {
		return 0, false
	}
	n, ok := intVal(raw)
	if !ok || n.Cmp(maxSafeBig) > 0 {
		return 0, false
	}
	if !n.IsInt64() {
		return math.MinInt64, true
	}
	return n.Int64(), true
}

var patternCache sync.Map

func compilePattern(pattern string) (*regexp.Regexp, error) {
	if re, ok := patternCache.Load(pattern); ok {
		return re.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	patternCache.Store(pattern, re)
	return re, nil
}

func lookup(steps any, k int64, key string) (ops []op, breaking bool, err error) {
	list, ok := steps.([]any)
	if !ok {
		return nil, false, unsupported("x-migrations is not a list")
	}
	var match map[string]any
	matches, malformed := 0, false
	for _, el := range list {
		to, valid := stepTo(el)
		switch {
		case !valid:
			malformed = true
		case to == k:
			match = el.(map[string]any)
			matches++
		}
	}
	switch {
	case matches > 1:
		return nil, false, unsupported("several steps have to %d", k)
	case matches == 0 && malformed:
		return nil, false, unsupported("no step has to %d and the list holds a malformed element", k)
	case matches == 0:
		return nil, false, fmt.Errorf("%w: no step has to %d", ErrMissingStep, k)
	}
	for name := range match {
		if name != "to" && name != "breaking" && name != "entries" {
			return nil, false, unsupported("step %d has unknown member %q", k, name)
		}
	}
	breaking, ok = match["breaking"].(bool)
	entries, eok := match["entries"].(map[string]any)
	if !ok || !eok {
		return nil, false, unsupported("step %d needs a boolean breaking and an object entries", k)
	}
	var found any
	hits := 0
	for pattern, candidate := range entries {
		re, err := compilePattern(pattern)
		if err != nil {
			return nil, false, unsupported("step %d: bad entries pattern %q", k, pattern)
		}
		if re.MatchString(key) {
			found = candidate
			hits++
		}
	}
	if hits > 1 {
		return nil, false, unsupported("step %d: several entries patterns match %q", k, key)
	}
	if hits == 1 {
		raw, ok := found.([]any)
		if !ok {
			return nil, false, unsupported("step %d: ops are not a list", k)
		}
		for _, r := range raw {
			o, err := compileOp(r)
			if err != nil {
				return nil, false, fmt.Errorf("step %d: %w", k, err)
			}
			ops = append(ops, o)
		}
	}
	return ops, breaking, nil
}

func parsePath(raw any) ([]string, bool) {
	s, ok := raw.(string)
	if !ok || s == "" {
		return nil, false
	}
	var names []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '.' {
			continue
		}
		name := s[start:i]
		if !validName(name) {
			return nil, false
		}
		names = append(names, name)
		start = i + 1
	}
	return names, names[0] != "v"
}

func validName(n string) bool {
	if n == "" {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		letter := c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if !letter && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func isPrefix(a, b []string) bool {
	if len(a) > len(b) {
		a, b = b, a
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isScalar(x any) bool {
	switch x.(type) {
	case nil, string, bool, json.Number:
		return true
	}
	_, ok := toRat(x)
	return ok
}

var opMembers = map[string][]string{
	"rename": {"from", "to"},
	"move":   {"from", "to"},
	"add":    {"path", "default"},
	"map":    {"path", "pairs"},
	"wrap":   {"path"},
	"unwrap": {"path"},
}

func compileOp(raw any) (op, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return op{}, unsupported("op is not an object")
	}
	kind, _ := m["op"].(string)
	req, ok := opMembers[kind]
	if !ok {
		return op{}, unsupported("unknown op %v", m["op"])
	}
	allowed := len(req) + 1
	if kind == "map" {
		if _, has := m["fallback"]; has {
			allowed++
		}
	}
	if len(m) != allowed {
		return op{}, unsupported("%s has wrong members", kind)
	}
	for _, name := range req {
		if _, has := m[name]; !has {
			return op{}, unsupported("%s lacks %s", kind, name)
		}
	}
	o := op{kind: kind}
	switch kind {
	case "rename", "move":
		var okFrom, okTo bool
		o.from, okFrom = parsePath(m["from"])
		o.to, okTo = parsePath(m["to"])
		if !okFrom || !okTo || isPrefix(o.from, o.to) {
			return op{}, unsupported("%s has bad paths", kind)
		}
		return o, nil
	}
	if o.path, ok = parsePath(m["path"]); !ok {
		return op{}, unsupported("%s has a bad path", kind)
	}
	switch kind {
	case "add":
		o.def = m["default"]
	case "map":
		if err := o.compileMap(m); err != nil {
			return op{}, err
		}
	}
	return o, nil
}

func (o *op) compileMap(m map[string]any) error {
	if fb, has := m["fallback"]; has {
		if !isScalar(fb) {
			return unsupported("map fallback is not a scalar")
		}
		o.fallback, o.hasFallback = fb, true
	}
	pairs, ok := m["pairs"].([]any)
	if !ok {
		return unsupported("map pairs is not a list")
	}
	for _, p := range pairs {
		pair, ok := p.([]any)
		if !ok || len(pair) != 2 || !isScalar(pair[0]) || !isScalar(pair[1]) {
			return unsupported("map pair is not a scalar pair")
		}
		for _, seen := range o.pairs {
			if equal(seen[0], pair[0]) || equal(seen[1], pair[1]) {
				return unsupported("map pairs repeat a value")
			}
		}
		o.pairs = append(o.pairs, [2]any{pair[0], pair[1]})
	}
	return nil
}

func getPath(root map[string]any, p []string) (any, bool) {
	var cur any = root
	for _, n := range p {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[n]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func removePath(root map[string]any, p []string, prune bool) {
	chain := []map[string]any{root}
	for _, n := range p[:len(p)-1] {
		next, ok := chain[len(chain)-1][n].(map[string]any)
		if !ok {
			return
		}
		chain = append(chain, next)
	}
	last := p[len(p)-1]
	if _, ok := chain[len(chain)-1][last]; !ok {
		return
	}
	delete(chain[len(chain)-1], last)
	for i := len(p) - 1; prune && i > 0 && len(chain[i]) == 0; i-- {
		delete(chain[i-1], p[i-1])
	}
}

func canSet(root map[string]any, p []string) bool {
	cur := root
	for _, n := range p[:len(p)-1] {
		next, present := cur[n]
		if !present {
			return true
		}
		m, ok := next.(map[string]any)
		if !ok {
			return false
		}
		cur = m
	}
	return true
}

func setPath(root map[string]any, p []string, val any) {
	cur := root
	for _, n := range p[:len(p)-1] {
		next, ok := cur[n].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[n] = next
		}
		cur = next
	}
	cur[p[len(p)-1]] = val
}

func wrapUp(x any) any {
	switch v := x.(type) {
	case nil:
		return []any{}
	case []any:
		return v
	}
	return []any{x}
}

func wrapDown(x any) any {
	if l, ok := x.([]any); ok {
		if len(l) == 0 {
			return nil
		}
		return l[0]
	}
	return x
}

func (o op) apply(root map[string]any, up bool) {
	switch o.kind {
	case "rename", "move":
		from, to := o.from, o.to
		if !up {
			from, to = to, from
		}
		val, ok := getPath(root, from)
		if !ok || !canSet(root, to) {
			return
		}
		removePath(root, from, true)
		setPath(root, to, val)
		return
	case "add":
		_, present := getPath(root, o.path)
		switch {
		case !up:
			removePath(root, o.path, true)
		case !present && canSet(root, o.path):
			setPath(root, o.path, clone(o.def))
		}
		return
	}
	cur, ok := getPath(root, o.path)
	if !ok {
		return
	}
	switch o.kind {
	case "map":
		for _, p := range o.pairs {
			from, to := p[0], p[1]
			if !up {
				from, to = to, from
			}
			if equal(cur, from) {
				setPath(root, o.path, to)
				return
			}
		}
		if !up && o.hasFallback {
			setPath(root, o.path, o.fallback)
		}
	case "wrap":
		if up {
			setPath(root, o.path, wrapUp(cur))
		} else {
			setPath(root, o.path, wrapDown(cur))
		}
	case "unwrap":
		if up {
			setPath(root, o.path, wrapDown(cur))
		} else {
			setPath(root, o.path, wrapUp(cur))
		}
	}
}

func (o op) lossy(up bool) bool {
	switch o.kind {
	case "map":
		return !up && o.hasFallback
	case "wrap":
		return !up
	case "unwrap":
		return up
	}
	return false
}

func migrate(steps any, key string, m map[string]any, to int64) (map[string]any, bool, error) {
	e, err := version(m)
	if err != nil {
		return nil, false, err
	}
	out := cloneMap(m)
	if e == to {
		return out, false, nil
	}
	lossy := false
	if e < to {
		for k := e + 1; k <= to; k++ {
			ops, _, err := lookup(steps, k, key)
			if err != nil {
				return nil, false, err
			}
			for _, o := range ops {
				o.apply(out, true)
				lossy = lossy || o.lossy(true)
			}
		}
	} else {
		for k := e; k > to; k-- {
			ops, breaking, err := lookup(steps, k, key)
			if err != nil {
				return nil, false, err
			}
			if breaking {
				return nil, false, fmt.Errorf("%w: step %d is breaking", ErrBreaking, k)
			}
			for i := len(ops) - 1; i >= 0; i-- {
				ops[i].apply(out, false)
				lossy = lossy || ops[i].lossy(false) || ops[i].lossy(true)
			}
		}
	}
	out["v"] = num(to)
	return out, lossy, nil
}

func Migrate(steps any, key string, value any, to int) (out any, lossy bool, err error) {
	if err := checkArg("to", to); err != nil {
		return nil, false, err
	}
	m, ok := value.(map[string]any)
	if !ok {
		return clone(value), false, nil
	}
	res, lossy, err := migrate(steps, key, m, int64(to))
	if err != nil {
		return nil, false, err
	}
	return res, lossy, nil
}

func Steps(schema []byte) (any, error) {
	root, err := decodeJSON(schema)
	if err != nil {
		return nil, fmt.Errorf("failed to parse schema: %w", err)
	}
	if m, ok := root.(map[string]any); ok {
		if raw, ok := m["x-migrations"]; ok {
			return raw, nil
		}
	}
	return []any{}, nil
}
