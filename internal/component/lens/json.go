package lens

import (
	"bytes"
	"encoding/json"
	"io"
	"math/big"
	"strconv"
	"strings"
)

const maxSafe = 1<<53 - 1

var maxSafeBig = big.NewInt(maxSafe)

func decodeJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, io.ErrUnexpectedEOF
	}
	return v, nil
}

// ponytail: numbers with a huge exponent or text are never built into a Rat (DoS) and equal only by exact text; Dart parity for such inputs is undefined.
func hugeNumber(n json.Number) bool {
	s := string(n)
	if len(s) > 1024 {
		return true
	}
	i := strings.IndexAny(s, "eE")
	if i < 0 {
		return false
	}
	exp, err := strconv.Atoi(s[i+1:])
	return err != nil || exp > 1000 || exp < -1000
}

func toRat(x any) (*big.Rat, bool) {
	switch n := x.(type) {
	case json.Number:
		if hugeNumber(n) || strings.ContainsRune(string(n), '/') {
			return nil, false
		}
		return new(big.Rat).SetString(string(n))
	case float64:
		r := new(big.Rat).SetFloat64(n)
		return r, r != nil
	case int:
		return new(big.Rat).SetInt64(int64(n)), true
	case int64:
		return new(big.Rat).SetInt64(n), true
	}
	return nil, false
}

func intVal(x any) (*big.Int, bool) {
	r, ok := toRat(x)
	if !ok || !r.IsInt() {
		return nil, false
	}
	return r.Num(), true
}

func equal(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, xv := range x {
			yv, ok := y[k]
			if !ok || !equal(xv, yv) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !equal(x[i], y[i]) {
				return false
			}
		}
		return true
	}
	if nx, ok := a.(json.Number); ok {
		if ny, ok := b.(json.Number); ok && (hugeNumber(nx) || hugeNumber(ny)) {
			return nx == ny
		}
	}
	rx, ok := toRat(a)
	if !ok {
		return false
	}
	ry, ok := toRat(b)
	return ok && rx.Cmp(ry) == 0
}

func clone(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return cloneMap(x)
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = clone(x[i])
		}
		return out
	}
	return v
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = clone(v)
	}
	return out
}
