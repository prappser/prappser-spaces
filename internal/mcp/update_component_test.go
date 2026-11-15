package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/prappser/prappser-spaces/internal/component"
)

const (
	settleKey = "s_0190a3b4-1c2d-7e3f-8a4b-5c6d7e8f9a0b"
	partyOnly = "from or to must be your publicKey"
)

func writeGate(t *testing.T, old, data map[string]any) error {
	t.Helper()
	v, err := component.NewValidator()
	require.NoError(t, err)
	_, _, err = checkWrite(v, "Expenses", old, data, "me", false, func(string, map[string]any) error { return nil })
	return err
}

func TestCheckWrite_ExpensesShouldGateWritesByKeyAndAuthor(t *testing.T) {
	mine := `{"from":"me","to":"x"}`
	theirs := `{"from":"x","to":"y"}`
	toMe := `{"from":"x","to":"me"}`
	cases := []struct {
		name    string
		old     map[string]any
		key     string
		value   any
		wantErr string
	}{
		{"own pay_ key", nil, "pay_me", []any{}, ""},
		{"someone else's pay_ key", nil, "pay_x", []any{}, "key pay_x: you can only write your own cell"},
		{"reminder from me", nil, "r_me__x", mine, ""},
		{"reminder from someone else", nil, "r_me__x", theirs, "key r_me__x: from must be your publicKey"},
		{"overwrite someone else's reminder", map[string]any{"r_x__y": theirs}, "r_x__y", mine, "key r_x__y: from must be your publicKey"},
		{"tombstone someone else's reminder", map[string]any{"r_x__y": theirs}, "r_x__y", "", "key r_x__y: from must be your publicKey"},
		{"overwrite someone else's settlement", map[string]any{settleKey: theirs}, settleKey, mine, "key " + settleKey + ": " + partyOnly},
		{"tombstone someone else's settlement", map[string]any{settleKey: theirs}, settleKey, "", "key " + settleKey + ": " + partyOnly},
		{"party tombstones own settlement (from)", map[string]any{settleKey: mine}, settleKey, "", ""},
		{"party tombstones own settlement (to)", map[string]any{settleKey: toMe}, settleKey, "", ""},
		{"party overwrites own settlement (to)", map[string]any{settleKey: toMe}, settleKey, mine, ""},
	}
	for _, c := range cases {
		// when
		err := writeGate(t, c.old, map[string]any{c.key: c.value})

		// then
		if c.wantErr == "" {
			assert.NoError(t, err, c.name)
		} else {
			assert.EqualError(t, err, c.wantErr, c.name)
		}
	}
}

// The key pattern cannot bind the key's creditor to from, so any member passes the
// author check by putting their own key in from. The app ignores such rows; server-side
// reminder rate limiting is out of scope.
func TestCheckWrite_ReminderKeyCreditorIsNotBoundToFrom(t *testing.T) {
	// when
	err := writeGate(t, nil, map[string]any{"r_alice__bob": `{"from":"me","to":"bob","amount":1}`})

	// then
	assert.NoError(t, err)
}
