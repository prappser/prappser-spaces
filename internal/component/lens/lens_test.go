package lens

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const keyA = "item_a"

func parse(t *testing.T, s string) any {
	t.Helper()
	v, err := decodeJSON([]byte(s))
	require.NoError(t, err)
	return v
}

func obj(t *testing.T, s string) map[string]any {
	t.Helper()
	m, ok := parse(t, s).(map[string]any)
	require.True(t, ok)
	return m
}

func step(to, ops string) string {
	return `{"to":` + to + `,"breaking":false,"entries":{"^item_.+$":[` + ops + `]}}`
}

func isLens(err error) bool {
	for _, s := range sentinels {
		if errors.Is(err, s) {
			return true
		}
	}
	return false
}

func TestSteps_ShouldReturnEmptyListWhenAbsent(t *testing.T) {
	// given
	schema := []byte(`{"type":"object"}`)

	// when
	steps, err := Steps(schema)

	// then
	require.NoError(t, err)
	assert.Equal(t, []any{}, steps)
}

func TestSteps_ShouldReturnArrayWithJSONNumbers(t *testing.T) {
	// given
	schema := []byte(`{"x-migrations":[` + step("2", `{"op":"wrap","path":"a"}`) + `]}`)

	// when
	steps, err := Steps(schema)

	// then
	require.NoError(t, err)
	list := steps.([]any)
	require.Len(t, list, 1)
	assert.IsType(t, parse(t, "2"), list[0].(map[string]any)["to"])
	_, _, err = Migrate(steps, keyA, obj(t, `{"a":1}`), 2)
	assert.NoError(t, err)
}

func TestSteps_ShouldReturnNullAndNonArrayRaw(t *testing.T) {
	// given
	null := []byte(`{"x-migrations":null}`)
	str := []byte(`{"x-migrations":"x"}`)

	// when
	gotNull, errNull := Steps(null)
	gotStr, errStr := Steps(str)

	// then
	require.NoError(t, errNull)
	require.NoError(t, errStr)
	assert.Nil(t, gotNull)
	assert.Equal(t, "x", gotStr)
}

func TestSteps_ShouldFailOnInvalidJSON(t *testing.T) {
	// when
	_, err := Steps([]byte(`{"x-migrations":`))

	// then
	assert.Error(t, err)
}

func TestMigrateEncoded_ShouldRoundTripAndKeepHTML(t *testing.T) {
	// given
	steps := parse(t, `[`+step("2", `{"op":"rename","from":"a","to":"b"}`)+`]`)

	// when
	up, _, err := MigrateEncoded(steps, keyA, `{"a":"<x>"}`, 2)
	require.NoError(t, err)
	down, _, err2 := MigrateEncoded(steps, keyA, up, 1)

	// then
	require.NoError(t, err2)
	assert.JSONEq(t, `{"v":2,"b":"<x>"}`, up)
	assert.Contains(t, up, "<x>")
	assert.JSONEq(t, `{"v":1,"a":"<x>"}`, down)
}

func TestMigrateEncoded_ShouldPassThroughNonObjects(t *testing.T) {
	// given
	for _, raw := range []string{"", "not json", "[1]", "5", `"s"`, `{"a":1} {"b":2}`} {
		// when
		out, lossy, err := MigrateEncoded(nil, keyA, raw, 2)

		// then
		require.NoError(t, err, raw)
		assert.Equal(t, raw, out)
		assert.False(t, lossy)
	}
}

func TestMigrateEncoded_ShouldReturnNonObjectBeforeCheckingTo(t *testing.T) {
	// when
	out, lossy, err := MigrateEncoded(nil, keyA, "not json", 0)

	// then
	require.NoError(t, err)
	assert.Equal(t, "not json", out)
	assert.False(t, lossy)
}

func TestMigrateEncoded_ShouldReturnRawWhenAlreadyAtTarget(t *testing.T) {
	// given
	raw := `{ "v": 2.0, "a": 1 }`

	// when
	out, lossy, err := MigrateEncoded(nil, keyA, raw, 2)

	// then
	require.NoError(t, err)
	assert.Equal(t, raw, out)
	assert.False(t, lossy)
}

func TestWriteBack_ShouldWriteIntegerVersionWhenOriginalHadFloatVersion(t *testing.T) {
	// given
	original := obj(t, `{"v":2.0,"a":1}`)

	// when
	out, wrote, err := WriteBack(nil, keyA, original, 2, obj(t, `{"v":2,"a":2}`))

	// then
	require.NoError(t, err)
	assert.True(t, wrote)
	enc, err := Encode(out)
	require.NoError(t, err)
	assert.JSONEq(t, `{"v":2,"a":2}`, enc)
	assert.Contains(t, enc, `"v":2`)
	assert.NotContains(t, enc, "2.0")
}

func TestWriteBack_ShouldNotWriteWhenOnlyFloatVersionDiffers(t *testing.T) {
	// given
	original := obj(t, `{"v":2.0,"a":1}`)

	// when
	_, wrote, err := WriteBack(nil, keyA, original, 2, obj(t, `{"v":2,"a":1}`))

	// then
	require.NoError(t, err)
	assert.False(t, wrote)
}

func TestWriteBackEncoded_ShouldReturnOriginalBytesWhenNothingChanges(t *testing.T) {
	// given
	original := `{ "v": 1,   "a": 1 }`

	// when
	out, wrote, err := WriteBackEncoded(nil, keyA, original, 1, obj(t, `{"v":1,"a":1}`))

	// then
	require.NoError(t, err)
	assert.False(t, wrote)
	assert.Equal(t, original, out)
}

func TestWriteBackEncoded_ShouldWriteChange(t *testing.T) {
	// when
	out, wrote, err := WriteBackEncoded(nil, keyA, `{"a":1}`, 1, obj(t, `{"a":2}`))

	// then
	require.NoError(t, err)
	assert.True(t, wrote)
	assert.JSONEq(t, `{"a":2}`, out)
}

func TestWriteBackEncoded_ShouldReturnReadOnlyForLossyEntry(t *testing.T) {
	// given
	steps := parse(t, `[`+step("2", `{"op":"wrap","path":"t"}`)+`]`)

	// when
	_, wrote, err := WriteBackEncoded(steps, keyA, `{"v":2,"t":["a"]}`, 1, obj(t, `{"t":"a"}`))

	// then
	assert.False(t, wrote)
	assert.ErrorIs(t, err, ErrReadOnly)
}

func TestWriteBackEncoded_ShouldFailPlainOnUndecodableOriginal(t *testing.T) {
	for _, raw := range []string{"", "nope", "[]"} {
		// when
		_, _, err := WriteBackEncoded(nil, keyA, raw, 1, map[string]any{})

		// then
		require.Error(t, err, raw)
		assert.False(t, isLens(err), raw)
	}
}

func TestWriteBack_ShouldFailPlainOnNonEntry(t *testing.T) {
	for _, orig := range []any{nil, "", 5, []any{}} {
		// when
		_, _, err := WriteBack(nil, keyA, orig, 1, map[string]any{})

		// then
		require.Error(t, err)
		assert.False(t, isLens(err))
	}
}

func TestMigrate_ShouldRejectBadArgumentsWithPlainError(t *testing.T) {
	for _, n := range []int{0, -1, 1 << 53} {
		// when
		_, _, mErr := Migrate(nil, keyA, map[string]any{}, n)
		_, _, wErr := WriteBack(nil, keyA, map[string]any{}, n, map[string]any{})
		_, _, meErr := MigrateEncoded(nil, keyA, `{}`, n)
		_, _, weErr := WriteBackEncoded(nil, keyA, `{}`, n, map[string]any{})

		// then
		for _, err := range []error{mErr, wErr, meErr, weErr} {
			require.Error(t, err, n)
			assert.False(t, isLens(err), n)
		}
	}
}

func TestMigrate_ShouldJudgeVersionByValue(t *testing.T) {
	// given
	steps := parse(t, `[`+step("2", `{"op":"rename","from":"a","to":"b"}`)+`]`)
	good := []string{`2.0`, `2e0`}
	bad := []string{`true`, `"2"`, `1.5`, `0`, `-1`, `9007199254740992`}

	for _, v := range good {
		// when
		out, _, err := Migrate(steps, keyA, obj(t, `{"v":`+v+`,"b":1}`), 1)

		// then
		require.NoError(t, err, v)
		assert.True(t, equal(out, obj(t, `{"v":1,"a":1}`)), v)
	}
	for _, v := range bad {
		// when
		out, _, err := Migrate(steps, keyA, obj(t, `{"v":`+v+`}`), 1)

		// then
		assert.ErrorIs(t, err, ErrBadVersion, v)
		assert.Nil(t, out)
	}
}

func TestMigrate_ShouldFindStepWithFloatTo(t *testing.T) {
	// given
	steps := parse(t, `[`+step("2.0", `{"op":"rename","from":"a","to":"b"}`)+`]`)

	// when
	out, _, err := Migrate(steps, keyA, obj(t, `{"a":1}`), 2)

	// then
	require.NoError(t, err)
	assert.True(t, equal(out, obj(t, `{"v":2,"b":1}`)))
}

func TestMigrate_ShouldBeUnsupportedForHugeToWithoutMatch(t *testing.T) {
	// given
	steps := parse(t, `[`+step("9007199254740992", `{"op":"wrap","path":"a"}`)+`]`)

	// when
	_, _, err := Migrate(steps, keyA, obj(t, `{}`), 2)

	// then
	assert.ErrorIs(t, err, ErrUnsupported)
}

func TestMigrate_ShouldBeMissingStepForNonPositiveTo(t *testing.T) {
	// given
	steps := parse(t, `[`+step("0", ``)+`,`+step("-3", ``)+`,`+step("1", ``)+`]`)

	// when
	_, _, err := Migrate(steps, keyA, obj(t, `{}`), 2)

	// then
	assert.ErrorIs(t, err, ErrMissingStep)
}

func TestMigrate_ShouldHandleNullStepsAsSpecified(t *testing.T) {
	// when
	_, _, errCrossed := Migrate(nil, keyA, obj(t, `{}`), 2)
	same, _, errSame := Migrate(nil, keyA, obj(t, `{"a":1}`), 1)

	// then
	assert.ErrorIs(t, errCrossed, ErrUnsupported)
	require.NoError(t, errSame)
	assert.True(t, equal(same, obj(t, `{"a":1}`)))
}

func TestMigrate_ShouldBeUnsupportedForBadCrossedStep(t *testing.T) {
	cases := map[string]string{
		"unknown member": `{"to":2,"breaking":false,"entries":{},"x":1}`,
		"to 2.5":         `{"to":2.5,"breaking":false,"entries":{}}`,
		"to string":      `{"to":"2","breaking":false,"entries":{}}`,
		"to bool":        `{"to":true,"breaking":false,"entries":{}}`,
	}
	for name, s := range cases {
		// given
		steps := parse(t, `[`+s+`]`)

		// when
		_, _, err := Migrate(steps, keyA, obj(t, `{}`), 2)

		// then
		assert.ErrorIs(t, err, ErrUnsupported, name)
	}
}

func TestMigrate_ShouldBeUnsupportedForVPathInMapWrapUnwrap(t *testing.T) {
	ops := []string{
		`{"op":"map","path":"v","pairs":[]}`,
		`{"op":"wrap","path":"v.x"}`,
		`{"op":"unwrap","path":"v"}`,
	}
	for _, o := range ops {
		// given
		steps := parse(t, `[`+step("2", o)+`]`)

		// when
		_, _, err := Migrate(steps, keyA, obj(t, `{}`), 2)

		// then
		assert.ErrorIs(t, err, ErrUnsupported, o)
	}
}

func TestMigrate_ShouldReportBreakingBeforeEarlierUnsupportedStep(t *testing.T) {
	// given
	steps := parse(t, `[{"to":2,"breaking":false,"entries":{},"x":1},{"to":3,"breaking":true,"entries":{}}]`)

	// when
	_, _, err := Migrate(steps, keyA, obj(t, `{"v":3}`), 1)

	// then
	assert.ErrorIs(t, err, ErrBreaking)
}

func TestMigrate_ShouldNotMutateInput(t *testing.T) {
	// given
	steps := parse(t, `[`+step("2", `{"op":"move","from":"a","to":"b.c"},{"op":"add","path":"d","default":{"k":1}}`)+`]`)
	in := obj(t, `{"a":[1],"x":{"y":2}}`)
	before := obj(t, `{"a":[1],"x":{"y":2}}`)

	// when
	out, _, err := Migrate(steps, keyA, in, 2)
	require.NoError(t, err)
	out.(map[string]any)["x"].(map[string]any)["y"] = "changed"

	// then
	assert.Equal(t, before, in)
}

func TestMigrate_ShouldNotApplyMapFallbackToAbsentFieldDown(t *testing.T) {
	// given
	steps := parse(t, `[`+step("2", `{"op":"map","path":"p","pairs":[["a","b"]],"fallback":"a"}`)+`]`)

	// when
	out, lossy, err := Migrate(steps, keyA, obj(t, `{"v":2}`), 1)

	// then
	require.NoError(t, err)
	assert.True(t, equal(out, obj(t, `{"v":1}`)))
	assert.True(t, lossy)
}

func TestWriteBack_ShouldNotReplaceNonObjectParentWhenOnlyDeleting(t *testing.T) {
	// given
	steps := parse(t, `[`+step("2", `{"op":"add","path":"meta","default":{"k":1}}`)+`]`)
	original := obj(t, `{"v":2,"meta":5}`)

	// when
	out, wrote, err := WriteBack(steps, keyA, original, 1, obj(t, `{"v":1,"meta":{}}`))

	// then
	require.NoError(t, err)
	assert.False(t, wrote)
	assert.True(t, equal(out, original))
}

func TestWriteBack_ShouldReplaceNonObjectParentWhenSettingChild(t *testing.T) {
	// given
	original := obj(t, `{"v":1,"meta":5}`)
	view := obj(t, `{"v":1,"meta":5}`)
	edited := view
	edited["meta"] = map[string]any{"k": parse(t, "1")}

	// when
	out, wrote, err := WriteBack(nil, keyA, original, 1, edited)

	// then
	require.NoError(t, err)
	assert.True(t, wrote)
	assert.True(t, equal(out, obj(t, `{"v":1,"meta":{"k":1}}`)))
}

func TestWriteBack_ShouldKeepEmptiedParentOnDelete(t *testing.T) {
	// given
	original := obj(t, `{"v":1,"m":{"k":1}}`)

	// when
	out, wrote, err := WriteBack(nil, keyA, original, 1, obj(t, `{"v":1,"m":{}}`))

	// then
	require.NoError(t, err)
	assert.True(t, wrote)
	assert.True(t, equal(out, obj(t, `{"v":1,"m":{}}`)))
}

func TestWriteBack_ShouldUpgradeOlderEntryAndIgnoreEditedV(t *testing.T) {
	// given
	steps := parse(t, `[`+step("2", `{"op":"rename","from":"a","to":"b"}`)+`]`)

	// when
	out, wrote, err := WriteBack(steps, keyA, obj(t, `{"a":1}`), 2, obj(t, `{"v":9,"b":2}`))

	// then
	require.NoError(t, err)
	assert.True(t, wrote)
	assert.True(t, equal(out, obj(t, `{"v":2,"b":2}`)))
}

func TestWriteBack_ShouldReturnMigrateErrorBeforeReadOnly(t *testing.T) {
	// given
	steps := parse(t, `[`+step("2", `{"op":"wrap","path":"t"}`)+`]`)

	// when
	_, _, err := WriteBack(steps, keyA, obj(t, `{"v":true}`), 1, map[string]any{})
	_, _, err2 := WriteBack(steps, keyA, obj(t, `{"v":3}`), 1, map[string]any{})

	// then
	assert.ErrorIs(t, err, ErrBadVersion)
	assert.ErrorIs(t, err2, ErrMissingStep)
}

func TestComponentState_ShouldTakeWorstStateAndSkipNonEntries(t *testing.T) {
	// given
	steps := parse(t, `[`+step("2", `{"op":"wrap","path":"t"}`)+`]`)
	lossy := Entry{Key: keyA, Value: obj(t, `{"v":2}`)}
	skipped := []Entry{{Key: keyA, Value: ""}, {Key: keyA, Value: nil}, {Key: keyA, Value: 5}, {Key: keyA, Value: obj(t, `{"v":true}`)}}
	broken := Entry{Key: keyA, Value: obj(t, `{"v":3}`)}
	state := func(entries []Entry) State {
		s, err := ComponentState(steps, 1, entries)
		require.NoError(t, err)
		return s
	}

	// then
	assert.Equal(t, StateFull, state(nil))
	assert.Equal(t, StateFull, state(skipped))
	assert.Equal(t, StateReadOnly, state(append(skipped, lossy)))
	assert.Equal(t, StateNeedsUpdate, state([]Entry{lossy, broken}))
	assert.Equal(t, "needs-update", StateNeedsUpdate.String())
}

func TestComponentState_ShouldRejectBadReaderWithPlainError(t *testing.T) {
	for _, n := range []int{0, -1, 1 << 53} {
		// when
		_, err := ComponentState(nil, n, nil)

		// then
		require.Error(t, err, n)
		assert.False(t, isLens(err), n)
	}
}

func TestMigrate_ShouldReportUnsupportedBeforeBreaking(t *testing.T) {
	// given
	invalid := parse(t, `[{"to":2,"breaking":true,"entries":{"^item_.+$":[{"op":"nope"}]}}]`)
	valid := parse(t, `[{"to":2,"breaking":true,"entries":{"^item_.+$":[{"op":"wrap","path":"a"}]}}]`)

	// when
	_, _, errInvalid := Migrate(invalid, keyA, obj(t, `{"v":2}`), 1)
	_, _, errValid := Migrate(valid, keyA, obj(t, `{"v":2}`), 1)

	// then
	assert.ErrorIs(t, errInvalid, ErrUnsupported)
	assert.ErrorIs(t, errValid, ErrBreaking)
}

func TestNumbers_ShouldStayFastWithHugeExponents(t *testing.T) {
	// given
	var b strings.Builder
	b.WriteString(`{"f":1e999999`)
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&b, `,"f%d":1e999999`, i)
	}
	b.WriteString(`}`)
	entry := obj(t, b.String())
	start := time.Now()

	// when
	_, _, mErr := Migrate(nil, keyA, entry, 1)
	_, wrote, wErr := WriteBack(nil, keyA, entry, 1, cloneMap(entry))
	same := equal(entry, cloneMap(entry))

	// then
	require.NoError(t, mErr)
	require.NoError(t, wErr)
	assert.False(t, wrote)
	assert.True(t, same)
	assert.Less(t, time.Since(start), 2*time.Second)
}

func TestNumbers_ShouldTreatHugeExponentAsOutOfRange(t *testing.T) {
	// given
	steps := parse(t, `[`+step("1e999999", ``)+`]`)

	// when
	_, _, vErr := Migrate(nil, keyA, obj(t, `{"v":1e999999}`), 1)
	_, _, sErr := Migrate(steps, keyA, obj(t, `{}`), 2)

	// then
	assert.ErrorIs(t, vErr, ErrBadVersion)
	assert.ErrorIs(t, sErr, ErrUnsupported)
	assert.True(t, equal(parse(t, `1e999999`), parse(t, `1e999999`)))
	assert.False(t, equal(parse(t, `1e999999`), parse(t, `2e999999`)))
	assert.False(t, equal(parse(t, `1e999999`), parse(t, `1`)))
}

func TestNumbers_ShouldKeepNormalNumbersEqualByValue(t *testing.T) {
	// then
	assert.True(t, equal(parse(t, `2.0`), parse(t, `2e0`)))
	assert.True(t, equal(parse(t, `1e3`), parse(t, `1000`)))
	assert.True(t, equal(parse(t, `0.5`), parse(t, `5e-1`)))
	assert.False(t, equal(parse(t, `1`), parse(t, `1.5`)))
}

func TestDecodeEncoded_ShouldReturnRawStringUnlessObject(t *testing.T) {
	// then
	assert.Equal(t, map[string]any{"a": parse(t, "1")}, DecodeEncoded(`{"a":1}`))
	assert.Equal(t, "", DecodeEncoded(""))
	assert.Equal(t, "[1]", DecodeEncoded("[1]"))
	assert.Equal(t, `{"a":1}x`, DecodeEncoded(`{"a":1}x`))
}
