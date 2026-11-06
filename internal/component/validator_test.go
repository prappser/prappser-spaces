package component

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const commonSchemaID = "https://prappser.app/schemas/component/common.v1.schema.json"

type vectorFile struct {
	Schema string `json:"schema"`
	Cases  []struct {
		Name   string `json:"name"`
		Schema string `json:"schema"`
		Data   any    `json:"data"`
		Valid  *bool  `json:"valid"`
	} `json:"cases"`
}

func loadVectors(t *testing.T) map[string]vectorFile {
	t.Helper()
	files, err := filepath.Glob("schemas/vectors/*.json")
	require.NoError(t, err)
	require.NotEmpty(t, files)
	out := map[string]vectorFile{}
	for _, f := range files {
		fh, err := os.Open(f)
		require.NoError(t, err)
		dec := json.NewDecoder(fh)
		dec.DisallowUnknownFields()
		var vf vectorFile
		require.NoError(t, dec.Decode(&vf), f)
		require.NoError(t, fh.Close())
		require.NotEmpty(t, vf.Cases, f)
		for _, c := range vf.Cases {
			require.NotNil(t, c.Valid, "%s: %s", f, c.Name)
		}
		out[filepath.Base(f)] = vf
	}
	return out
}

func vectorData(t *testing.T, file, name string) map[string]any {
	t.Helper()
	for _, c := range loadVectors(t)[file].Cases {
		if c.Name == name {
			data, ok := c.Data.(map[string]any)
			require.True(t, ok, "vector %s/%s is not an object", file, name)
			return data
		}
	}
	require.FailNow(t, "vector not found", "%s/%s", file, name)
	return nil
}

func TestSchemaCopy_ShouldMatchManifest(t *testing.T) {
	// given
	hint := "run scripts/sync-schemas.sh"
	manifest := map[string]string{}
	f, err := os.Open("schemas.sha256")
	require.NoError(t, err)
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "# ") {
			continue
		}
		sum, name, ok := strings.Cut(sc.Text(), "  ")
		require.True(t, ok, "malformed manifest line %q; %s", sc.Text(), hint)
		manifest[name] = sum
	}
	require.NoError(t, sc.Err())

	// when
	actual := map[string]string{}
	err = filepath.WalkDir("schemas", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		rel, _ := filepath.Rel("schemas", p)
		actual[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	})
	require.NoError(t, err)

	// then
	assert.Equal(t, manifest, actual, "schema copy differs from schemas.sha256; %s", hint)
}

func TestVectors_ShouldMatchExpectedValidity(t *testing.T) {
	// given
	v, err := NewValidator()
	require.NoError(t, err)
	vectors := loadVectors(t)
	total := 0

	for name := range v.components {
		assert.Contains(t, vectors, strings.ToLower(name)+".json")
	}
	assert.Contains(t, vectors, "template-doc.json")

	for file, vf := range vectors {
		name := strings.TrimSuffix(file, ".json")
		wantID := templateSchema
		if file != "template-doc.json" {
			name = strings.ToUpper(name[:1]) + name[1:]
			wantID = v.componentIDs[name]
		}
		assert.Equal(t, wantID, vf.Schema, file)
		for _, c := range vf.Cases {
			// when
			var err error
			data, isObject := c.Data.(map[string]any)
			switch {
			case c.Schema == "" && isObject && file == "template-doc.json":
				err = v.ValidateTemplateDoc(data)
			case c.Schema == "" && isObject:
				err = v.ValidateComponentData(name, data)
			default:
				loc := vf.Schema
				if c.Schema != "" {
					loc = c.Schema
				}
				sch, cerr := v.compiler.Compile(loc)
				require.NoError(t, cerr, "%s: %s", file, c.Name)
				err = sch.Validate(c.Data)
			}

			// then
			assert.Equal(t, *c.Valid, err == nil, "%s: %s: %v", file, c.Name, err)
			total++
		}
	}
	assert.Positive(t, total)
}

func TestVectors_ShouldCoverEverySchema(t *testing.T) {
	// given
	v, err := NewValidator()
	require.NoError(t, err)
	used := map[string]bool{}
	for _, vf := range loadVectors(t) {
		used[strings.SplitN(vf.Schema, "#", 2)[0]] = true
		for _, c := range vf.Cases {
			if c.Schema != "" {
				used[strings.SplitN(c.Schema, "#", 2)[0]] = true
			}
		}
	}
	onDisk := map[string]bool{}
	files, err := filepath.Glob("schemas/*/*.schema.json")
	require.NoError(t, err)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		require.NoError(t, err)
		var doc struct {
			ID string `json:"$id"`
		}
		require.NoError(t, json.Unmarshal(raw, &doc), f)
		if doc.ID != commonSchemaID {
			onDisk[doc.ID] = true
		}
	}

	// when
	loaded := map[string]bool{templateSchema: true}
	for name, id := range v.componentIDs {
		lo, cur, _ := v.Versions(name)
		for n := lo; n <= cur; n++ {
			suffix := fmt.Sprintf(".v%d.schema.json", cur)
			require.True(t, strings.HasSuffix(id, suffix), "%s: id %s must end in %s", name, id, suffix)
			loaded[strings.TrimSuffix(id, suffix)+fmt.Sprintf(".v%d.schema.json", n)] = true
		}
	}

	// then
	assert.Equal(t, onDisk, loaded)
	assert.Equal(t, onDisk, used)
}

func TestValidateComponentData_ShouldRejectUnknownType(t *testing.T) {
	// given
	v, err := NewValidator()
	require.NoError(t, err)

	// when
	errCommon := v.ValidateComponentData("Common", map[string]any{})
	errNope := v.ValidateComponentData("Nope", map[string]any{})
	errLower := v.ValidateComponentData("checklist", map[string]any{})
	errUpper := v.ValidateComponentData("CHECKLIST", map[string]any{})
	errLowerCommon := v.ValidateComponentData("common", map[string]any{})

	// then
	assert.ErrorIs(t, errCommon, ErrUnknownComponentType)
	assert.ErrorIs(t, errNope, ErrUnknownComponentType)
	assert.ErrorIs(t, errLower, ErrUnknownComponentType)
	assert.ErrorIs(t, errUpper, ErrUnknownComponentType)
	assert.ErrorIs(t, errLowerCommon, ErrUnknownComponentType)
}

func TestValidateComponentData_ShouldAcceptValidData(t *testing.T) {
	// given
	v, err := NewValidator()
	require.NoError(t, err)

	// when
	err = v.ValidateComponentData("Checklist", vectorData(t, "checklist.json", "minimal item"))

	// then
	assert.NoError(t, err)
}

func TestValidateComponentData_ShouldRejectInvalidData(t *testing.T) {
	// given
	v, err := NewValidator()
	require.NoError(t, err)

	// when
	err = v.ValidateComponentData("Checklist", map[string]any{"items": []any{}, "bogus": float64(1)})

	// then
	assert.ErrorIs(t, err, ErrInvalidData)
}

func TestValidateTemplateDoc_ShouldAcceptValidDoc(t *testing.T) {
	// given
	v, err := NewValidator()
	require.NoError(t, err)

	// when
	err = v.ValidateTemplateDoc(vectorData(t, "template-doc.json", "minimal"))

	// then
	assert.NoError(t, err)
}

func TestValidateTemplateDoc_ShouldRejectInvalidDoc(t *testing.T) {
	// given
	v, err := NewValidator()
	require.NoError(t, err)

	// when
	err = v.ValidateTemplateDoc(map[string]any{"name": float64(1)})

	// then
	assert.ErrorIs(t, err, ErrInvalidData)
}

func TestMergeMode_ShouldResolveKeys(t *testing.T) {
	// given
	v, err := NewValidator()
	require.NoError(t, err)
	id := "01234567-89ab-7def-8123-456789abcdef"

	// when
	entry, entryOK := v.MergeMode("Chat", "m_"+id)
	member, memberOK := v.MergeMode("Chat", "react_m_"+id+"_pk-bob")
	single, singleOK := v.MergeMode("Chat", "_title")
	_, unknownKeyOK := v.MergeMode("Chat", "nope")
	_, unknownTypeOK := v.MergeMode("Nope", "m_"+id)
	poll, pollOK := v.MergeMode("Poll", "vote_pk-alice")
	_, lowerTypeOK := v.MergeMode("chat", "_title")
	_, commonOK := v.MergeMode("Common", "_title")
	item, itemOK := v.MergeMode("Checklist", "item_i1")
	legacy, legacyOK := v.MergeMode("Checklist", "items")

	// then
	assert.True(t, entryOK)
	assert.Equal(t, "per-entry", entry)
	assert.True(t, memberOK)
	assert.Equal(t, "per-member", member)
	assert.True(t, singleOK)
	assert.Equal(t, "single", single)
	assert.False(t, unknownKeyOK)
	assert.False(t, unknownTypeOK)
	assert.True(t, pollOK)
	assert.Equal(t, "per-member", poll)
	assert.False(t, lowerTypeOK)
	assert.False(t, commonOK)
	assert.True(t, itemOK)
	assert.Equal(t, "per-entry", item)
	assert.True(t, legacyOK)
	assert.Equal(t, "single", legacy)
}

func TestValidateComponentData_ShouldReportFieldErrors(t *testing.T) {
	// given
	v, err := NewValidator()
	require.NoError(t, err)
	data := map[string]any{
		"item_a": map[string]any{"title": "t"},
		"bogus":  float64(1),
	}

	// when
	err = v.ValidateComponentData("Checklist", data)

	// then
	var verrs ValidationErrors
	require.True(t, errors.As(err, &verrs))
	assert.ErrorIs(t, err, ErrInvalidData)
	byPath := map[string]string{}
	for _, f := range verrs {
		byPath[f.Path] += f.Message + "; "
	}
	assert.Contains(t, byPath["/item_a"], "checked")
	assert.Contains(t, byPath[""], "bogus")
}

func TestNewValidator_ShouldRejectExternalRef(t *testing.T) {
	// given
	fsys := fstest.MapFS{
		"schemas/bundle.json": {Data: []byte(`{"types":{}}`)},
		"schemas/template/template-doc.v1.schema.json": {Data: []byte(
			`{"$id":"` + templateSchema + `","$ref":"file:///etc/passwd"}`)},
	}

	// when
	_, err := NewValidatorFS(fsys)

	// then
	assert.ErrorContains(t, err, "not allowed")
}

const msgID = "01234567-89ab-7def-8123-456789abcdef"

func TestAccess_ShouldResolveRulesFromSchema(t *testing.T) {
	// given
	v, err := NewValidator()
	require.NoError(t, err)

	// when
	msg, msgOK := v.Access("Chat", "m_"+msgID)
	react, _ := v.Access("Chat", "react_m_"+msgID+"_pk")
	item, _ := v.Access("Checklist", "item_x")
	what, _ := v.Access("Countdown", "what")
	question, _ := v.Access("Poll", "question")
	items, _ := v.Access("Checklist", "items")
	_, unknownKey := v.Access("Chat", "nope")
	_, unknownType := v.Access("Nope", "m_"+msgID)

	// then
	assert.True(t, msgOK)
	assert.True(t, msg.Append)
	assert.Equal(t, "sender", msg.Author)
	assert.Equal(t, "message", msg.Content)
	assert.Equal(t, AccessMember, react.Level)
	assert.False(t, react.OwnKey("react_m_"+msgID+"_other", "pk"))
	require.NotNil(t, item.Gate)
	assert.Equal(t, Flag{Name: "allowAddInUsage", Default: true}, *item.Gate)
	assert.Equal(t, &Flag{Name: "allowToggleInUsage", Default: true}, item.Fields["checked"])
	assert.Contains(t, item.Fields, "detailsDocument")
	assert.Nil(t, item.Fields["detailsDocument"])
	assert.Contains(t, item.Fields, "order")
	assert.Nil(t, item.Fields["order"])
	assert.Equal(t, &Flag{Name: "runEditable", Default: false}, what.Gate)
	assert.Equal(t, AccessManage, question.Level)
	assert.Equal(t, AccessNone, items.Level)
	assert.False(t, unknownKey)
	assert.False(t, unknownType)
}

func TestOwnKey_ShouldMatchOnlyTheCallersCell(t *testing.T) {
	// given
	v, err := NewValidator()
	require.NoError(t, err)
	pk := "a+b/c="
	vote, _ := v.Access("Poll", "vote_x")
	react, _ := v.Access("Chat", "react_m_"+msgID+"_x")
	question, _ := v.Access("Poll", "question")

	// then
	assert.True(t, vote.OwnKey("vote_"+pk, pk))
	assert.False(t, vote.OwnKey("vote_other", pk))
	assert.False(t, vote.OwnKey("vote_X_"+pk, pk))
	assert.False(t, vote.OwnKey("vote_aab/c=", pk))
	assert.True(t, react.OwnKey("react_m_"+msgID+"_"+pk, pk))
	assert.True(t, question.OwnKey("question", pk))
}

func accessFixture(component string) error {
	fsys := fstest.MapFS{
		"schemas/template/template-doc.v1.schema.json": {Data: []byte(`{"$id":"` + templateSchema + `"}`)},
		"schemas/component/x.v1.schema.json":           {Data: []byte(component)},
	}
	_, err := NewValidatorFS(fsys)
	return err
}

func TestNewValidator_ShouldRejectBadAccess(t *testing.T) {
	flag := `"on":{"type":"boolean","default":true,"x-access":"manage"}`
	cases := map[string][2]string{
		"missing x-access":       {`"a":{}`, "missing x-access"},
		"invalid x-access":       {`"a":{"x-access":"everyone"}`, "invalid x-access"},
		"unknown object key":     {`"a":{"x-access":{"bogus":1}}`, "unknown x-access key"},
		"gate without default":   {`"a":{"x-access":{"gate":"b"}},"b":{"x-access":"manage"}`, "has no boolean default"},
		"unless without default": {`"a":{"x-access":{"unless":"b"}},"b":{"x-access":"manage"}`, "has no boolean default"},
		"unknown content def":    {`"a":{"x-access":{"content":"nope"}}`, "is not in $defs"},
		"wrong gate type":        {`"a":{"x-access":{"gate":1}}`, "gate must be a string"},
	}
	for name, c := range cases {
		// when
		err := accessFixture(`{"$id":"https://x/x.json","properties":{` + c[0] + `,` + flag + `}}`)

		// then
		assert.ErrorContains(t, err, c[1], name)
	}
}

func TestAccess_ShouldResolveUnless(t *testing.T) {
	// given
	fsys := fstest.MapFS{
		"schemas/template/template-doc.v1.schema.json": {Data: []byte(`{"$id":"` + templateSchema + `"}`)},
		"schemas/bundle.json":                          {Data: []byte(`{"types":{"X":{"min":1,"current":1}}}`)},
		"schemas/component/x.v1.schema.json": {Data: []byte(`{"$id":"https://x/x.json","properties":{
			"closed":{"type":"boolean","default":false,"x-access":"manage"}},
			"patternProperties":{"^v_.+$":{"x-access":{"unless":"closed"}}}}`)},
	}
	v, err := NewValidatorFS(fsys)
	require.NoError(t, err)

	// when
	acc, ok := v.Access("X", "v_a")

	// then
	require.True(t, ok)
	assert.Equal(t, AccessMember, acc.Level)
	assert.Equal(t, &Flag{Name: "closed", Default: false}, acc.Unless)
}

func TestNewValidator_ShouldRejectPerMemberPatternWithoutSuffix(t *testing.T) {
	// when
	err := accessFixture(`{"$id":"https://x/x.json","patternProperties":{"^v_.*$":{"x-merge":"per-member","x-access":"member"}}}`)

	// then
	assert.ErrorContains(t, err, "must end in .+$")
}

func TestValidateComponentKeys_ShouldIgnoreRootRequiredOnly(t *testing.T) {
	// given
	v, err := NewValidator()
	require.NoError(t, err)

	// when
	full := v.ValidateComponentData("Poll", map[string]any{"vote_pk": "a"})
	partial := v.ValidateComponentKeys("Poll", map[string]any{"vote_pk": "a"})
	badValue := v.ValidateComponentKeys("Poll", map[string]any{"vote_pk": float64(1)})
	unknown := v.ValidateComponentKeys("Poll", map[string]any{"nope": "a"})

	// then
	assert.Error(t, full)
	assert.NoError(t, partial)
	var ve ValidationErrors
	require.True(t, errors.As(badValue, &ve))
	assert.Equal(t, "/vote_pk", ve[0].Path)
	assert.Error(t, unknown)
}

func TestValidateContent_ShouldCheckDecodedValue(t *testing.T) {
	// given
	v, err := NewValidator()
	require.NoError(t, err)

	// when
	ok := v.ValidateContent("Chat", "message", `{"v":1,"sender":"pk","ts":1700000000000,"body":"hi"}`)
	noBody := v.ValidateContent("Chat", "message", `{"v":1,"sender":"pk","ts":1700000000000}`)
	notJSON := v.ValidateContent("Chat", "message", `not json`)

	// then
	assert.NoError(t, ok)
	var ve ValidationErrors
	assert.True(t, errors.As(noBody, &ve))
	require.True(t, errors.As(notJSON, &ve))
	assert.Equal(t, "not valid JSON", ve[0].Message)
}

func TestTypesAndSchema_ShouldExposeEmbeddedSchemas(t *testing.T) {
	// given
	v, err := NewValidator()
	require.NoError(t, err)

	// when
	types := v.Types()
	chat, chatOK := v.Schema("Chat")
	_, nopeOK := v.Schema("Nope")

	// then
	names := make([]string, len(types))
	for i, ti := range types {
		names[i] = ti.Type
		assert.NotEmpty(t, ti.Description, ti.Type)
	}
	assert.True(t, sort.StringsAreSorted(names))
	assert.Contains(t, names, "Chat")
	assert.NotContains(t, names, "Common")
	assert.True(t, chatOK)
	assert.Contains(t, string(chat), "x-access")
	assert.False(t, nopeOK)
}

func TestNewValidator_ShouldRejectPerMemberOnExactProperty(t *testing.T) {
	// when
	err := accessFixture(`{"$id":"https://x/x.json","properties":{"a":{"x-merge":"per-member","x-access":"member"}}}`)

	// then
	assert.ErrorContains(t, err, "per-member property")
}

func versionFixtureFS(files map[string]string) fstest.MapFS {
	fsys := fstest.MapFS{
		"schemas/template/template-doc.v1.schema.json": {Data: []byte(`{"$id":"` + templateSchema + `"}`)},
	}
	for name, data := range files {
		fsys["schemas/"+name] = &fstest.MapFile{Data: []byte(data)}
	}
	return fsys
}

const (
	xV1 = `{"$id":"https://x/x.v1.json","description":"one","properties":{"a":{"type":"string","x-merge":"single","x-access":"member"}}}`
	xV2 = `{"$id":"https://x/x.v2.json","description":"two","x-migrations":[{"to":2}],"additionalProperties":false,"properties":{"b":{"type":"string","x-merge":"single","x-access":"manage"}}}`
)

func bundleCurrent2Fixture(t *testing.T) *Validator {
	t.Helper()
	v, err := NewValidatorFS(versionFixtureFS(map[string]string{
		"component/x.v1.schema.json": xV1,
		"component/x.v2.schema.json": xV2,
		"bundle.json":                `{"bundle":1,"types":{"X":{"min":1,"current":2}}}`,
	}))
	require.NoError(t, err)
	return v
}

func TestNewValidator_ShouldUseBundleCurrentForValidation(t *testing.T) {
	// given
	v := bundleCurrent2Fixture(t)

	// when
	raw, _ := v.Schema("X")
	_, aOK := v.Access("X", "a")
	b, bOK := v.Access("X", "b")
	_, mergeOK := v.MergeMode("X", "b")

	// then
	assert.Contains(t, string(raw), "x.v2.json")
	assert.False(t, aOK)
	assert.True(t, bOK)
	assert.Equal(t, AccessManage, b.Level)
	assert.True(t, mergeOK)
	assert.NoError(t, v.ValidateComponentData("X", map[string]any{"b": "s"}))
	assert.Error(t, v.ValidateComponentData("X", map[string]any{"a": "s"}))
}

func TestVersions_ShouldReportBundleRange(t *testing.T) {
	// given
	v := bundleCurrent2Fixture(t)

	// when
	lo, cur, ok := v.Versions("X")

	// then
	assert.True(t, ok)
	assert.Equal(t, 1, lo)
	assert.Equal(t, 2, cur)
}

func TestSteps_ShouldReadCurrentFileMigrations(t *testing.T) {
	// given
	v := bundleCurrent2Fixture(t)

	// when
	steps := v.Steps("X")

	// then
	assert.Equal(t, []any{map[string]any{"to": json.Number("2")}}, steps)
}

func TestNewValidator_ShouldRejectMissingBundle(t *testing.T) {
	// given
	fsys := versionFixtureFS(map[string]string{"component/x.v1.schema.json": xV1})

	// when
	_, err := NewValidatorFS(fsys)

	// then
	assert.ErrorContains(t, err, "schemas/bundle.json is missing")
}

func TestNewValidator_ShouldRejectTypeNotInBundle(t *testing.T) {
	// given
	fsys := versionFixtureFS(map[string]string{
		"component/x.v1.schema.json": xV1,
		"component/y.v1.schema.json": `{"$id":"https://x/y.v1.json"}`,
		"bundle.json":                `{"types":{"X":{"min":1,"current":1}}}`,
	})

	// when
	_, err := NewValidatorFS(fsys)

	// then
	assert.ErrorContains(t, err, "Y has schema files but is not listed")
}

func TestNewValidator_ShouldRejectFileAboveBundleCurrent(t *testing.T) {
	// given
	fsys := versionFixtureFS(map[string]string{
		"component/x.v1.schema.json": xV1,
		"component/x.v2.schema.json": xV2,
		"bundle.json":                `{"types":{"X":{"min":1,"current":1}}}`,
	})

	// when
	_, err := NewValidatorFS(fsys)

	// then
	assert.ErrorContains(t, err, "x.v2.schema.json is above current version 1 of X")
}

func TestNewValidator_ShouldReportLowestFileAboveBundleCurrent(t *testing.T) {
	// given
	fsys := versionFixtureFS(map[string]string{
		"component/x.v1.schema.json": xV1,
		"component/x.v2.schema.json": xV2,
		"component/x.v3.schema.json": strings.ReplaceAll(xV2, "x.v2", "x.v3"),
		"component/x.v4.schema.json": strings.ReplaceAll(xV2, "x.v2", "x.v4"),
		"bundle.json":                `{"types":{"X":{"min":1,"current":2}}}`,
	})

	// when
	_, err := NewValidatorFS(fsys)

	// then
	assert.ErrorContains(t, err, "x.v3.schema.json is above current version 2 of X")
}

func TestNewValidator_ShouldRejectBundleCurrentWithoutFile(t *testing.T) {
	// given
	fsys := versionFixtureFS(map[string]string{
		"component/x.v1.schema.json": xV1,
		"bundle.json":                `{"bundle":1,"types":{"X":{"min":1,"current":2}}}`,
	})

	// when
	_, err := NewValidatorFS(fsys)

	// then
	assert.ErrorContains(t, err, "version 2 of X has no schema file")
}

func TestNewValidator_ShouldRejectMalformedSchemaFileName(t *testing.T) {
	for _, name := range []string{"x.schema.json", "x.v0.schema.json", "X.v1.schema.json", "x.v01.schema.json", "x.v99999999999999999999.schema.json"} {
		// given
		fsys := versionFixtureFS(map[string]string{"component/" + name: xV1})

		// when
		_, err := NewValidatorFS(fsys)

		// then
		assert.ErrorContains(t, err, "invalid schema file name", name)
	}
}

func TestSteps_ShouldComeFromCurrentFile(t *testing.T) {
	// given
	fsys := versionFixtureFS(map[string]string{
		"component/x.v1.schema.json": xV1,
		"component/x.v2.schema.json": xV2,
		"component/y.v1.schema.json": `{"$id":"https://x/y.v1.json","x-migrations":[{"to":9}]}`,
		"component/y.v2.schema.json": `{"$id":"https://x/y.v2.json"}`,
		"bundle.json":                `{"types":{"X":{"min":1,"current":2},"Y":{"min":1,"current":2}}}`,
	})
	v, err := NewValidatorFS(fsys)
	require.NoError(t, err)

	// when
	x := v.Steps("X")
	y := v.Steps("Y")

	// then
	assert.Len(t, x, 1)
	assert.Equal(t, []any{}, y)
}

func TestEntry_ShouldReportPerEntryFamilyAndEncoding(t *testing.T) {
	// given
	v, err := NewValidator()
	require.NoError(t, err)
	id := msgID

	// when
	chatEnc, chatOK := v.Entry("Chat", "m_"+id)
	expEnc, expOK := v.Entry("Expenses", "e_"+id)
	setEnc, setOK := v.Entry("Expenses", "s_"+id)
	itemEnc, itemOK := v.Entry("Checklist", "item_i1")
	_, voteOK := v.Entry("Poll", "vote_pk")
	_, itemsOK := v.Entry("Checklist", "items")
	_, titleOK := v.Entry("Chat", "_title")
	_, unknownOK := v.Entry("Chat", "nope")

	// then
	assert.True(t, chatOK)
	assert.True(t, chatEnc)
	assert.True(t, expOK)
	assert.True(t, expEnc)
	assert.True(t, setOK)
	assert.True(t, setEnc)
	assert.True(t, itemOK)
	assert.False(t, itemEnc)
	assert.False(t, voteOK)
	assert.False(t, itemsOK)
	assert.False(t, titleOK)
	assert.False(t, unknownOK)
}

func TestVersions_ShouldReadEmbeddedBundle(t *testing.T) {
	// given
	v, err := NewValidator()
	require.NoError(t, err)

	// when
	types := v.Types()
	raw, err := os.ReadFile("schemas/bundle.json")
	require.NoError(t, err)
	var bundle struct {
		Types map[string]struct{ Min, Current int } `json:"types"`
	}
	require.NoError(t, json.Unmarshal(raw, &bundle))

	// then
	require.NotEmpty(t, types)
	for _, ti := range types {
		lo, cur, ok := v.Versions(ti.Type)
		assert.True(t, ok, ti.Type)
		assert.Equal(t, bundle.Types[ti.Type].Min, lo, ti.Type)
		assert.Equal(t, bundle.Types[ti.Type].Current, cur, ti.Type)
	}
	lo, cur, ok := v.Versions("Checklist")
	assert.True(t, ok)
	assert.Equal(t, 1, lo)
	assert.Equal(t, 2, cur)
	_, _, ok = v.Versions("Nope")
	assert.False(t, ok)
}

func TestNewValidator_ShouldRejectInvalidBundleRanges(t *testing.T) {
	cases := map[string]struct {
		files map[string]string
		want  string
	}{
		"min zero": {map[string]string{
			"component/x.v1.schema.json": xV1,
			"bundle.json":                `{"types":{"X":{"min":0,"current":1}}}`,
		}, "invalid version range 0..1 of X"},
		"min above current": {map[string]string{
			"component/x.v1.schema.json": xV1,
			"component/x.v2.schema.json": xV2,
			"bundle.json":                `{"types":{"X":{"min":2,"current":1}}}`,
		}, "invalid version range 2..1 of X"},
		"gap in range": {map[string]string{
			"component/x.v1.schema.json": xV1,
			"component/x.v3.schema.json": `{"$id":"https://x/x.v3.json"}`,
			"bundle.json":                `{"types":{"X":{"min":1,"current":3}}}`,
		}, "version 2 of X has no schema file"},
		"type without file": {map[string]string{
			"component/x.v1.schema.json": xV1,
			"bundle.json":                `{"types":{"Y":{"min":1,"current":1}}}`,
		}, "bundle lists Y but it has no schema file"},
	}
	for name, c := range cases {
		// when
		_, err := NewValidatorFS(versionFixtureFS(c.files))

		// then
		assert.ErrorContains(t, err, c.want, name)
	}
}
