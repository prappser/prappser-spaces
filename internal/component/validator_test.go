package component

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	for _, id := range v.componentIDs {
		loaded[id] = true
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
		"schemas/template/template-doc.v1.schema.json": {Data: []byte(
			`{"$id":"` + templateSchema + `","$ref":"file:///etc/passwd"}`)},
	}

	// when
	_, err := newValidator(fsys)

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
	_, err := newValidator(fsys)
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
		"schemas/component/x.v1.schema.json": {Data: []byte(`{"$id":"https://x/x.json","properties":{
			"closed":{"type":"boolean","default":false,"x-access":"manage"}},
			"patternProperties":{"^v_.+$":{"x-access":{"unless":"closed"}}}}`)},
	}
	v, err := newValidator(fsys)
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
