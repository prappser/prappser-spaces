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
	err = v.ValidateComponentData("Checklist", vectorData(t, "checklist.json", "minimal"))

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
}

func TestValidateComponentData_ShouldReportFieldErrors(t *testing.T) {
	// given
	v, err := NewValidator()
	require.NoError(t, err)
	data := map[string]any{
		"items": []any{map[string]any{"id": "a", "title": "t"}},
		"bogus": float64(1),
	}

	// when
	err = v.ValidateComponentData("Checklist", data)

	// then
	var verrs ValidationErrors
	require.True(t, errors.As(err, &verrs))
	assert.ErrorIs(t, err, ErrInvalidData)
	byPath := map[string]string{}
	for _, f := range verrs {
		byPath[f.Path] = f.Message
	}
	assert.Contains(t, byPath["/items/0"], "checked")
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
