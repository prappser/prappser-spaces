package schemabundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newKey(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

func manifestText(t testing.TB, bundle any, files map[string]string, mutate func(entries []map[string]any)) string {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	entries := []map[string]any{}
	for _, p := range paths {
		entries = append(entries, map[string]any{"path": p, "sha256": sum([]byte(files[p]))})
	}
	if mutate != nil {
		mutate(entries)
	}
	b, err := json.MarshalIndent(map[string]any{
		"bundle": bundle,
		"types":  map[string]any{"A": map[string]int{"min": 1, "current": 1}},
		"files":  entries,
	}, "", "  ")
	require.NoError(t, err)
	return string(b) + "\n"
}

func containerJSON(t testing.TB, manifest, sig string, files map[string]any, extra map[string]any) []byte {
	m := map[string]any{"manifest": manifest, "signature": sig, "files": files}
	for k, v := range extra {
		m[k] = v
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	require.NoError(t, enc.Encode(m))
	return buf.Bytes()
}

func sigOf(priv ed25519.PrivateKey, manifest string) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(manifest)))
}

func anyFiles(f map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range f {
		out[k] = v
	}
	return out
}

var sampleFiles = map[string]string{
	"component/a.v1.schema.json":      "{\"a\": \"café\"}\n",
	"component/common.v1.schema.json": "{\"c\": 1}\n",
}

func writeSchemas(t *testing.T, bundle int) string {
	dir := t.TempDir()
	for p, c := range sampleFiles {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, p), []byte(c), 0o644))
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bundle.json"), []byte(manifestText(t, bundle, sampleFiles, nil)), 0o644))
	return dir
}

func TestDecide(t *testing.T) {
	prev := &Verified{ManifestRaw: []byte("m1"), Manifest: Manifest{Bundle: 3}}
	tests := []struct {
		name    string
		prev    *Verified
		raw     string
		bundle  int
		want    Action
		wantErr bool
	}{
		{"no previous publishes", nil, "m1", 1, ActionPublish, false},
		{"equal manifest reuses", prev, "m1", 3, ActionReuse, false},
		{"changed with higher number publishes", prev, "m2", 4, ActionPublish, false},
		{"changed with equal number errors", prev, "m2", 3, "", true},
		{"changed with lower number errors", prev, "m2", 2, "", true},
		{"reformatted with lower number errors", prev, "m1 ", 2, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decide(tt.prev, []byte(tt.raw), tt.bundle)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantErr, err != nil)
		})
	}
}

func TestParseKey(t *testing.T) {
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	require.NoError(t, err)
	_, err = ParseKey(base64.StdEncoding.EncodeToString(seed))
	assert.NoError(t, err)

	full := ed25519.NewKeyFromSeed(seed)
	for name, in := range map[string]string{
		"64 byte form": base64.StdEncoding.EncodeToString(full),
		"short":        base64.StdEncoding.EncodeToString(seed[:16]),
		"bad base64":   "!!!not base64!!!",
		"unpadded":     base64.RawStdEncoding.EncodeToString(seed),
		"empty":        "",
	} {
		_, err := ParseKey(in)
		assert.Error(t, err, name)
	}
}

func TestBuild(t *testing.T) {
	t.Run("good dir verifies only under its own key", func(t *testing.T) {
		pub, priv := newKey(t)
		out, err := Build(writeSchemas(t, 1), priv)
		require.NoError(t, err)
		v, err := Verify(out, pub)
		require.NoError(t, err)
		assert.Equal(t, 1, v.Manifest.Bundle)
		assert.Len(t, v.Files, 2)
		other, _ := newKey(t)
		_, err = Verify(out, other)
		assert.Error(t, err)
	})
	t.Run("hash mismatch names the path", func(t *testing.T) {
		_, priv := newKey(t)
		dir := writeSchemas(t, 1)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "component/a.v1.schema.json"), []byte("changed"), 0o644))
		_, err := Build(dir, priv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "component/a.v1.schema.json")
	})
	t.Run("missing file", func(t *testing.T) {
		_, priv := newKey(t)
		dir := writeSchemas(t, 1)
		require.NoError(t, os.Remove(filepath.Join(dir, "component/common.v1.schema.json")))
		_, err := Build(dir, priv)
		assert.Error(t, err)
	})
	t.Run("non UTF-8 file", func(t *testing.T) {
		_, priv := newKey(t)
		bad := map[string]string{"component/x.json": "\xff\xfe"}
		dir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "component"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "component/x.json"), []byte(bad["component/x.json"]), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "bundle.json"), []byte(manifestText(t, 1, bad, nil)), 0o644))
		_, err := Build(dir, priv)
		assert.Error(t, err)
	})
}

func TestExecute(t *testing.T) {
	seedKey := func(priv ed25519.PrivateKey) string {
		return base64.StdEncoding.EncodeToString(priv.Seed())
	}

	t.Run("keyless real run does nothing", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "out.json")
		res, err := Execute(Options{SchemasDir: writeSchemas(t, 1), OutPath: out})
		require.NoError(t, err)
		assert.Equal(t, Result{Action: ActionNone, Bundle: 1}, res)
		assert.NoFileExists(t, out)
	})
	t.Run("dry run publishes with a throwaway key", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "sub", "out.json")
		res, err := Execute(Options{SchemasDir: writeSchemas(t, 2), OutPath: out, DryRun: true})
		require.NoError(t, err)
		assert.Equal(t, Result{Action: ActionPublish, Bundle: 2}, res)
		b, err := os.ReadFile(out)
		require.NoError(t, err)
		_, err = Verify(b, PublicKey())
		assert.Error(t, err)
		var c struct{ Signature string }
		require.NoError(t, json.Unmarshal(b, &c))
		assert.Len(t, c.Signature, 88)
	})
	t.Run("real run with a foreign key errors", func(t *testing.T) {
		_, priv := newKey(t)
		_, err := Execute(Options{SchemasDir: writeSchemas(t, 1), OutPath: filepath.Join(t.TempDir(), "o"), KeyB64: seedKey(priv)})
		assert.Error(t, err)
	})
	t.Run("previous signed by another key errors", func(t *testing.T) {
		_, other := newKey(t)
		dir := writeSchemas(t, 1)
		prev, err := Build(dir, other)
		require.NoError(t, err)
		pp := filepath.Join(t.TempDir(), "prev.json")
		require.NoError(t, os.WriteFile(pp, prev, 0o644))
		_, err = Execute(Options{SchemasDir: dir, PreviousPath: pp, OutPath: filepath.Join(t.TempDir(), "o"), DryRun: true})
		assert.Error(t, err)
	})
	t.Run("real run publishes then reuses previous bytes", func(t *testing.T) {
		pub, priv := newKey(t)
		dir := writeSchemas(t, 1)
		out := filepath.Join(t.TempDir(), "out.json")
		res, err := Execute(Options{SchemasDir: dir, OutPath: out, KeyB64: seedKey(priv), PublicKey: pub})
		require.NoError(t, err)
		assert.Equal(t, ActionPublish, res.Action)
		first, err := os.ReadFile(out)
		require.NoError(t, err)

		out2 := filepath.Join(t.TempDir(), "out2.json")
		res, err = Execute(Options{SchemasDir: dir, PreviousPath: out, OutPath: out2, KeyB64: seedKey(priv), PublicKey: pub})
		require.NoError(t, err)
		assert.Equal(t, ActionReuse, res.Action)
		second, err := os.ReadFile(out2)
		require.NoError(t, err)
		assert.Equal(t, first, second)
	})
	t.Run("reuse does not consult the key", func(t *testing.T) {
		pub, priv := newKey(t)
		dir := writeSchemas(t, 1)
		prev, err := Build(dir, priv)
		require.NoError(t, err)
		pp := filepath.Join(t.TempDir(), "prev.json")
		require.NoError(t, os.WriteFile(pp, prev, 0o644))
		_, wrong := newKey(t)
		for _, key := range []string{"", seedKey(wrong)} {
			out := filepath.Join(t.TempDir(), "out.json")
			res, err := Execute(Options{SchemasDir: dir, PreviousPath: pp, OutPath: out, KeyB64: key, PublicKey: pub})
			require.NoError(t, err)
			assert.Equal(t, Result{Action: ActionReuse, Bundle: 1}, res)
			got, err := os.ReadFile(out)
			require.NoError(t, err)
			assert.Equal(t, prev, got)
		}
	})
	t.Run("reuse with an edited schema file errors", func(t *testing.T) {
		pub, priv := newKey(t)
		dir := writeSchemas(t, 1)
		prev, err := Build(dir, priv)
		require.NoError(t, err)
		pp := filepath.Join(t.TempDir(), "prev.json")
		require.NoError(t, os.WriteFile(pp, prev, 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "component/a.v1.schema.json"), []byte("edited"), 0o644))
		out := filepath.Join(t.TempDir(), "out.json")
		_, err = Execute(Options{SchemasDir: dir, PreviousPath: pp, OutPath: out, PublicKey: pub})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "component/a.v1.schema.json")
		assert.NoFileExists(t, out)
	})
	t.Run("missing or empty previous counts as none", func(t *testing.T) {
		empty := filepath.Join(t.TempDir(), "empty.json")
		require.NoError(t, os.WriteFile(empty, nil, 0o644))
		for _, p := range []string{filepath.Join(t.TempDir(), "nope.json"), empty} {
			res, err := Execute(Options{SchemasDir: writeSchemas(t, 1), PreviousPath: p, OutPath: filepath.Join(t.TempDir(), "o"), DryRun: true})
			require.NoError(t, err)
			assert.Equal(t, ActionPublish, res.Action)
		}
	})
}

func nonCanonical(sig string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b := []byte(sig)
	b[85] = alphabet[strings.IndexByte(alphabet, b[85])|1]
	return string(b)
}

func TestVerify_ShouldRejectNonCanonicalSignatureEncoding(t *testing.T) {
	pub, priv := newKey(t)
	manifest := manifestText(t, 1, sampleFiles, nil)
	sig := nonCanonical(sigOf(priv, manifest))
	_, err := Verify(containerJSON(t, manifest, sig, anyFiles(sampleFiles), nil), pub)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "padded standard base64")
}

func TestVerify_ShouldRejectBundleSpelledAsFloat(t *testing.T) {
	pub, priv := newKey(t)
	for _, lit := range []string{"1.0", "1e0"} {
		m := manifestText(t, json.RawMessage(lit), sampleFiles, nil)
		_, err := Verify(containerJSON(t, m, sigOf(priv, m), anyFiles(sampleFiles), nil), pub)
		assert.Error(t, err, lit)
	}
}

func TestVerify_ShouldRejectBundleOutOfRange(t *testing.T) {
	pub, priv := newKey(t)
	for _, lit := range []string{"2147483648", "9999999999999999999"} {
		m := manifestText(t, json.RawMessage(lit), sampleFiles, nil)
		_, err := Verify(containerJSON(t, m, sigOf(priv, m), anyFiles(sampleFiles), nil), pub)
		assert.Error(t, err, lit)
	}
	m := manifestText(t, json.RawMessage("2147483647"), sampleFiles, nil)
	_, err := Verify(containerJSON(t, m, sigOf(priv, m), anyFiles(sampleFiles), nil), pub)
	assert.NoError(t, err)
}

func TestResolveOutPath(t *testing.T) {
	got, err := ResolveOutPath("", true)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(os.TempDir(), "schema-bundle-dryrun.json"), got)

	got, err = ResolveOutPath("", false)
	require.NoError(t, err)
	assert.Equal(t, "internal/schemabundle/signed/schema-bundle.json", got)

	_, err = ResolveOutPath("internal/schemabundle/signed/schema-bundle.json", true)
	assert.Error(t, err)
	_, err = ResolveOutPath("./internal/schemabundle/signed/x.json", true)
	assert.Error(t, err)

	got, err = ResolveOutPath("internal/schemabundle/signed/schema-bundle.json", false)
	require.NoError(t, err)
	assert.Equal(t, "internal/schemabundle/signed/schema-bundle.json", got)
	got, err = ResolveOutPath("/tmp/x/out.json", true)
	require.NoError(t, err)
	assert.Equal(t, "/tmp/x/out.json", got)
}

func TestVerifyEmbedded(t *testing.T) {
	pub, priv := newKey(t)
	good, err := Build(writeSchemas(t, 7), priv)
	require.NoError(t, err)

	v, err := verifyEmbedded(nil, false, pub)
	assert.NoError(t, err)
	assert.Nil(t, v)

	v, err = verifyEmbedded(good, true, pub)
	require.NoError(t, err)
	assert.Equal(t, 7, v.Manifest.Bundle)

	_, err = verifyEmbedded([]byte("{}"), true, pub)
	assert.Error(t, err)
}

func TestSigned_ShouldBeAbsentOnCleanTree(t *testing.T) {
	_, ok := Signed()
	assert.False(t, ok)
}

func TestPublicKey_ShouldDecode(t *testing.T) {
	assert.Len(t, PublicKey(), ed25519.PublicKeySize)
}

func TestBuild_ShouldMatchSyncedSchemas(t *testing.T) {
	dir := "../component/schemas"
	if _, err := os.Stat(filepath.Join(dir, "bundle.json")); err != nil {
		t.Skip("bundle.json is not synced into internal/component/schemas yet")
	}
	pub, priv := newKey(t)
	out, err := Build(dir, priv)
	require.NoError(t, err)
	_, err = Verify(out, pub)
	assert.NoError(t, err)
}

func TestVectors(t *testing.T) {
	path := os.Getenv("SCHEMA_BUNDLE_VECTORS")
	if path == "" {
		path = "../component/schemas/vectors/bundle/container.json"
		if _, err := os.Stat(path); err != nil {
			t.Skip("shared bundle vectors are not synced yet")
		}
	}
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var f struct {
		PublicKey string `json:"publicKey"`
		Cases     []struct {
			Name      string          `json:"name"`
			Container json.RawMessage `json:"container"`
			Valid     bool            `json:"valid"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	pub, err := base64.StdEncoding.DecodeString(f.PublicKey)
	require.NoError(t, err)
	require.NotEmpty(t, f.Cases)
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			_, err := Verify(c.Container, pub)
			if c.Valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestWriteVectors(t *testing.T) {
	outPath := os.Getenv("SCHEMA_BUNDLE_WRITE_VECTORS")
	if outPath == "" {
		t.Skip("set SCHEMA_BUNDLE_WRITE_VECTORS to regenerate the shared vectors")
	}
	// The key is random and discarded; only the public half is written.
	var pub ed25519.PublicKey
	var priv ed25519.PrivateKey
	manifest := manifestText(t, 1, sampleFiles, nil)
	for {
		pub, priv = newKey(t)
		if strings.ContainsAny(sigOf(priv, manifest), "+/") {
			break
		}
	}
	good := sigOf(priv, manifest)
	files := func() map[string]any { return anyFiles(sampleFiles) }
	const pathA = "component/a.v1.schema.json"

	type vcase struct {
		Name      string          `json:"name"`
		Container json.RawMessage `json:"container"`
		Valid     bool            `json:"valid"`
	}
	var cases []vcase
	add := func(name string, valid bool, c []byte) {
		cases = append(cases, vcase{name, json.RawMessage(bytes.TrimSpace(c)), valid})
	}
	resign := func(m string, f map[string]any) []byte { return containerJSON(t, m, sigOf(priv, m), f, nil) }

	add("valid", true, containerJSON(t, manifest, good, files(), nil))
	add("valid with unknown top-level member", true, containerJSON(t, manifest, good, files(), map[string]any{"note": "ignored"}))

	b := []byte(manifest)
	b[strings.Index(manifest, "types")] = 'T'
	add("tampered manifest", false, containerJSON(t, string(b), good, files(), nil))

	f := files()
	f[pathA] = sampleFiles[pathA] + " "
	add("tampered file content", false, containerJSON(t, manifest, good, f, nil))

	f = files()
	delete(f, pathA)
	add("missing file", false, containerJSON(t, manifest, good, f, nil))

	f = files()
	f["component/extra.json"] = "{}"
	add("extra file", false, containerJSON(t, manifest, good, f, nil))

	wrong := make([]byte, 64)
	add("bad signature", false, containerJSON(t, manifest, base64.StdEncoding.EncodeToString(wrong), files(), nil))
	add("signature wrong length", false, containerJSON(t, manifest, base64.StdEncoding.EncodeToString(wrong[:48]), files(), nil))
	add("signature url-safe base64", false, containerJSON(t, manifest, strings.NewReplacer("+", "-", "/", "_").Replace(good), files(), nil))

	upper := manifestText(t, 1, sampleFiles, func(e []map[string]any) { e[0]["sha256"] = strings.ToUpper(e[0]["sha256"].(string)) })
	add("sha256 not lowercase hex", false, resign(upper, files()))

	dup := manifestText(t, 1, sampleFiles, func(e []map[string]any) { e[1]["path"] = e[0]["path"] })
	dupFiles := map[string]any{pathA: sampleFiles[pathA]}
	add("duplicate path in manifest", false, resign(dup, dupFiles))

	f = files()
	f[pathA] = 5
	add("file value not a string", false, containerJSON(t, manifest, good, f, nil))

	add("bundle 0", false, resign(manifestText(t, 0, sampleFiles, nil), files()))
	add("bundle above int32", false, resign(manifestText(t, json.RawMessage("2147483648"), sampleFiles, nil), files()))
	add("bundle overflows int64", false, resign(manifestText(t, json.RawMessage("9999999999999999999"), sampleFiles, nil), files()))
	add("bundle not an integer", false, resign(manifestText(t, 1.5, sampleFiles, nil), files()))

	add("bundle written as 1.0", false, resign(manifestText(t, json.RawMessage("1.0"), sampleFiles, nil), files()))
	add("bundle written as 1e0", false, resign(manifestText(t, json.RawMessage("1e0"), sampleFiles, nil), files()))
	add("container files is an array", false, containerJSON(t, manifest, good, nil, map[string]any{"files": []any{}}))
	add("manifest is not JSON", false, resign("not json\n", files()))
	add("manifest is a JSON array", false, resign("[]\n", files()))
	without := func(member string) []byte {
		m := map[string]any{"manifest": manifest, "signature": good, "files": files()}
		delete(m, member)
		raw, err := json.MarshalIndent(m, "", "  ")
		require.NoError(t, err)
		return raw
	}
	add("container missing signature", false, without("signature"))
	add("container missing manifest", false, without("manifest"))
	add("container missing files", false, without("files"))
	add("signature with non-canonical trailing bits", false, containerJSON(t, manifest, nonCanonical(good), files(), nil))

	_, other := newKey(t)
	add("signed by a different key", false, containerJSON(t, manifest, sigOf(other, manifest), files(), nil))

	out, err := json.MarshalIndent(map[string]any{
		"publicKey": base64.StdEncoding.EncodeToString(pub),
		"cases":     cases,
	}, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(outPath, append(out, '\n'), 0o644))
	fmt.Println("wrote", outPath)
}
