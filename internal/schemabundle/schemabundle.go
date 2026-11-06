// Package schemabundle signs, verifies and publishes the component schema bundle.
package schemabundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const PublicKeyBase64 = "hRp/eQ+AtYuK2DGLOEF5Qis0WIOm2zzt+wPEUBIUvXs="

const (
	ActionReuse   = "reuse"
	ActionPublish = "publish"
	ActionNone    = "none"
)

var publicKey = mustDecodePublicKey()

func mustDecodePublicKey() ed25519.PublicKey {
	b, err := base64.StdEncoding.DecodeString(PublicKeyBase64)
	if err != nil || len(b) != ed25519.PublicKeySize {
		panic("schemabundle: PublicKeyBase64 is not a 32 byte key")
	}
	return b
}

func PublicKey() ed25519.PublicKey { return publicKey }

type TypeRange struct {
	Min     int `json:"min"`
	Current int `json:"current"`
}

type FileEntry struct {
	Path   string
	SHA256 string
}

type Manifest struct {
	Bundle int
	Types  map[string]TypeRange
	Files  []FileEntry
}

type Verified struct {
	ManifestRaw []byte
	Manifest    Manifest
	Files       map[string]string
}

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

func asString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

func parseManifest(raw []byte) (Manifest, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || top == nil {
		return Manifest{}, errors.New("manifest is not a JSON object")
	}
	var m Manifest
	n, err := strconv.Atoi(string(top["bundle"]))
	if err != nil || n < 1 || n > math.MaxInt32 {
		return Manifest{}, errors.New("manifest bundle must be an integer between 1 and 2147483647")
	}
	m.Bundle = n

	// types is not validated: the Dart verifier ignores it too, and both must agree.
	_ = json.Unmarshal(top["types"], &m.Types)

	var files []map[string]json.RawMessage
	if err := json.Unmarshal(top["files"], &files); err != nil || files == nil {
		return Manifest{}, errors.New("manifest files must be an array of objects")
	}
	seen := map[string]bool{}
	for i, f := range files {
		p, ok1 := asString(f["path"])
		h, ok2 := asString(f["sha256"])
		if !ok1 || !ok2 {
			return Manifest{}, fmt.Errorf("manifest files[%d]: path and sha256 must be strings", i)
		}
		if !sha256Re.MatchString(h) {
			return Manifest{}, fmt.Errorf("manifest files[%d]: sha256 must be 64 lowercase hex chars", i)
		}
		if seen[p] {
			return Manifest{}, fmt.Errorf("manifest has duplicate path %q", p)
		}
		seen[p] = true
		m.Files = append(m.Files, FileEntry{Path: p, SHA256: h})
	}
	return m, nil
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func Verify(container []byte, pub ed25519.PublicKey) (*Verified, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(container, &top); err != nil || top == nil {
		return nil, errors.New("container is not a JSON object")
	}
	manifest, ok := asString(top["manifest"])
	if !ok {
		return nil, errors.New("container manifest must be a string")
	}
	sigStr, ok := asString(top["signature"])
	if !ok {
		return nil, errors.New("container signature must be a string")
	}
	var rawFiles map[string]json.RawMessage
	if len(top["files"]) == 0 || top["files"][0] != '{' || json.Unmarshal(top["files"], &rawFiles) != nil {
		return nil, errors.New("container files must be an object")
	}
	files := make(map[string]string, len(rawFiles))
	for k, v := range rawFiles {
		s, ok := asString(v)
		if !ok {
			return nil, fmt.Errorf("container file %q must be a string", k)
		}
		files[k] = s
	}

	sig, err := base64.StdEncoding.Strict().DecodeString(sigStr)
	if err != nil || len(sigStr) != 88 || len(sig) != ed25519.SignatureSize ||
		base64.StdEncoding.EncodeToString(sig) != sigStr {
		return nil, errors.New("signature must be padded standard base64 of 64 bytes")
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, []byte(manifest), sig) {
		return nil, errors.New("signature does not match manifest")
	}

	m, err := parseManifest([]byte(manifest))
	if err != nil {
		return nil, err
	}
	if len(m.Files) != len(files) {
		return nil, errors.New("container files do not match manifest paths")
	}
	for _, f := range m.Files {
		content, ok := files[f.Path]
		if !ok {
			return nil, fmt.Errorf("container is missing file %q", f.Path)
		}
		if sum([]byte(content)) != f.SHA256 {
			return nil, fmt.Errorf("sha256 mismatch for %q", f.Path)
		}
	}
	return &Verified{ManifestRaw: []byte(manifest), Manifest: m, Files: files}, nil
}

func readSchemaFiles(schemasDir string, m Manifest) (map[string]string, error) {
	files := make(map[string]string, len(m.Files))
	for _, f := range m.Files {
		b, err := os.ReadFile(filepath.Join(schemasDir, filepath.FromSlash(f.Path)))
		if err != nil {
			return nil, err
		}
		if !utf8.Valid(b) {
			return nil, fmt.Errorf("%s is not valid UTF-8", f.Path)
		}
		if sum(b) != f.SHA256 {
			return nil, fmt.Errorf("%s: sha256 does not match bundle.json (stale manifest)", f.Path)
		}
		files[f.Path] = string(b)
	}
	return files, nil
}

func Build(schemasDir string, priv ed25519.PrivateKey) ([]byte, error) {
	manifestRaw, err := os.ReadFile(filepath.Join(schemasDir, "bundle.json"))
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(manifestRaw) {
		return nil, errors.New("bundle.json is not valid UTF-8")
	}
	m, err := parseManifest(manifestRaw)
	if err != nil {
		return nil, err
	}
	files, err := readSchemaFiles(schemasDir, m)
	if err != nil {
		return nil, err
	}
	out := struct {
		Manifest  string            `json:"manifest"`
		Signature string            `json:"signature"`
		Files     map[string]string `json:"files"`
	}{
		string(manifestRaw),
		base64.StdEncoding.EncodeToString(ed25519.Sign(priv, manifestRaw)),
		files,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return nil, err
	}
	if _, err := Verify(buf.Bytes(), priv.Public().(ed25519.PublicKey)); err != nil {
		return nil, fmt.Errorf("self-verification failed: %w", err)
	}
	return buf.Bytes(), nil
}

type Action string

func Decide(prev *Verified, manifestRaw []byte, bundle int) (Action, error) {
	switch {
	case prev == nil:
		return ActionPublish, nil
	case bytes.Equal(prev.ManifestRaw, manifestRaw):
		return ActionReuse, nil
	case bundle > prev.Manifest.Bundle:
		return ActionPublish, nil
	}
	return "", fmt.Errorf("manifest changed but bundle %d is not higher than published %d", bundle, prev.Manifest.Bundle)
}

func ParseKey(b64 string) (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("signing key must be padded standard base64 of a 32 byte seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

//go:embed all:signed
var signedFS embed.FS

func Signed() ([]byte, bool) {
	b, err := signedFS.ReadFile("signed/schema-bundle.json")
	return b, err == nil
}

// Embedded verifies the container compiled into the binary: (nil, nil) when none is embedded.
func Embedded() (*Verified, error) {
	b, ok := Signed()
	return verifyEmbedded(b, ok, PublicKey())
}

func verifyEmbedded(b []byte, present bool, pub ed25519.PublicKey) (*Verified, error) {
	if !present {
		return nil, nil
	}
	return Verify(b, pub)
}

const signedDir = "internal/schemabundle/signed"

// ResolveOutPath keeps a dry-run container (throwaway key) out of the embedded directory.
func ResolveOutPath(out string, dryRun bool) (string, error) {
	if out == "" {
		if dryRun {
			return filepath.Join(os.TempDir(), "schema-bundle-dryrun.json"), nil
		}
		return signedDir + "/schema-bundle.json", nil
	}
	if dryRun {
		abs, err := filepath.Abs(out)
		if err != nil {
			return "", err
		}
		if strings.Contains(filepath.ToSlash(abs)+"/", "/"+signedDir+"/") {
			return "", errors.New("a dry-run bundle must not be written into " + signedDir)
		}
	}
	return out, nil
}

type Options struct {
	SchemasDir   string
	PreviousPath string
	OutPath      string
	DryRun       bool
	KeyB64       string
	// PublicKey replaces the production key so tests can use throwaway keys.
	PublicKey ed25519.PublicKey
}

type Result struct {
	Action string
	Bundle int
}

func Execute(o Options) (Result, error) {
	pub := o.PublicKey
	if pub == nil {
		pub = PublicKey()
	}
	manifestRaw, err := os.ReadFile(filepath.Join(o.SchemasDir, "bundle.json"))
	if err != nil {
		return Result{}, err
	}
	m, err := parseManifest(manifestRaw)
	if err != nil {
		return Result{}, err
	}

	var prev *Verified
	var prevBytes []byte
	if o.PreviousPath != "" {
		b, err := os.ReadFile(o.PreviousPath)
		if err != nil && !os.IsNotExist(err) {
			return Result{}, err
		}
		if len(b) > 0 {
			// A release asset can be uploaded by anyone with write access, so it must verify too.
			if prev, err = Verify(b, pub); err != nil {
				return Result{}, fmt.Errorf("previous bundle: %w", err)
			}
			prevBytes = b
		}
	}
	action, err := Decide(prev, manifestRaw, m.Bundle)
	if err != nil {
		return Result{}, err
	}

	if action == ActionReuse {
		// The reused container must still describe the schemas in this tree.
		if _, err := readSchemaFiles(o.SchemasDir, m); err != nil {
			return Result{}, err
		}
		if err := writeOut(o.OutPath, prevBytes); err != nil {
			return Result{}, err
		}
		return Result{Action: ActionReuse, Bundle: m.Bundle}, nil
	}

	var priv ed25519.PrivateKey
	switch {
	case o.DryRun:
		if _, priv, err = ed25519.GenerateKey(rand.Reader); err != nil {
			return Result{}, err
		}
	case o.KeyB64 == "":
		return Result{Action: ActionNone, Bundle: m.Bundle}, nil
	default:
		if priv, err = ParseKey(o.KeyB64); err != nil {
			return Result{}, err
		}
		if !priv.Public().(ed25519.PublicKey).Equal(pub) {
			return Result{}, errors.New("signing key does not match the embedded public key")
		}
	}

	out, err := Build(o.SchemasDir, priv)
	if err != nil {
		return Result{}, err
	}
	if err := writeOut(o.OutPath, out); err != nil {
		return Result{}, err
	}
	return Result{Action: ActionPublish, Bundle: m.Bundle}, nil
}

func writeOut(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
