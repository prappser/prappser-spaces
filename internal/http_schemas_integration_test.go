//go:build integration

package internal

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/health"
	"github.com/prappser/prappser-spaces/internal/schemabundle"
	"github.com/prappser/prappser-spaces/internal/schemas"
	"github.com/prappser/prappser-spaces/internal/testdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

func signedBundle(t *testing.T, priv ed25519.PrivateKey, bundle int) []byte {
	t.Helper()
	schema := "{\"a\": 1}\n"
	sum := sha256.Sum256([]byte(schema))
	manifest := fmt.Sprintf(`{"bundle":%d,"types":{"A":{"min":1,"current":1}},"files":[{"path":"component/a.v1.schema.json","sha256":%q}]}`+"\n",
		bundle, hex.EncodeToString(sum[:]))
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "component"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "component", "a.v1.schema.json"), []byte(schema), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bundle.json"), []byte(manifest), 0o644))
	out, err := schemabundle.Build(dir, priv)
	require.NoError(t, err)
	return out
}

type schemasEnv struct {
	svc     *schemas.Service
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	repo    *schemas.Repository
	handler fasthttp.RequestHandler
}

func newSchemasEnv(t *testing.T, url string) schemasEnv {
	t.Helper()
	db := testdb.Connect(t, "schemashttp")
	t.Cleanup(func() { db.Close() })
	_, err := db.Exec(`DELETE FROM schema_bundle`)
	require.NoError(t, err)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	repo := schemas.NewRepository(db)
	svc := schemas.NewService(repo, pub, url)
	he := health.NewEndpoints("1.0.0", func() bool { return false }, false, svc)
	cfg := &Config{AllowedOrigins: []string{"https://prappser.app"}}
	handler := NewRequestHandler(cfg, nil, nil, he, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	return schemasEnv{svc, pub, priv, repo, handler}
}

func (e schemasEnv) get(path string) *fasthttp.RequestCtx {
	ctx := newAuthRouteRequestCtxWithMethod("GET", path)
	e.handler(ctx)
	return ctx
}

func (e schemasEnv) healthBundle(t *testing.T) (int, bool) {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.Unmarshal(e.get("/health").Response.Body(), &body))
	v, ok := body["bundle"]
	if !ok {
		return 0, false
	}
	return int(v.(float64)), true
}

func (e schemasEnv) servedBundle(t *testing.T) int {
	t.Helper()
	v, err := schemabundle.Verify(e.get("/schemas").Response.Body(), e.pub)
	require.NoError(t, err)
	return v.Manifest.Bundle
}

func TestSchemasRoutes_NoContainer_ShouldOmitBundleAndReturn404_Integration(t *testing.T) {
	// given
	e := newSchemasEnv(t, "")

	// when
	e.svc.Load(nil)

	// then
	_, present := e.healthBundle(t)
	assert.False(t, present)
	assert.Equal(t, fasthttp.StatusNotFound, e.get("/schemas").Response.StatusCode())
}

func TestSchemasRoutes_EmbeddedContainer_ShouldServeExactBytes_Integration(t *testing.T) {
	// given
	e := newSchemasEnv(t, "")
	container := signedBundle(t, e.priv, 4)

	// when
	e.svc.Load(container)

	// then
	ctx := e.get("/schemas")
	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Equal(t, container, ctx.Response.Body())
	got, present := e.healthBundle(t)
	assert.True(t, present)
	assert.Equal(t, e.servedBundle(t), got)
	assert.Equal(t, 4, got)
}

func TestSchemasRoutes_StoredContainerOnly_ShouldBeServed_Integration(t *testing.T) {
	// given
	e := newSchemasEnv(t, "")
	container := signedBundle(t, e.priv, 5)
	require.NoError(t, e.repo.Save(5, container))

	// when
	e.svc.Load(nil)

	// then
	assert.Equal(t, container, e.get("/schemas").Response.Body())
	got, _ := e.healthBundle(t)
	assert.Equal(t, 5, got)
}

func TestSchemasRoutes_FetchHigherBundle_ShouldServeAndStoreIt_Integration(t *testing.T) {
	// given
	var served []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(served)
	}))
	t.Cleanup(srv.Close)
	e := newSchemasEnv(t, srv.URL)
	e.svc.Load(signedBundle(t, e.priv, 4))
	served = signedBundle(t, e.priv, 9)

	// when
	e.svc.Fetch(t.Context())

	// then
	got, _ := e.healthBundle(t)
	assert.Equal(t, 9, got)
	assert.Equal(t, 9, e.servedBundle(t))
	row, err := e.repo.Get()
	require.NoError(t, err)
	require.NotNil(t, row)
	assert.Equal(t, 9, row.Bundle)
}
