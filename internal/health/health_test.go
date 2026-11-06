package health

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/schemabundle"
	"github.com/prappser/prappser-spaces/internal/schemas"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

func healthBody(t *testing.T, open bool, mcpEnabled bool) HealthResponse {
	t.Helper()
	ctx := &fasthttp.RequestCtx{}

	NewEndpoints("1.0.0", func() bool { return open }, mcpEnabled, nil).Health(ctx)

	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	var body HealthResponse
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &body))
	return body
}

func TestHealth_RegistrationOpen_ShouldReportTrue(t *testing.T) {
	// given / when
	body := healthBody(t, true, false)

	// then
	assert.True(t, body.RegistrationOpen)
	assert.Equal(t, "ok", body.Status)
}

func TestHealth_RegistrationClosed_ShouldReportFalse(t *testing.T) {
	// given / when
	body := healthBody(t, false, false)

	// then
	assert.False(t, body.RegistrationOpen)
}

func TestHealth_MCPEnabled_ShouldReportTrue(t *testing.T) {
	// given / when
	body := healthBody(t, false, true)

	// then
	assert.True(t, body.MCPEnabled)
}

func TestHealth_MCPDisabled_ShouldReportFalse(t *testing.T) {
	// given / when
	body := healthBody(t, false, false)

	// then
	assert.False(t, body.MCPEnabled)
}

type fakeStore struct{}

func (fakeStore) Get() (*schemas.Stored, error) { return nil, nil }
func (fakeStore) Save(int, []byte) error        { return nil }

func signedContainer(t *testing.T, priv ed25519.PrivateKey, bundle int) []byte {
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

func loadedService(t *testing.T, bundle int) (*schemas.Service, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	container := signedContainer(t, priv, bundle)
	svc := schemas.NewService(fakeStore{}, pub, "")
	svc.Load(container)
	require.NotNil(t, svc.Current())
	return svc, container
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = prev })
	return &buf
}

func schemasCtx(method string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(method)
	ctx.Request.SetRequestURI("/schemas")
	return ctx
}

func TestHealth_NoContainer_ShouldOmitBundle(t *testing.T) {
	// given
	ctx := &fasthttp.RequestCtx{}

	// when
	NewEndpoints("1.0.0", func() bool { return false }, false, nil).Health(ctx)

	// then
	var body map[string]any
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &body))
	assert.NotContains(t, body, "bundle")
}

func TestHealth_WithContainer_ShouldReportBundle(t *testing.T) {
	// given
	svc, _ := loadedService(t, 7)
	ctx := &fasthttp.RequestCtx{}

	// when
	NewEndpoints("1.0.0", func() bool { return false }, false, svc).Health(ctx)

	// then
	var body HealthResponse
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &body))
	assert.Equal(t, 7, body.Bundle)
}

func TestSchemas_ShouldServeExactBytes(t *testing.T) {
	// given
	svc, container := loadedService(t, 3)
	ctx := schemasCtx("GET")

	// when
	NewEndpoints("1.0.0", func() bool { return false }, false, svc).Schemas(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Equal(t, "application/json", string(ctx.Response.Header.ContentType()))
	assert.Equal(t, container, ctx.Response.Body())
}

func TestSchemas_NilService_ShouldReturn404WithoutLogging(t *testing.T) {
	// given
	buf := captureLog(t)
	ctx := schemasCtx("GET")

	// when
	NewEndpoints("1.0.0", func() bool { return false }, false, nil).Schemas(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNotFound, ctx.Response.StatusCode())
	assert.Empty(t, buf.String())
}

func TestSchemas_NothingLoaded_ShouldReturn404WithoutLogging(t *testing.T) {
	// given
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	svc := schemas.NewService(fakeStore{}, pub, "")
	buf := captureLog(t)
	ctx := schemasCtx("GET")

	// when
	NewEndpoints("1.0.0", func() bool { return false }, false, svc).Schemas(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNotFound, ctx.Response.StatusCode())
	assert.Empty(t, buf.String())
}

func TestSchemas_Post_ShouldReturn405(t *testing.T) {
	// given
	svc, _ := loadedService(t, 3)
	ctx := schemasCtx("POST")

	// when
	NewEndpoints("1.0.0", func() bool { return false }, false, svc).Schemas(ctx)

	// then
	assert.Equal(t, fasthttp.StatusMethodNotAllowed, ctx.Response.StatusCode())
	assert.Equal(t, "GET, HEAD", string(ctx.Response.Header.Peek("Allow")))
}

func TestSchemas_Head_ShouldReturn200(t *testing.T) {
	// given
	svc, _ := loadedService(t, 3)
	ctx := schemasCtx("HEAD")

	// when
	NewEndpoints("1.0.0", func() bool { return false }, false, svc).Schemas(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Equal(t, "application/json", string(ctx.Response.Header.ContentType()))
}
