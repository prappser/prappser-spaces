package keys

import (
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// newExportTestService builds a KeyService with only privateKey/publicKey
// set, no repo/DB - enough to exercise ExportIdentity, which is a pure
// in-memory re-encryption (see KeyService.ExportIdentity).
func newExportTestService(t *testing.T) *KeyService {
	t.Helper()
	priv, pub, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	return &KeyService{privateKey: priv, publicKey: pub}
}

func newExportRequestCtx(t *testing.T, body any) *fasthttp.RequestCtx {
	t.Helper()
	b, err := json.Marshal(body)
	assert.NoError(t, err)
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.SetBody(b)
	return ctx
}

// TestExportIdentity_ShouldReturn200WithBlobThatDecryptsBackToSameKey covers
// the happy path end to end: the returned blob decodes and decrypts back to
// the exact same private key the service holds.
func TestExportIdentity_ShouldReturn200WithBlobThatDecryptsBackToSameKey(t *testing.T) {
	// given
	keyService := newExportTestService(t)
	ke := NewKeyEndpoints(keyService)
	ctx := newExportRequestCtx(t, exportIdentityRequest{Passphrase: "a-strong-passphrase"})

	// when
	ke.ExportIdentity(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	var resp exportIdentityResponse
	assert.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	assert.NotEmpty(t, resp.Blob)

	decoded, err := DecodeIdentityBlob(resp.Blob)
	assert.NoError(t, err)
	decryptedPriv, err := DecryptPrivateKey(decoded, "a-strong-passphrase")
	assert.NoError(t, err)
	assert.Equal(t, keyService.PrivateKey().Seed(), decryptedPriv.Seed())
}

func TestExportIdentity_ShouldReturn400ForUnparsableBody(t *testing.T) {
	// given
	ke := NewKeyEndpoints(newExportTestService(t))
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("POST")
	ctx.Request.SetBody([]byte("not json"))

	// when
	ke.ExportIdentity(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestExportIdentity_ShouldReturn400ForMissingPassphrase(t *testing.T) {
	// given
	ke := NewKeyEndpoints(newExportTestService(t))
	ctx := newExportRequestCtx(t, exportIdentityRequest{})

	// when
	ke.ExportIdentity(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestExportIdentity_ShouldReturn400ForPassphraseShorterThan12Chars(t *testing.T) {
	// given
	ke := NewKeyEndpoints(newExportTestService(t))
	ctx := newExportRequestCtx(t, exportIdentityRequest{Passphrase: "short"})

	// when
	ke.ExportIdentity(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}
