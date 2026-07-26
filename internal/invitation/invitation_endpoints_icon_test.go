package invitation

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/prappser/prappser-spaces/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// mockIconResolver satisfies inviteIconResolver for endpoint tests.
type mockIconResolver struct {
	storageID     string
	applicationID string
	err           error
}

func (m *mockIconResolver) GetInviteIconStorageID(token string) (string, string, error) {
	return m.storageID, m.applicationID, m.err
}

// mockIconReader satisfies iconStorageReader for endpoint tests.
type mockIconReader struct {
	data   []byte
	stored *storage.Storage
	err    error
}

func (m *mockIconReader) GetData(ctx context.Context, id string) (io.ReadCloser, *storage.Storage, error) {
	if m.err != nil {
		return nil, nil, m.err
	}
	return io.NopCloser(bytes.NewReader(m.data)), m.stored, nil
}

// newIconTestEndpoints wires mock resolver/reader implementations directly into
// InvitationEndpoints, bypassing the constructor since no real *InvitationService
// or database is needed for these tests.
func newIconTestEndpoints(resolver *mockIconResolver, reader *mockIconReader) *InvitationEndpoints {
	return &InvitationEndpoints{
		iconResolver: resolver,
		iconReader:   reader,
	}
}

func newIconTestRequestCtx(token string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("GET")
	if token != "" {
		ctx.SetUserValue("token", token)
	}
	return ctx
}

// ---- GetInviteIcon ----

func TestGetInviteIcon_ShouldReturn200WithIconBytes(t *testing.T) {
	// given
	iconBytes := []byte("fake-png-bytes")
	resolver := &mockIconResolver{storageID: "storage-1"}
	reader := &mockIconReader{
		data: iconBytes,
		stored: &storage.Storage{
			ID:          "storage-1",
			ContentType: "image/png",
			Status:      string(storage.StorageStatusReady),
		},
	}
	ep := newIconTestEndpoints(resolver, reader)
	ctx := newIconTestRequestCtx("valid-token")

	// when
	ep.GetInviteIcon(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Equal(t, iconBytes, ctx.Response.Body())
	assert.Equal(t, "image/png", string(ctx.Response.Header.ContentType()))
	assert.Equal(t, "private, max-age=3600", string(ctx.Response.Header.Peek("Cache-Control")))
}

func TestGetInviteIcon_ShouldReturn404WhenResolverErrors(t *testing.T) {
	// given
	resolver := &mockIconResolver{err: errors.New("invalid token")}
	reader := &mockIconReader{}
	ep := newIconTestEndpoints(resolver, reader)
	ctx := newIconTestRequestCtx("bad-token")

	// when
	ep.GetInviteIcon(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNotFound, ctx.Response.StatusCode())
}

func TestGetInviteIcon_ShouldReturn404WhenGetDataErrors(t *testing.T) {
	// given
	resolver := &mockIconResolver{storageID: "storage-1"}
	reader := &mockIconReader{err: errors.New("not found")}
	ep := newIconTestEndpoints(resolver, reader)
	ctx := newIconTestRequestCtx("valid-token")

	// when
	ep.GetInviteIcon(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNotFound, ctx.Response.StatusCode())
}

func TestGetInviteIcon_ShouldReturn404WhenStorageNotReady(t *testing.T) {
	// given
	resolver := &mockIconResolver{storageID: "storage-1"}
	reader := &mockIconReader{
		data: []byte("partial-bytes"),
		stored: &storage.Storage{
			ID:          "storage-1",
			ContentType: "image/png",
			Status:      "pending",
		},
	}
	ep := newIconTestEndpoints(resolver, reader)
	ctx := newIconTestRequestCtx("valid-token")

	// when
	ep.GetInviteIcon(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNotFound, ctx.Response.StatusCode())
}

func TestGetInviteIcon_ShouldReturn404WhenStorageBelongsToDifferentApplication(t *testing.T) {
	// given
	victimAppID := "victim-app"
	resolver := &mockIconResolver{storageID: "storage-1", applicationID: "attacker-app"}
	reader := &mockIconReader{
		data: []byte("fake-png-bytes"),
		stored: &storage.Storage{
			ID:            "storage-1",
			ContentType:   "image/png",
			Status:        string(storage.StorageStatusReady),
			ApplicationID: &victimAppID,
		},
	}
	ep := newIconTestEndpoints(resolver, reader)
	ctx := newIconTestRequestCtx("valid-token")

	// when
	ep.GetInviteIcon(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNotFound, ctx.Response.StatusCode())
	assert.NotEqual(t, []byte("fake-png-bytes"), ctx.Response.Body())
}

func TestGetInviteIcon_ShouldReturn200WhenStorageApplicationIDIsNil(t *testing.T) {
	// given
	iconBytes := []byte("fake-png-bytes")
	resolver := &mockIconResolver{storageID: "storage-1", applicationID: "some-app"}
	reader := &mockIconReader{
		data: iconBytes,
		stored: &storage.Storage{
			ID:          "storage-1",
			ContentType: "image/png",
			Status:      string(storage.StorageStatusReady),
			// ApplicationID left nil: registration-time icon uploads have no app context.
		},
	}
	ep := newIconTestEndpoints(resolver, reader)
	ctx := newIconTestRequestCtx("valid-token")

	// when
	ep.GetInviteIcon(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Equal(t, iconBytes, ctx.Response.Body())
}

func TestGetInviteIcon_ShouldReturn200WhenStorageApplicationIDMatchesInvite(t *testing.T) {
	// given
	iconBytes := []byte("fake-png-bytes")
	appID := "app-1"
	resolver := &mockIconResolver{storageID: "storage-1", applicationID: appID}
	reader := &mockIconReader{
		data: iconBytes,
		stored: &storage.Storage{
			ID:            "storage-1",
			ContentType:   "image/png",
			Status:        string(storage.StorageStatusReady),
			ApplicationID: &appID,
		},
	}
	ep := newIconTestEndpoints(resolver, reader)
	ctx := newIconTestRequestCtx("valid-token")

	// when
	ep.GetInviteIcon(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Equal(t, iconBytes, ctx.Response.Body())
}

func TestGetInviteIcon_ShouldReturn400WhenTokenMissing(t *testing.T) {
	// given
	resolver := &mockIconResolver{}
	reader := &mockIconReader{}
	ep := newIconTestEndpoints(resolver, reader)
	ctx := newIconTestRequestCtx("")

	// when
	ep.GetInviteIcon(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}
