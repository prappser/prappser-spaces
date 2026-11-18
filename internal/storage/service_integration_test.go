//go:build integration

package storage

import (
	"bytes"
	"context"
	"image"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/prappser/prappser-spaces/internal/testdb"
)

// TestUpload_PDF_Succeeds_Integration verifies that Service.Upload, wired to
// a real repository, accepts a content type that was previously rejected by
// the deleted allowedContentTypes gate. Uses testdb for the repository (real
// migrations, per-package schema) and the mock backend for blob storage, so
// no object storage backend is needed.
func TestUpload_PDF_Succeeds_Integration(t *testing.T) {
	// given
	db := testdb.Connect(t, "storage")
	defer db.Close()

	repo := NewRepository(db)
	backend := newMockBackend()
	svc := NewService(repo, backend, 10*1024*1024, 0)

	data := []byte("%PDF-1.4 fake pdf bytes")
	req := &UploadRequest{
		ID:          "pdf-upload-1",
		Filename:    "report.pdf",
		ContentType: "application/pdf",
		SizeBytes:   int64(len(data)),
	}

	// when
	stored, err := svc.Upload(context.Background(), nil, "user-pk-1", nil, req, bytes.NewReader(data), "http://localhost", false)

	// then
	assert.NoError(t, err)
	assert.NotNil(t, stored)
	assert.Equal(t, "application/pdf", stored.ContentType)
}

func TestSetThumbnail_ShouldStoreThumbnailForPDFAndOverwrite_Integration(t *testing.T) {
	// given
	db := testdb.Connect(t, "storage")
	defer db.Close()

	backend, err := NewLocalStorage(&BackendConfig{LocalPath: t.TempDir()})
	require.NoError(t, err)
	svc := NewService(NewRepository(db), backend, 0, 0)
	ctx := context.Background()

	data := []byte("%PDF-1.4 fake pdf bytes")
	stored, err := svc.Upload(ctx, nil, "user-pk-thumb", nil, &UploadRequest{
		ID: "pdf-thumb-1", Filename: "doc.pdf", ContentType: "application/pdf", SizeBytes: int64(len(data)),
	}, bytes.NewReader(data), "http://localhost", false)
	require.NoError(t, err)

	thumb := pngBytes(t, 600, 400)

	// when
	require.NoError(t, svc.SetThumbnail(ctx, stored, thumb))
	err = svc.SetThumbnail(ctx, stored, thumb)

	// then
	require.NoError(t, err)
	want := strings.TrimSuffix(stored.StoragePath, filepath.Ext(stored.StoragePath)) + "_thumb.jpg"
	var got string
	require.NoError(t, db.QueryRow(`SELECT thumbnail_path FROM storage WHERE id = $1`, stored.ID).Scan(&got))
	assert.Equal(t, want, got)

	reader, _, err := svc.GetThumbnail(ctx, stored.ID)
	require.NoError(t, err)
	defer reader.Close()
	raw, err := io.ReadAll(reader)
	require.NoError(t, err)
	_, format, err := image.DecodeConfig(bytes.NewReader(raw))
	require.NoError(t, err)
	assert.Equal(t, "jpeg", format)
}
