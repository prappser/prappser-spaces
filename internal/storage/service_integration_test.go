//go:build integration

package storage

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/prappser/prappser-spaces/internal/testdb"
)

// TestUpload_MalformedPDF_SucceedsWithoutThumbnail_Integration verifies that
// Service.Upload, wired to a real repository, still accepts a PDF whose
// thumbnail cannot be rendered. Uses testdb for the repository (real
// migrations, per-package schema) and the mock backend for blob storage, so
// no object storage backend is needed.
func TestUpload_MalformedPDF_SucceedsWithoutThumbnail_Integration(t *testing.T) {
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
	assert.Empty(t, stored.ThumbnailURL)
}

func TestUpload_PDF_GeneratesThumbnail_Integration(t *testing.T) {
	// given
	db := testdb.Connect(t, "storage")
	defer db.Close()

	repo := NewRepository(db)
	backend := newMockBackend()
	svc := NewService(repo, backend, 10*1024*1024, 0)

	data, err := os.ReadFile("testdata/one-page.pdf")
	require.NoError(t, err)
	req := &UploadRequest{
		ID:          "pdf-upload-thumb-1",
		Filename:    "one-page.pdf",
		ContentType: "application/pdf",
		SizeBytes:   int64(len(data)),
	}

	// when
	stored, err := svc.Upload(context.Background(), nil, "user-pk-1", nil, req, bytes.NewReader(data), "http://localhost", false)

	// then
	require.NoError(t, err)
	assert.NotEmpty(t, stored.ThumbnailURL)
	assert.True(t, strings.HasSuffix(stored.ThumbnailPath, "_thumb.jpg"))
	assert.Contains(t, backend.objects, stored.ThumbnailPath)
	row, err := repo.GetByID(req.ID)
	assert.NoError(t, err)
	assert.Equal(t, stored.ThumbnailPath, row.ThumbnailPath)
}
