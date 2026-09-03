//go:build integration

package storage

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

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
	svc := NewService(repo, backend, 10*1024*1024)

	data := []byte("%PDF-1.4 fake pdf bytes")
	req := &UploadRequest{
		ID:          "pdf-upload-1",
		Filename:    "report.pdf",
		ContentType: "application/pdf",
		SizeBytes:   int64(len(data)),
	}

	// when
	stored, err := svc.Upload(context.Background(), nil, "user-pk-1", nil, req, bytes.NewReader(data), "http://localhost")

	// then
	assert.NoError(t, err)
	assert.NotNil(t, stored)
	assert.Equal(t, "application/pdf", stored.ContentType)
}
