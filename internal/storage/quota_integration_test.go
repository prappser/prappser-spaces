//go:build integration

package storage

import (
	"bytes"
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/prappser/prappser-spaces/internal/testdb"
)

func newQuotaService(t *testing.T, pk string, maxFileSize, quota int64) *Service {
	t.Helper()
	db := testdb.Connect(t, "storage")
	t.Cleanup(func() { db.Close() })
	seedQuotaUser(t, db, pk)
	return NewService(NewRepository(db), newMockBackend(), maxFileSize, quota)
}

func seedQuotaUser(t *testing.T, db *sql.DB, pk string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO users (public_key, username, role, created_at, issuer) VALUES ($1, $1, 'user', $2, $1) ON CONFLICT DO NOTHING`, pk, time.Now().Unix())
	require.NoError(t, err)
}

func uploadBytes(svc *Service, id, pk string, size int, exempt bool) error {
	_, err := svc.Upload(context.Background(), nil, pk, nil, &UploadRequest{
		ID:          id,
		Filename:    id + ".bin",
		ContentType: "application/octet-stream",
		SizeBytes:   int64(size),
	}, bytes.NewReader(make([]byte, size)), "http://localhost", exempt)
	return err
}

func TestUpload_OverFileCap_ShouldReturnErrFileTooLarge_Integration(t *testing.T) {
	// given
	svc := newQuotaService(t, "quota-pk-cap", 10, 0)

	// when
	err := uploadBytes(svc, "quota-cap-1", "quota-pk-cap", 20, false)

	// then
	assert.ErrorIs(t, err, ErrFileTooLarge)
}

func TestUpload_OverAccountQuota_ShouldReturnErrStorageQuotaExceeded_Integration(t *testing.T) {
	// given
	svc := newQuotaService(t, "quota-pk-over", 100, 100)
	require.NoError(t, uploadBytes(svc, "quota-over-1", "quota-pk-over", 60, false))

	// when
	err := uploadBytes(svc, "quota-over-2", "quota-pk-over", 60, false)

	// then
	assert.ErrorIs(t, err, ErrStorageQuotaExceeded)
}

func TestUpload_OverAccountQuotaAsExempt_ShouldSucceed_Integration(t *testing.T) {
	// given
	svc := newQuotaService(t, "quota-pk-exempt", 100, 100)
	require.NoError(t, uploadBytes(svc, "quota-exempt-1", "quota-pk-exempt", 60, true))

	// when
	err := uploadBytes(svc, "quota-exempt-2", "quota-pk-exempt", 60, true)

	// then
	assert.NoError(t, err)
}

func TestUpload_QuotaZero_ShouldBeUnlimited_Integration(t *testing.T) {
	// given
	svc := newQuotaService(t, "quota-pk-zero", 100, 0)
	require.NoError(t, uploadBytes(svc, "quota-zero-1", "quota-pk-zero", 90, false))

	// when
	err := uploadBytes(svc, "quota-zero-2", "quota-pk-zero", 90, false)

	// then
	assert.NoError(t, err)
}

func TestInitChunkedUpload_OverAccountQuota_ShouldReturnErrStorageQuotaExceeded_Integration(t *testing.T) {
	// given
	svc := newQuotaService(t, "quota-pk-init", 100, 100)
	require.NoError(t, uploadBytes(svc, "quota-init-1", "quota-pk-init", 60, false))

	// when
	_, err := svc.InitChunkedUpload(context.Background(), nil, "quota-pk-init", nil, &ChunkedUploadInitRequest{
		ID:          "quota-init-2",
		Filename:    "big.bin",
		ContentType: "application/octet-stream",
		TotalSize:   60,
	}, false)

	// then
	assert.ErrorIs(t, err, ErrStorageQuotaExceeded)
}

func TestCompleteChunkedUpload_CombinedLargerThanDeclared_ShouldReturnErrFileTooLarge_Integration(t *testing.T) {
	// given
	ctx := context.Background()
	svc := newQuotaService(t, "quota-pk-lie", 100, 0)
	_, err := svc.InitChunkedUpload(ctx, nil, "quota-pk-lie", nil, &ChunkedUploadInitRequest{
		ID:          "quota-lie-1",
		Filename:    "lie.bin",
		ContentType: "application/octet-stream",
		TotalSize:   5,
	}, false)
	require.NoError(t, err)
	require.NoError(t, svc.UploadChunk(ctx, "quota-lie-1", 0, bytes.NewReader(make([]byte, 50))))

	// when
	_, err = svc.CompleteChunkedUpload(ctx, "quota-lie-1", "http://localhost")

	// then
	assert.ErrorIs(t, err, ErrFileTooLarge)
}
