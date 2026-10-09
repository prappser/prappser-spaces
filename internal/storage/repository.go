package storage

import (
	"context"
	"database/sql"
	"fmt"
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Create(s *Storage) error {
	query := `INSERT INTO storage (id, application_id, space_id, uploader_public_key, filename, content_type, size_bytes, storage_path, thumbnail_path, width, height, duration_ms, checksum, created_at, status)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`

	_, err := r.db.Exec(query,
		s.ID,
		s.ApplicationID,
		s.SpaceID,
		s.UploaderPublicKey,
		s.Filename,
		s.ContentType,
		s.SizeBytes,
		s.StoragePath,
		s.ThumbnailPath,
		s.Width,
		s.Height,
		s.DurationMs,
		s.Checksum,
		s.CreatedAt,
		s.Status,
	)
	return err
}

func (r *Repository) GetByID(id string) (*Storage, error) {
	query := `SELECT id, application_id, uploader_public_key, filename, content_type, size_bytes, storage_path, thumbnail_path, width, height, duration_ms, checksum, created_at, status
			  FROM storage WHERE id = $1`

	s := &Storage{}
	var applicationID sql.NullString
	var thumbnailPath sql.NullString
	var width, height, durationMs sql.NullInt64

	err := r.db.QueryRow(query, id).Scan(
		&s.ID,
		&applicationID,
		&s.UploaderPublicKey,
		&s.Filename,
		&s.ContentType,
		&s.SizeBytes,
		&s.StoragePath,
		&thumbnailPath,
		&width,
		&height,
		&durationMs,
		&s.Checksum,
		&s.CreatedAt,
		&s.Status,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("storage not found")
	}
	if err != nil {
		return nil, err
	}

	if applicationID.Valid {
		s.ApplicationID = &applicationID.String
	}
	populateNullableFields(s, thumbnailPath, width, height, durationMs)
	return s, nil
}

func populateNullableFields(s *Storage, thumbnailPath sql.NullString, width, height, durationMs sql.NullInt64) {
	if thumbnailPath.Valid {
		s.ThumbnailPath = thumbnailPath.String
	}
	if width.Valid {
		w := int(width.Int64)
		s.Width = &w
	}
	if height.Valid {
		h := int(height.Int64)
		s.Height = &h
	}
	if durationMs.Valid {
		d := int(durationMs.Int64)
		s.DurationMs = &d
	}
}

func (r *Repository) GetByApplicationID(appID string) ([]*Storage, error) {
	query := `SELECT id, application_id, uploader_public_key, filename, content_type, size_bytes, storage_path, thumbnail_path, width, height, duration_ms, checksum, created_at, status
			  FROM storage WHERE application_id = $1 ORDER BY created_at DESC`

	rows, err := r.db.Query(query, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var storageList []*Storage
	for rows.Next() {
		s := &Storage{}
		var applicationID sql.NullString
		var thumbnailPath sql.NullString
		var width, height, durationMs sql.NullInt64

		err := rows.Scan(
			&s.ID,
			&applicationID,
			&s.UploaderPublicKey,
			&s.Filename,
			&s.ContentType,
			&s.SizeBytes,
			&s.StoragePath,
			&thumbnailPath,
			&width,
			&height,
			&durationMs,
			&s.Checksum,
			&s.CreatedAt,
			&s.Status,
		)
		if err != nil {
			return nil, err
		}

		if applicationID.Valid {
			s.ApplicationID = &applicationID.String
		}
		populateNullableFields(s, thumbnailPath, width, height, durationMs)
		storageList = append(storageList, s)
	}

	return storageList, rows.Err()
}

func (r *Repository) GetPersonalByUploader(publicKey string) ([]*Storage, error) {
	rows, err := r.db.Query(`SELECT id, storage_path, thumbnail_path FROM storage
		WHERE uploader_public_key = $1 AND application_id IS NULL`, publicKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*Storage
	for rows.Next() {
		s := &Storage{}
		var thumbnailPath sql.NullString
		if err := rows.Scan(&s.ID, &s.StoragePath, &thumbnailPath); err != nil {
			return nil, err
		}
		s.ThumbnailPath = thumbnailPath.String
		list = append(list, s)
	}
	return list, rows.Err()
}

func (r *Repository) UpdateStatus(id, status string) error {
	return r.execWithRowCheck(`UPDATE storage SET status = $1 WHERE id = $2`, status, id)
}

func (r *Repository) UpdateThumbnail(id, thumbnailPath string) error {
	return r.execWithRowCheck(`UPDATE storage SET thumbnail_path = $1 WHERE id = $2`, thumbnailPath, id)
}

func (r *Repository) UpdateDimensions(id string, width, height int) error {
	return r.execWithRowCheck(`UPDATE storage SET width = $1, height = $2 WHERE id = $3`, width, height, id)
}

func (r *Repository) Delete(id string) error {
	return r.execWithRowCheck(`DELETE FROM storage WHERE id = $1`, id)
}

func (r *Repository) DeleteByApplicationID(appID string) error {
	_, err := r.db.Exec(`DELETE FROM storage WHERE application_id = $1`, appID)
	return err
}

func (r *Repository) execWithRowCheck(query string, args ...interface{}) error {
	result, err := r.db.Exec(query, args...)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("storage not found")
	}

	return nil
}

func (r *Repository) CreateChunk(chunk *StorageChunk) error {
	query := `INSERT INTO storage_chunks (storage_id, chunk_index, chunk_size, checksum, uploaded_at)
			  VALUES ($1, $2, $3, $4, $5)
			  ON CONFLICT (storage_id, chunk_index) DO UPDATE SET
			  chunk_size = EXCLUDED.chunk_size,
			  checksum = EXCLUDED.checksum,
			  uploaded_at = EXCLUDED.uploaded_at`

	_, err := r.db.Exec(query, chunk.StorageID, chunk.ChunkIndex, chunk.ChunkSize, chunk.Checksum, chunk.UploadedAt)
	return err
}

func (r *Repository) GetChunks(storageID string) ([]*StorageChunk, error) {
	query := `SELECT storage_id, chunk_index, chunk_size, checksum, uploaded_at
			  FROM storage_chunks WHERE storage_id = $1 ORDER BY chunk_index`

	rows, err := r.db.Query(query, storageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var chunks []*StorageChunk
	for rows.Next() {
		chunk := &StorageChunk{}
		err := rows.Scan(&chunk.StorageID, &chunk.ChunkIndex, &chunk.ChunkSize, &chunk.Checksum, &chunk.UploadedAt)
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, chunk)
	}

	return chunks, rows.Err()
}

func (r *Repository) DeleteChunks(storageID string) error {
	query := `DELETE FROM storage_chunks WHERE storage_id = $1`
	_, err := r.db.Exec(query, storageID)
	return err
}

// DeleteStalePending deletes storage rows with status='pending' older than
// olderThanSeconds seconds (Unix timestamp cutoff). It first deletes orphaned
// storage_chunks rows because storage_chunks has no FK cascade back to storage.
// Returns the number of storage rows deleted.
//
// SQL executed (both inside a single transaction):
//
//	DELETE FROM storage_chunks
//	WHERE storage_id IN (
//	    SELECT id FROM storage
//	    WHERE status = 'pending' AND created_at < $1
//	)
//
//	DELETE FROM storage
//	WHERE status = 'pending' AND created_at < $1
//
// NOTE: the unit test (TestCleanupPending_MockWiring) covers service wiring only,
// not these SQL statements. Add an integration test if the SQL is ever changed.
func (r *Repository) DeleteStalePending(olderThanSeconds int64) (int, error) {
	tx, err := r.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck

	// Delete chunks for stale pending rows first (no FK cascade on storage_chunks).
	_, err = tx.Exec(`
		DELETE FROM storage_chunks
		WHERE storage_id IN (
			SELECT id FROM storage
			WHERE status = 'pending' AND created_at < $1
		)`, olderThanSeconds)
	if err != nil {
		return 0, err
	}

	result, err := tx.Exec(`
		DELETE FROM storage
		WHERE status = 'pending' AND created_at < $1`, olderThanSeconds)
	if err != nil {
		return 0, err
	}

	n, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(n), nil
}

// Ids appear as bare strings, as storage:<id> icons and as /storage/<id> URLs
// inside Quill deltas, so match by substring: it can only err toward keeping.
// ponytail: O(storage rows x text) seq scan, fine for personal spaces; upgrade
// to an in-Go scan or re-verify only rows near the cutoff if it gets slow.
const referencedPredicate = `(EXISTS (SELECT 1 FROM components c WHERE strpos(c.data, s.id) > 0)
	OR EXISTS (SELECT 1 FROM events e WHERE strpos(e.data, s.id) > 0)
	OR EXISTS (SELECT 1 FROM applications a WHERE strpos(a.icon, s.id) > 0)
	OR EXISTS (SELECT 1 FROM users u WHERE u.avatar_storage_id = s.id))`

func (r *Repository) MarkReferenced(ctx context.Context, now int64) error {
	_, err := r.db.ExecContext(ctx, `UPDATE storage s SET last_referenced_at = $1
		WHERE s.status <> 'pending'
		AND (s.last_referenced_at IS NULL OR s.last_referenced_at < $1 - 86400)
		AND `+referencedPredicate, now)
	return err
}

// DeleteUnreferenced deletes up to limit rows whose last reference is older than
// cutoff and returns them so the caller can remove their blobs. The NOT
// referenced re-check in the DELETE guards against a reference that landed
// after the subquery picked the row.
func (r *Repository) DeleteUnreferenced(ctx context.Context, cutoff int64, limit int) ([]*Storage, error) {
	rows, err := r.db.QueryContext(ctx, `DELETE FROM storage AS s
		WHERE s.id IN (
			SELECT id FROM storage
			WHERE status <> 'pending' AND COALESCE(last_referenced_at, created_at) < $1
			ORDER BY created_at LIMIT $2)
		AND NOT `+referencedPredicate+`
		RETURNING s.id, s.storage_path, s.thumbnail_path`, cutoff, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deleted []*Storage
	for rows.Next() {
		s := &Storage{}
		var thumbnailPath sql.NullString
		if err := rows.Scan(&s.ID, &s.StoragePath, &thumbnailPath); err != nil {
			return nil, err
		}
		s.ThumbnailPath = thumbnailPath.String
		deleted = append(deleted, s)
	}
	return deleted, rows.Err()
}

// GetUsedBytesByUploader counts every row of the uploader in any status,
// including files of soft-deleted apps, whose bytes stay on disk until purge.
func (r *Repository) GetUsedBytesByUploader(publicKey string) (int64, error) {
	var total int64
	err := r.db.QueryRow(`SELECT COALESCE(SUM(size_bytes), 0) FROM storage WHERE uploader_public_key = $1`, publicKey).Scan(&total)
	if err != nil {
		return 0, err
	}
	return total, nil
}

func (r *Repository) GetTotalUsedBytes() (int64, error) {
	var total sql.NullInt64
	err := r.db.QueryRow(`SELECT COALESCE(SUM(size_bytes), 0) FROM storage`).Scan(&total)
	if err != nil {
		return 0, err
	}
	return total.Int64, nil
}
