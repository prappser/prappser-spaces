package storage

import (
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
	query := `INSERT INTO storage (id, application_id, uploader_public_key, filename, content_type, size_bytes, storage_path, thumbnail_path, width, height, duration_ms, checksum, created_at, status)
			  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`

	_, err := r.db.Exec(query,
		s.ID,
		s.ApplicationID,
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

func (r *Repository) GetTotalUsedBytes() (int64, error) {
	var total sql.NullInt64
	err := r.db.QueryRow(`SELECT COALESCE(SUM(size_bytes), 0) FROM storage`).Scan(&total)
	if err != nil {
		return 0, err
	}
	return total.Int64, nil
}
