package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"mime"
	"path/filepath"
	"strings"
	"time"

	"github.com/disintegration/imaging"
	"github.com/lib/pq"
	"github.com/rs/zerolog/log"
)

const (
	maxThumbnailWidth  = 300
	maxThumbnailHeight = 300

	pqUniqueViolation = "23505"

	// maxContentTypeLength caps the stored content type; the DB column is
	// unbounded TEXT, so this is an app-level sanity limit, not a schema one.
	maxContentTypeLength = 255
)

// isValidContentType reports whether contentType is a well-formed, single-line
// media type, safe to persist and later reflect verbatim into a response
// header (see GetFile's ctx.SetContentType). mime.ParseMediaType alone
// already rejects a CRLF-injected value; the explicit control-byte scan
// below is defense in depth against one, independent of the stdlib grammar.
func isValidContentType(contentType string) bool {
	if contentType == "" || len(contentType) > maxContentTypeLength {
		return false
	}
	for i := 0; i < len(contentType); i++ {
		if b := contentType[i]; b < 0x20 || b == 0x7f {
			return false
		}
	}
	_, _, err := mime.ParseMediaType(contentType)
	return err == nil
}

type Service struct {
	repo        *Repository
	backend     StorageBackend
	maxFileSize int64
}

func NewService(repo *Repository, backend StorageBackend, maxFileSize int64) *Service {
	if maxFileSize <= 0 {
		maxFileSize = 500 * 1024 * 1024
	}
	return &Service{
		repo:        repo,
		backend:     backend,
		maxFileSize: maxFileSize,
	}
}

// Upload no longer gates on a content-type allowlist: req.ContentType is
// client-supplied (see endpoints.go), so the allowlist never validated the
// actual bytes and was never a content-integrity control. Serving hardens
// against it instead (see GetFile's inlineContentTypes). isValidContentType
// below replaces the shape validation the allowlist provided incidentally.
func (s *Service) Upload(ctx context.Context, appID *string, uploaderPublicKey string, spaceID *string, req *UploadRequest, data io.Reader, baseURL string) (*Storage, error) {
	if !isValidContentType(req.ContentType) {
		return nil, fmt.Errorf("invalid content type: %q", req.ContentType)
	}
	if req.SizeBytes > s.maxFileSize {
		return nil, fmt.Errorf("file too large: %d bytes (max: %d)", req.SizeBytes, s.maxFileSize)
	}

	buf := &bytes.Buffer{}
	hasher := sha256.New()
	writer := io.MultiWriter(buf, hasher)

	n, err := io.CopyN(writer, data, s.maxFileSize+1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}
	if n > s.maxFileSize {
		return nil, fmt.Errorf("file too large: exceeds %d bytes", s.maxFileSize)
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))
	if req.Checksum != "" && checksum != req.Checksum {
		return nil, fmt.Errorf("checksum mismatch: expected %s, got %s", req.Checksum, checksum)
	}

	now := time.Now()
	storagePath := buildStoragePath(appID, req.ID, req.Filename, req.ContentType, now)

	if err := s.backend.Store(ctx, storagePath, bytes.NewReader(buf.Bytes())); err != nil {
		return nil, fmt.Errorf("failed to store file: %w", err)
	}

	stored := &Storage{
		ID:                req.ID,
		ApplicationID:     appID,
		UploaderPublicKey: uploaderPublicKey,
		Filename:          req.Filename,
		ContentType:       req.ContentType,
		SizeBytes:         n,
		StoragePath:       storagePath,
		Checksum:          checksum,
		CreatedAt:         now.Unix(),
		Status:            string(StorageStatusReady),
		SpaceID:           spaceID,
	}

	if err := s.repo.Create(stored); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == pqUniqueViolation {
			s.backend.Delete(ctx, storagePath)
			existing, err := s.repo.GetByID(req.ID)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch existing storage record: %w", err)
			}
			s.populateURLs(ctx, existing, baseURL)
			return existing, nil
		}
		s.backend.Delete(ctx, storagePath)
		return nil, fmt.Errorf("failed to save storage record: %w", err)
	}

	if strings.HasPrefix(req.ContentType, "image/") {
		s.processImage(ctx, stored, buf.Bytes())
		if stored.Width != nil && stored.Height != nil {
			s.repo.UpdateDimensions(stored.ID, *stored.Width, *stored.Height)
		}
		if stored.ThumbnailPath != "" {
			s.repo.UpdateThumbnail(stored.ID, stored.ThumbnailPath)
		}
	}

	s.populateURLs(ctx, stored, baseURL)
	return stored, nil
}

func (s *Service) generateThumbnail(ctx context.Context, stored *Storage, data []byte) error {
	img, err := imaging.Decode(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to decode image for thumbnail: %w", err)
	}

	thumb := imaging.Fit(img, maxThumbnailWidth, maxThumbnailHeight, imaging.Lanczos)

	var thumbBuf bytes.Buffer
	if err := imaging.Encode(&thumbBuf, thumb, imaging.JPEG, imaging.JPEGQuality(80)); err != nil {
		return fmt.Errorf("failed to encode thumbnail: %w", err)
	}

	ext := "_thumb.jpg"
	basePath := strings.TrimSuffix(stored.StoragePath, filepath.Ext(stored.StoragePath))
	thumbnailPath := basePath + ext

	if err := s.backend.Store(ctx, thumbnailPath, &thumbBuf); err != nil {
		return fmt.Errorf("failed to store thumbnail: %w", err)
	}

	stored.ThumbnailPath = thumbnailPath
	return nil
}

func (s *Service) Get(ctx context.Context, id string, baseURL string) (*Storage, error) {
	stored, err := s.repo.GetByID(id)
	if err != nil {
		return nil, err
	}

	s.populateURLs(ctx, stored, baseURL)
	return stored, nil
}

func (s *Service) populateURLs(ctx context.Context, stored *Storage, baseURL string) {
	stored.URL, _ = s.backend.GetURL(ctx, stored.StoragePath, baseURL)
	if stored.ThumbnailPath != "" {
		stored.ThumbnailURL = stored.URL + "/thumb"
	}
}

func (s *Service) GetData(ctx context.Context, id string) (io.ReadCloser, *Storage, error) {
	stored, err := s.repo.GetByID(id)
	if err != nil {
		return nil, nil, err
	}

	reader, err := s.backend.Get(ctx, stored.StoragePath)
	if err != nil {
		return nil, nil, err
	}

	return reader, stored, nil
}

func (s *Service) GetThumbnail(ctx context.Context, id string) (io.ReadCloser, *Storage, error) {
	stored, err := s.repo.GetByID(id)
	if err != nil {
		return nil, nil, err
	}

	if stored.ThumbnailPath == "" {
		return nil, nil, fmt.Errorf("no thumbnail available")
	}

	reader, err := s.backend.Get(ctx, stored.ThumbnailPath)
	if err != nil {
		return nil, nil, err
	}

	return reader, stored, nil
}

func (s *Service) Delete(ctx context.Context, id, requestorPublicKey string) error {
	stored, err := s.repo.GetByID(id)
	if err != nil {
		return err
	}

	if stored.UploaderPublicKey != requestorPublicKey {
		return fmt.Errorf("not authorized to delete this file")
	}

	if err := s.backend.Delete(ctx, stored.StoragePath); err != nil {
		log.Warn().Err(err).Str("path", stored.StoragePath).Msg("Failed to delete storage file")
	}

	if stored.ThumbnailPath != "" {
		if err := s.backend.Delete(ctx, stored.ThumbnailPath); err != nil {
			log.Warn().Err(err).Str("path", stored.ThumbnailPath).Msg("Failed to delete thumbnail")
		}
	}

	return s.repo.Delete(id)
}

func (s *Service) CleanupApplicationStorage(ctx context.Context, appID string) error {
	storageList, err := s.repo.GetByApplicationID(appID)
	if err != nil {
		return err
	}

	for _, stored := range storageList {
		if err := s.backend.Delete(ctx, stored.StoragePath); err != nil {
			log.Warn().Err(err).Str("path", stored.StoragePath).Msg("Failed to delete storage file during cleanup")
		}
		if stored.ThumbnailPath != "" {
			if err := s.backend.Delete(ctx, stored.ThumbnailPath); err != nil {
				log.Warn().Err(err).Str("path", stored.ThumbnailPath).Msg("Failed to delete thumbnail during cleanup")
			}
		}
	}

	return nil
}

// See Upload's doc-comment: no content-type allowlist here either, so the
// same isValidContentType gate applies.
func (s *Service) InitChunkedUpload(ctx context.Context, appID *string, uploaderPublicKey string, spaceID *string, req *ChunkedUploadInitRequest) (*ChunkedUploadInitResponse, error) {
	if !isValidContentType(req.ContentType) {
		return nil, fmt.Errorf("invalid content type: %q", req.ContentType)
	}
	if req.TotalSize > s.maxFileSize {
		return nil, fmt.Errorf("file too large: %d bytes (max: %d)", req.TotalSize, s.maxFileSize)
	}

	now := time.Now()
	storagePath := buildStoragePath(appID, req.ID, req.Filename, req.ContentType, now)

	stored := &Storage{
		ID:                req.ID,
		ApplicationID:     appID,
		UploaderPublicKey: uploaderPublicKey,
		Filename:          req.Filename,
		ContentType:       req.ContentType,
		SizeBytes:         req.TotalSize,
		StoragePath:       storagePath,
		Checksum:          req.Checksum,
		CreatedAt:         now.Unix(),
		Status:            string(StorageStatusPending),
		SpaceID:           spaceID,
	}

	if err := s.repo.Create(stored); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == pqUniqueViolation {
			return nil, fmt.Errorf("chunked upload already initialized for storage ID: %s", req.ID)
		}
		return nil, fmt.Errorf("failed to create storage record: %w", err)
	}

	return &ChunkedUploadInitResponse{
		StorageID:   req.ID,
		UploadedAt:  now.Unix(),
		StoragePath: storagePath,
	}, nil
}

func (s *Service) UploadChunk(ctx context.Context, storageID string, chunkIndex int, data io.Reader) error {
	stored, err := s.repo.GetByID(storageID)
	if err != nil {
		return err
	}

	if stored.Status != string(StorageStatusPending) {
		return fmt.Errorf("cannot upload chunks for storage in status: %s", stored.Status)
	}

	buf := &bytes.Buffer{}
	hasher := sha256.New()
	writer := io.MultiWriter(buf, hasher)

	n, err := io.Copy(writer, data)
	if err != nil {
		return fmt.Errorf("failed to read chunk data: %w", err)
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))

	chunkPath := fmt.Sprintf("%s.chunk.%d", stored.StoragePath, chunkIndex)
	if err := s.backend.Store(ctx, chunkPath, bytes.NewReader(buf.Bytes())); err != nil {
		return fmt.Errorf("failed to store chunk: %w", err)
	}

	chunk := &StorageChunk{
		StorageID:  storageID,
		ChunkIndex: chunkIndex,
		ChunkSize:  n,
		Checksum:   checksum,
		UploadedAt: time.Now().Unix(),
	}

	return s.repo.CreateChunk(chunk)
}

func (s *Service) CompleteChunkedUpload(ctx context.Context, storageID string, baseURL string) (*Storage, error) {
	stored, err := s.repo.GetByID(storageID)
	if err != nil {
		return nil, err
	}

	if stored.Status != string(StorageStatusPending) {
		return nil, fmt.Errorf("cannot complete upload for storage in status: %s", stored.Status)
	}

	chunks, err := s.repo.GetChunks(storageID)
	if err != nil {
		return nil, err
	}

	if len(chunks) == 0 {
		return nil, fmt.Errorf("no chunks uploaded")
	}

	var combined bytes.Buffer
	hasher := sha256.New()
	writer := io.MultiWriter(&combined, hasher)

	for i, chunk := range chunks {
		if chunk.ChunkIndex != i {
			return nil, fmt.Errorf("missing chunk at index %d", i)
		}

		chunkPath := fmt.Sprintf("%s.chunk.%d", stored.StoragePath, i)
		reader, err := s.backend.Get(ctx, chunkPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read chunk %d: %w", i, err)
		}

		if _, err := io.Copy(writer, reader); err != nil {
			reader.Close()
			return nil, fmt.Errorf("failed to combine chunk %d: %w", i, err)
		}
		reader.Close()
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))
	if stored.Checksum != "" && checksum != stored.Checksum {
		return nil, fmt.Errorf("checksum mismatch: expected %s, got %s", stored.Checksum, checksum)
	}

	if err := s.backend.Store(ctx, stored.StoragePath, bytes.NewReader(combined.Bytes())); err != nil {
		return nil, fmt.Errorf("failed to store combined file: %w", err)
	}

	for _, chunk := range chunks {
		chunkPath := fmt.Sprintf("%s.chunk.%d", stored.StoragePath, chunk.ChunkIndex)
		s.backend.Delete(ctx, chunkPath)
	}

	s.repo.DeleteChunks(storageID)

	if strings.HasPrefix(stored.ContentType, "image/") {
		s.processImage(ctx, stored, combined.Bytes())
		if stored.Width != nil && stored.Height != nil {
			s.repo.UpdateDimensions(storageID, *stored.Width, *stored.Height)
		}
		if stored.ThumbnailPath != "" {
			s.repo.UpdateThumbnail(storageID, stored.ThumbnailPath)
		}
	}

	stored.SizeBytes = int64(combined.Len())
	stored.Status = string(StorageStatusReady)
	if err := s.repo.UpdateStatus(storageID, string(StorageStatusReady)); err != nil {
		return nil, err
	}

	s.populateURLs(ctx, stored, baseURL)
	return stored, nil
}

// CleanupStalePendingUploads deletes storage rows with status='pending' that
// were created more than 1 hour ago, along with their orphaned chunk rows.
func (s *Service) CleanupStalePendingUploads(ctx context.Context) error {
	cutoff := time.Now().Add(-1 * time.Hour).Unix()
	n, err := s.repo.DeleteStalePending(cutoff)
	if err != nil {
		return err
	}
	log.Info().Int("deletedCount", n).Msg("[STORAGE] Stale pending upload cleanup completed")
	return nil
}

// PendingCleanupScheduler runs CleanupStalePendingUploads on a fixed interval.
type PendingCleanupScheduler struct {
	service  *Service
	interval time.Duration
	ticker   *time.Ticker
	done     chan bool
}

// NewPendingCleanupScheduler creates a scheduler that will run cleanup every interval.
func NewPendingCleanupScheduler(service *Service, interval time.Duration) *PendingCleanupScheduler {
	return &PendingCleanupScheduler{
		service:  service,
		interval: interval,
		done:     make(chan bool),
	}
}

// Start begins the cleanup loop in a background goroutine.
func (p *PendingCleanupScheduler) Start() {
	p.ticker = time.NewTicker(p.interval)
	log.Info().Dur("interval", p.interval).Msg("[STORAGE] Pending upload cleanup scheduler started")
	go p.loop()
}

func (p *PendingCleanupScheduler) loop() {
	for {
		select {
		case <-p.ticker.C:
			if err := p.service.CleanupStalePendingUploads(context.Background()); err != nil {
				log.Error().Err(err).Msg("[STORAGE] Stale pending upload cleanup failed")
			}
		case <-p.done:
			p.ticker.Stop()
			return
		}
	}
}

// Stop halts the cleanup scheduler.
func (p *PendingCleanupScheduler) Stop() {
	log.Info().Msg("[STORAGE] Stopping pending upload cleanup scheduler")
	if p.ticker != nil {
		p.done <- true
	}
}

func buildStoragePath(appID *string, storageID, filename, contentType string, now time.Time) string {
	year := now.Format("2006")
	month := now.Format("01")
	ext := filepath.Ext(filename)
	if ext == "" {
		ext = extensionFromContentType(contentType)
	}
	prefix := "_user"
	if appID != nil {
		prefix = *appID
	}
	return fmt.Sprintf("%s/%s/%s/%s%s", prefix, year, month, storageID, ext)
}

func (s *Service) processImage(ctx context.Context, stored *Storage, data []byte) {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return
	}

	bounds := img.Bounds()
	w := bounds.Dx()
	h := bounds.Dy()
	stored.Width = &w
	stored.Height = &h

	if err := s.generateThumbnail(ctx, stored, data); err != nil {
		log.Warn().Err(err).Str("storageId", stored.ID).Msg("Failed to generate thumbnail")
	}
}

// extensionFromContentType mirrors detectContentType's table in endpoints.go
// (which in turn mirrors the Dart client's), used as a fallback when a
// filename has no extension of its own.
func extensionFromContentType(contentType string) string {
	switch contentType {
	case "image/jpeg":
		return ".jpg"
	case "image/png":
		return ".png"
	case "image/gif":
		return ".gif"
	case "image/webp":
		return ".webp"
	case "image/bmp":
		return ".bmp"
	case "image/svg+xml":
		return ".svg"
	case "video/mp4":
		return ".mp4"
	case "video/webm":
		return ".webm"
	case "video/mov":
		return ".mov"
	case "video/x-msvideo":
		return ".avi"
	case "video/x-matroska":
		return ".mkv"
	case "audio/mpeg":
		return ".mp3"
	case "audio/wav":
		return ".wav"
	case "audio/ogg":
		return ".ogg"
	case "audio/flac":
		return ".flac"
	case "application/pdf":
		return ".pdf"
	case "application/msword":
		return ".doc"
	case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
		return ".docx"
	case "application/vnd.ms-excel":
		return ".xls"
	case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
		return ".xlsx"
	case "application/vnd.ms-powerpoint":
		return ".ppt"
	case "application/vnd.openxmlformats-officedocument.presentationml.presentation":
		return ".pptx"
	case "text/plain":
		return ".txt"
	case "text/csv":
		return ".csv"
	case "application/json":
		return ".json"
	case "application/xml":
		return ".xml"
	case "text/html":
		return ".html"
	case "application/zip":
		return ".zip"
	case "application/x-rar-compressed":
		return ".rar"
	case "application/x-7z-compressed":
		return ".7z"
	default:
		return ""
	}
}
