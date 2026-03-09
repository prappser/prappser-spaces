package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/disintegration/imaging"
	"github.com/rs/zerolog/log"
)

const (
	maxThumbnailWidth  = 300
	maxThumbnailHeight = 300
)

var allowedContentTypes = map[string]bool{
	"image/jpeg": true,
	"image/png":  true,
	"image/gif":  true,
	"image/webp": true,
	"video/mp4":  true,
	"video/webm": true,
	"video/mov":  true,
}

type Service struct {
	repo        *Repository
	backend     StorageBackend
	maxFileSize int64
	externalURL string
}

func NewService(repo *Repository, backend StorageBackend, maxFileSize int64, externalURL string) *Service {
	if maxFileSize <= 0 {
		maxFileSize = 500 * 1024 * 1024
	}
	return &Service{
		repo:        repo,
		backend:     backend,
		maxFileSize: maxFileSize,
		externalURL: externalURL,
	}
}

func (s *Service) ExternalURL() string {
	return s.externalURL
}

func (s *Service) Upload(ctx context.Context, appID *string, uploaderPublicKey string, req *UploadRequest, data io.Reader) (*Storage, error) {
	if !allowedContentTypes[req.ContentType] {
		return nil, fmt.Errorf("unsupported content type: %s", req.ContentType)
	}

	if req.SizeBytes > s.maxFileSize {
		return nil, fmt.Errorf("file too large: %d bytes (max: %d)", req.SizeBytes, s.maxFileSize)
	}

	buf := &bytes.Buffer{}
	hasher := sha256.New()
	writer := io.MultiWriter(buf, hasher)

	n, err := io.CopyN(writer, data, s.maxFileSize+1)
	if err != nil && err != io.EOF {
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
	}

	if strings.HasPrefix(req.ContentType, "image/") {
		s.processImage(ctx, stored, buf.Bytes())
	}

	if err := s.repo.Create(stored); err != nil {
		s.backend.Delete(ctx, storagePath)
		return nil, fmt.Errorf("failed to save storage record: %w", err)
	}

	s.populateURLs(ctx, stored)
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

func (s *Service) Get(ctx context.Context, id string) (*Storage, error) {
	stored, err := s.repo.GetByID(id)
	if err != nil {
		return nil, err
	}

	s.populateURLs(ctx, stored)
	return stored, nil
}

func (s *Service) populateURLs(ctx context.Context, stored *Storage) {
	stored.URL, _ = s.backend.GetURL(ctx, stored.StoragePath)
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

func (s *Service) InitChunkedUpload(ctx context.Context, appID *string, uploaderPublicKey string, req *ChunkedUploadInitRequest) (*ChunkedUploadInitResponse, error) {
	if !allowedContentTypes[req.ContentType] {
		return nil, fmt.Errorf("unsupported content type: %s", req.ContentType)
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
	}

	if err := s.repo.Create(stored); err != nil {
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

func (s *Service) CompleteChunkedUpload(ctx context.Context, storageID string) (*Storage, error) {
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

	s.populateURLs(ctx, stored)
	return stored, nil
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
	case "video/mp4":
		return ".mp4"
	case "video/webm":
		return ".webm"
	case "video/mov":
		return ".mov"
	default:
		return ""
	}
}
