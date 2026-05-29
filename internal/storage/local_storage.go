package storage

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
)

type LocalStorage struct {
	basePath string
}

func NewLocalStorage(config *BackendConfig) (*LocalStorage, error) {
	basePath := config.LocalPath
	if basePath == "" {
		basePath = "./storage"
	}

	absPath, _ := filepath.Abs(basePath)
	_, statErr := os.Stat(basePath)
	existedBefore := statErr == nil

	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	// existedBeforeStartup=false + topLevelEntries=0 after redeploy indicates ephemeral (non-persistent) disk
	entryCount := -1
	if entries, err := os.ReadDir(basePath); err == nil {
		entryCount = len(entries)
	}
	log.Info().
		Str("basePath", basePath).
		Str("absolutePath", absPath).
		Bool("existedBeforeStartup", existedBefore).
		Int("topLevelEntries", entryCount).
		Msg("[STORAGE] Local storage backend initialized")

	return &LocalStorage{
		basePath: basePath,
	}, nil
}

func (s *LocalStorage) Store(ctx context.Context, path string, reader io.Reader) error {
	fullPath := filepath.Join(s.basePath, path)
	dir := filepath.Dir(fullPath)

	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.Create(fullPath)
	if err != nil {
		return err
	}
	defer file.Close()

	n, err := io.Copy(file, reader)
	if err != nil {
		os.Remove(fullPath)
		return err
	}
	log.Info().Str("fullPath", fullPath).Int64("bytes", n).Msg("[STORAGE] Local blob stored")

	return nil
}

func (s *LocalStorage) Get(ctx context.Context, path string) (io.ReadCloser, error) {
	fullPath := filepath.Join(s.basePath, path)

	file, err := os.Open(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			_, baseErr := os.Stat(s.basePath)
			log.Warn().
				Str("requestedPath", path).
				Str("fullPath", fullPath).
				Bool("basePathExists", baseErr == nil).
				Msg("[STORAGE] Local blob not found")
			return nil, fmt.Errorf("%w: %s", ErrBlobNotFound, path)
		}
		return nil, err
	}

	return file, nil
}

func (s *LocalStorage) Delete(ctx context.Context, path string) error {
	fullPath := filepath.Join(s.basePath, path)

	if err := os.Remove(fullPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

func (s *LocalStorage) Exists(ctx context.Context, path string) (bool, error) {
	fullPath := filepath.Join(s.basePath, path)

	_, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (s *LocalStorage) GetURL(ctx context.Context, path string, baseURL string) (string, error) {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	storageID := strings.TrimSuffix(base, ext)
	return fmt.Sprintf("%s/storage/%s", baseURL, storageID), nil
}
