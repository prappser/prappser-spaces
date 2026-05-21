package storage

import (
	"context"
	"errors"
	"io"
)

// ErrBlobNotFound is returned by StorageBackend.Get when the blob does not exist
// on the storage medium (e.g. file deleted from disk, S3 key missing).
var ErrBlobNotFound = errors.New("blob not found")

type StorageBackend interface {
	Store(ctx context.Context, path string, reader io.Reader) error
	Get(ctx context.Context, path string) (io.ReadCloser, error)
	Delete(ctx context.Context, path string) error
	Exists(ctx context.Context, path string) (bool, error)
	GetURL(ctx context.Context, path string, baseURL string) (string, error)
}

type StorageType string

const (
	StorageTypeLocal StorageType = "local"
	StorageTypeS3    StorageType = "s3"
)

type BackendConfig struct {
	Type        StorageType
	LocalPath   string
	S3Endpoint  string
	S3Bucket    string
	S3AccessKey string
	S3SecretKey string
	S3Region    string
	S3UseSSL    bool
	MaxFileSize int64
	ChunkSize   int64
}

func NewBackend(config *BackendConfig) (StorageBackend, error) {
	switch config.Type {
	case StorageTypeS3:
		return NewS3Storage(config)
	default:
		return NewLocalStorage(config)
	}
}
