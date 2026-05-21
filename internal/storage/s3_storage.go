package storage

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type S3Storage struct {
	client *minio.Client
	bucket string
}

func NewS3Storage(config *BackendConfig) (*S3Storage, error) {
	client, err := minio.New(config.S3Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(config.S3AccessKey, config.S3SecretKey, ""),
		Secure: config.S3UseSSL,
		Region: config.S3Region,
	})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	exists, err := client.BucketExists(ctx, config.S3Bucket)
	if err != nil {
		return nil, err
	}

	if !exists {
		if err := client.MakeBucket(ctx, config.S3Bucket, minio.MakeBucketOptions{Region: config.S3Region}); err != nil {
			return nil, err
		}
	}

	return &S3Storage{
		client: client,
		bucket: config.S3Bucket,
	}, nil
}

func (s *S3Storage) Store(ctx context.Context, path string, reader io.Reader) error {
	_, err := s.client.PutObject(ctx, s.bucket, path, reader, -1, minio.PutObjectOptions{})
	return err
}

func (s *S3Storage) Get(ctx context.Context, path string) (io.ReadCloser, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, path, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}

	_, err = obj.Stat()
	if err != nil {
		errResponse := minio.ToErrorResponse(err)
		if errResponse.Code == "NoSuchKey" {
			return nil, fmt.Errorf("%w: %s", ErrBlobNotFound, path)
		}
		return nil, err
	}

	return obj, nil
}

func (s *S3Storage) Delete(ctx context.Context, path string) error {
	return s.client.RemoveObject(ctx, s.bucket, path, minio.RemoveObjectOptions{})
}

func (s *S3Storage) Exists(ctx context.Context, path string) (bool, error) {
	_, err := s.client.StatObject(ctx, s.bucket, path, minio.StatObjectOptions{})
	if err != nil {
		errResponse := minio.ToErrorResponse(err)
		if errResponse.Code == "NoSuchKey" {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *S3Storage) GetURL(ctx context.Context, path string, _ string) (string, error) {
	presignedURL, err := s.client.PresignedGetObject(ctx, s.bucket, path, time.Hour, nil)
	if err != nil {
		return "", err
	}
	return presignedURL.String(), nil
}
