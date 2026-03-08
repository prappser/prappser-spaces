package storage

type Storage struct {
	ID                string  `json:"id"`
	ApplicationID     *string `json:"applicationId,omitempty"`
	UploaderPublicKey string  `json:"uploaderPublicKey"`
	Filename          string `json:"filename"`
	ContentType       string `json:"contentType"`
	SizeBytes         int64  `json:"sizeBytes"`
	StoragePath       string `json:"-"`
	ThumbnailPath     string `json:"-"`
	Width             *int   `json:"width,omitempty"`
	Height            *int   `json:"height,omitempty"`
	DurationMs        *int   `json:"durationMs,omitempty"`
	Checksum          string `json:"checksum"`
	CreatedAt         int64  `json:"createdAt"`
	Status            string `json:"status"`
	URL               string `json:"url,omitempty"`
	ThumbnailURL      string `json:"thumbnailUrl,omitempty"`
}

type StorageChunk struct {
	StorageID  string `json:"storageId"`
	ChunkIndex int    `json:"chunkIndex"`
	ChunkSize  int64  `json:"chunkSize"`
	Checksum   string `json:"checksum"`
	UploadedAt int64  `json:"uploadedAt"`
}

type StorageStatus string

const (
	StorageStatusPending  StorageStatus = "pending"
	StorageStatusUploaded StorageStatus = "uploaded"
	StorageStatusReady    StorageStatus = "ready"
	StorageStatusFailed   StorageStatus = "failed"
)

type UploadRequest struct {
	ID          string `json:"id"`
	Filename    string `json:"filename"`
	ContentType string `json:"contentType"`
	SizeBytes   int64  `json:"sizeBytes"`
	Checksum    string `json:"checksum"`
}

type ChunkedUploadInitRequest struct {
	ID          string `json:"id"`
	Filename    string `json:"filename"`
	ContentType string `json:"contentType"`
	TotalSize   int64  `json:"totalSize"`
	ChunkSize   int64  `json:"chunkSize"`
	TotalChunks int    `json:"totalChunks"`
	Checksum    string `json:"checksum"`
}

type ChunkedUploadInitResponse struct {
	StorageID   string `json:"storageId"`
	UploadedAt  int64  `json:"uploadedAt"`
	StoragePath string `json:"-"`
}

type StorageResponse struct {
	ID           string `json:"id"`
	URL          string `json:"url"`
	ThumbnailURL string `json:"thumbnailUrl,omitempty"`
	ContentType  string `json:"contentType"`
	SizeBytes    int64  `json:"sizeBytes"`
	Checksum     string `json:"checksum"`
}
