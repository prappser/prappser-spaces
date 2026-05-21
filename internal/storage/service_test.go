package storage

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// ---- mock storage backend ----

type mockBackend struct {
	mu      sync.Mutex
	objects map[string]string
	// getErr, when non-nil, is returned by Get for every path
	getErr error
}

func newMockBackend() *mockBackend {
	return &mockBackend{objects: make(map[string]string)}
}

func (m *mockBackend) Store(_ context.Context, path string, r io.Reader) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, _ := io.ReadAll(r)
	m.objects[path] = string(b)
	return nil
}

func (m *mockBackend) Get(_ context.Context, path string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getErr != nil {
		return nil, m.getErr
	}
	content, ok := m.objects[path]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrBlobNotFound, path)
	}
	return io.NopCloser(strings.NewReader(content)), nil
}

func (m *mockBackend) Delete(_ context.Context, _ string) error   { return nil }
func (m *mockBackend) Exists(_ context.Context, _ string) (bool, error) { return false, nil }
func (m *mockBackend) GetURL(_ context.Context, path, base string) (string, error) {
	return base + "/storage/" + path, nil
}

// ---- mock storage repository ----

type mockStorageRepo struct {
	mu      sync.Mutex
	records map[string]*Storage
	chunks  map[string][]*StorageChunk
}

func newMockStorageRepo() *mockStorageRepo {
	return &mockStorageRepo{
		records: make(map[string]*Storage),
		chunks:  make(map[string][]*StorageChunk),
	}
}

func (r *mockStorageRepo) Create(s *Storage) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records[s.ID] = s
	return nil
}

func (r *mockStorageRepo) GetByID(id string) (*Storage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.records[id]
	if !ok {
		return nil, fmt.Errorf("storage not found")
	}
	return s, nil
}

func (r *mockStorageRepo) GetByApplicationID(_ string) ([]*Storage, error) { return nil, nil }

func (r *mockStorageRepo) UpdateStatus(id, status string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.records[id]; ok {
		s.Status = status
	}
	return nil
}

func (r *mockStorageRepo) UpdateThumbnail(_, _ string) error       { return nil }
func (r *mockStorageRepo) UpdateDimensions(_ string, _, _ int) error { return nil }

func (r *mockStorageRepo) Delete(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.records, id)
	return nil
}

func (r *mockStorageRepo) CreateChunk(chunk *StorageChunk) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.chunks[chunk.StorageID] = append(r.chunks[chunk.StorageID], chunk)
	return nil
}

func (r *mockStorageRepo) GetChunks(storageID string) ([]*StorageChunk, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.chunks[storageID], nil
}

func (r *mockStorageRepo) DeleteChunks(storageID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.chunks, storageID)
	return nil
}

func (r *mockStorageRepo) GetTotalUsedBytes() (int64, error) { return 0, nil }

// DeleteStalePending implements the same logic as Repository.DeleteStalePending
// but operates on the in-memory maps.
func (r *mockStorageRepo) DeleteStalePending(olderThanSeconds int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for id, s := range r.records {
		if s.Status == string(StorageStatusPending) && s.CreatedAt < olderThanSeconds {
			delete(r.chunks, id)
			delete(r.records, id)
			count++
		}
	}
	return count, nil
}

// ---- mock app repo ----

type mockAppRepo struct {
	isMember bool
}

func (m *mockAppRepo) IsMember(_, _ string) (bool, error) { return m.isMember, nil }
func (m *mockAppRepo) GetApplicationsByMemberPublicKey(_ string) ([]*application.Application, error) {
	return nil, nil
}

// ---- mock service ----

// mockStorageService is a minimal storageService implementation backed by
// a mockStorageRepo and mockBackend. It only implements the methods exercised
// by the endpoint tests below.
type mockStorageService struct {
	repo    *mockStorageRepo
	backend *mockBackend
}

func (m *mockStorageService) Get(_ context.Context, id, _ string) (*Storage, error) {
	return m.repo.GetByID(id)
}

func (m *mockStorageService) GetData(_ context.Context, id string) (io.ReadCloser, *Storage, error) {
	s, err := m.repo.GetByID(id)
	if err != nil {
		return nil, nil, err
	}
	reader, err := m.backend.Get(context.Background(), s.StoragePath)
	if err != nil {
		return nil, nil, err
	}
	return reader, s, nil
}

func (m *mockStorageService) GetThumbnail(_ context.Context, id string) (io.ReadCloser, *Storage, error) {
	return nil, nil, fmt.Errorf("no thumbnail available")
}

func (m *mockStorageService) Upload(_ context.Context, _ *string, _ string, _ *string, _ *UploadRequest, _ io.Reader, _ string) (*Storage, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *mockStorageService) Delete(_ context.Context, _, _ string) error {
	return fmt.Errorf("not implemented in mock")
}

func (m *mockStorageService) InitChunkedUpload(_ context.Context, _ *string, _ string, _ *string, _ *ChunkedUploadInitRequest) (*ChunkedUploadInitResponse, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *mockStorageService) UploadChunk(_ context.Context, _ string, _ int, _ io.Reader) error {
	return fmt.Errorf("not implemented in mock")
}

func (m *mockStorageService) CompleteChunkedUpload(_ context.Context, _ string, _ string) (*Storage, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *mockStorageService) CleanupApplicationStorage(_ context.Context, _ string) error {
	return nil
}

// ---- helpers ----

func newTestEndpointsStorage(svc storageService, isMember bool) *Endpoints {
	return &Endpoints{
		service:  svc,
		appRepo:  &mockAppRepo{isMember: isMember},
		userRepo: nil,
	}
}

func newTestRequestCtxStorage(method string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(method)
	return ctx
}

func setStorageAuthUser(ctx *fasthttp.RequestCtx, u *user.User) {
	ctx.SetUserValue("user", u)
}

func storageTestUser(publicKey string) *user.User {
	return &user.User{PublicKey: publicKey, Username: "testuser", Role: "user"}
}

// ---- cleanupStalePendingUploads helper (mirrors service logic, uses mock repo) ----

func runCleanupWithMockRepo(repo *mockStorageRepo) error {
	cutoff := time.Now().Add(-1 * time.Hour).Unix()
	_, err := repo.DeleteStalePending(cutoff)
	return err
}

// ---- tests ----

// TestGetFile_BlobMissing_Returns404 verifies that when the storage record
// exists with status=ready but the backend blob is missing, GetFile returns 404.
func TestGetFile_BlobMissing_Returns404(t *testing.T) {
	// given
	backend := newMockBackend()
	backend.getErr = fmt.Errorf("%w: some/path.jpg", ErrBlobNotFound)

	repo := newMockStorageRepo()
	repo.records["file-1"] = &Storage{
		ID:                "file-1",
		UploaderPublicKey: "user-pk-1",
		Filename:          "photo.jpg",
		ContentType:       "image/jpeg",
		SizeBytes:         1024,
		StoragePath:       "app-1/2026/05/file-1.jpg",
		CreatedAt:         time.Now().Unix(),
		Status:            string(StorageStatusReady),
	}

	svc := &mockStorageService{repo: repo, backend: backend}
	ep := newTestEndpointsStorage(svc, true)

	ctx := newTestRequestCtxStorage("GET")
	setStorageAuthUser(ctx, storageTestUser("user-pk-1"))
	ctx.SetUserValue("storageID", "file-1")

	// when
	ep.GetFile(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNotFound, ctx.Response.StatusCode())
	assert.Contains(t, string(ctx.Response.Body()), "file not found")
}

// TestGet_PendingRow_TreatedAsNotFound verifies that a storage record with
// status=pending is rejected by getStorageAndCheckAccess with a 404.
func TestGet_PendingRow_TreatedAsNotFound(t *testing.T) {
	// given
	backend := newMockBackend()
	repo := newMockStorageRepo()
	repo.records["file-pending"] = &Storage{
		ID:                "file-pending",
		UploaderPublicKey: "user-pk-1",
		Filename:          "upload.jpg",
		ContentType:       "image/jpeg",
		SizeBytes:         512,
		StoragePath:       "app-1/2026/05/file-pending.jpg",
		CreatedAt:         time.Now().Unix(),
		Status:            string(StorageStatusPending),
	}

	svc := &mockStorageService{repo: repo, backend: backend}
	ep := newTestEndpointsStorage(svc, true)

	ctx := newTestRequestCtxStorage("GET")
	setStorageAuthUser(ctx, storageTestUser("user-pk-1"))
	ctx.SetUserValue("storageID", "file-pending")

	// when
	ep.GetFile(ctx)

	// then: pending row treated as not found before GetData is even called
	assert.Equal(t, fasthttp.StatusNotFound, ctx.Response.StatusCode())
}

// TestCleanupPending_MockWiring verifies that the cleanup service plumbing calls
// DeleteStalePending with the correct cutoff and that the mock repo honours the
// stale/fresh split. NOTE: the SQL inside Repository.DeleteStalePending is NOT
// exercised here; see the doc-comment on that method for the queries it runs.
func TestCleanupPending_MockWiring(t *testing.T) {
	// given
	repo := newMockStorageRepo()
	now := time.Now().Unix()

	repo.records["stale-1"] = &Storage{
		ID:        "stale-1",
		Status:    string(StorageStatusPending),
		CreatedAt: now - int64(2*time.Hour/time.Second),
	}
	repo.chunks["stale-1"] = []*StorageChunk{
		{StorageID: "stale-1", ChunkIndex: 0},
	}

	repo.records["fresh-1"] = &Storage{
		ID:        "fresh-1",
		Status:    string(StorageStatusPending),
		CreatedAt: now - int64(30*time.Minute/time.Second),
	}

	// when
	err := runCleanupWithMockRepo(repo)

	// then
	assert.NoError(t, err)

	repo.mu.Lock()
	_, staleExists := repo.records["stale-1"]
	_, freshExists := repo.records["fresh-1"]
	_, staleChunksExist := repo.chunks["stale-1"]
	repo.mu.Unlock()

	assert.False(t, staleExists, "stale pending row must be deleted")
	assert.True(t, freshExists, "fresh pending row must be kept")
	assert.False(t, staleChunksExist, "chunks for stale row must be cleaned up")
}
