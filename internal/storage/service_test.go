package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/textproto"
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
	// uploadResult/uploadErr, when either is non-nil, is returned by Upload
	// instead of the "not implemented" default below.
	uploadResult *Storage
	uploadErr    error
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
	if m.uploadResult != nil || m.uploadErr != nil {
		return m.uploadResult, m.uploadErr
	}
	return nil, fmt.Errorf("not implemented in mock")
}

func (m *mockStorageService) Delete(_ context.Context, _, _ string) error {
	return fmt.Errorf("not implemented in mock")
}

// InitChunkedUpload mirrors the real Service's isValidContentType gate and
// persist-on-success behavior, letting endpoint tests drive the actual
// content-type exploit path without a real DB-backed Repository.
func (m *mockStorageService) InitChunkedUpload(_ context.Context, appID *string, uploaderPublicKey string, spaceID *string, req *ChunkedUploadInitRequest) (*ChunkedUploadInitResponse, error) {
	if !isValidContentType(req.ContentType) {
		return nil, fmt.Errorf("invalid content type: %q", req.ContentType)
	}
	stored := &Storage{
		ID:                req.ID,
		ApplicationID:     appID,
		UploaderPublicKey: uploaderPublicKey,
		Filename:          req.Filename,
		ContentType:       req.ContentType,
		SizeBytes:         req.TotalSize,
		StoragePath:       req.ID,
		Checksum:          req.Checksum,
		Status:            string(StorageStatusPending),
		SpaceID:           spaceID,
	}
	if err := m.repo.Create(stored); err != nil {
		return nil, err
	}
	return &ChunkedUploadInitResponse{StorageID: req.ID, StoragePath: stored.StoragePath}, nil
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

// ---- mock user repository (avatar tests only) ----

// mockUserRepoStorage is a no-op user.UserRepository stub: UploadUserAvatar
// only needs UpdateAvatarStorageID to not panic, the rest of the interface
// is never exercised by these tests.
type mockUserRepoStorage struct{}

func (m *mockUserRepoStorage) CreateUser(_ *user.User) error                   { return nil }
func (m *mockUserRepoStorage) GetUserByPublicKey(_ string) (*user.User, error) { return nil, nil }
func (m *mockUserRepoStorage) UpdateUserRole(_, _ string) error                { return nil }
func (m *mockUserRepoStorage) UpdateAvatarStorageID(_ string, _ *string) error { return nil }
func (m *mockUserRepoStorage) UpdateUsername(_, _ string) error                { return nil }
func (m *mockUserRepoStorage) UpdateUserIssuer(_, _ string) error              { return nil }
func (m *mockUserRepoStorage) SetUserIssuer(_, _ string) error                 { return nil }
func (m *mockUserRepoStorage) EnsureDevice(_, _ string, _ *string, _ int64) error {
	return nil
}
func (m *mockUserRepoStorage) GetDevice(_ string) (*user.Device, error)     { return nil, nil }
func (m *mockUserRepoStorage) ListDevices(_ string) ([]*user.Device, error) { return nil, nil }
func (m *mockUserRepoStorage) RevokeDevice(_ string, _ int64) error         { return nil }
func (m *mockUserRepoStorage) RenameDevice(_, _ string) error               { return nil }
func (m *mockUserRepoStorage) TouchDeviceLastSeen(_ string, _ int64) error  { return nil }
func (m *mockUserRepoStorage) SetPasswordCredentials(_, _, _, _, _ string) error {
	return nil
}
func (m *mockUserRepoStorage) GetPasswordCredential(_ string) (string, string, error) {
	return "", "", nil
}
func (m *mockUserRepoStorage) GetPasswordHandle(_ string) (string, error) { return "", nil }
func (m *mockUserRepoStorage) GetEscrow(_ string) (string, string, error) {
	return "", "", nil
}
func (m *mockUserRepoStorage) UpdateUserState(_, _ string) error { return nil }
func (m *mockUserRepoStorage) ClaimOwner(_, _, _, _, _, _ string, _ *string, _ int64) error {
	return nil
}
func (m *mockUserRepoStorage) HasClaim() (bool, error) { return false, nil }

// ---- helpers ----

// newAvatarUploadRequestCtx builds a fasthttp.RequestCtx carrying a real
// multipart/form-data body, since UploadUserAvatar parses the request via
// ctx.MultipartForm() rather than accepting pre-parsed fields.
func newAvatarUploadRequestCtx(t *testing.T, filename, contentType string, fileBytes []byte, storageID string) *fasthttp.RequestCtx {
	t.Helper()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": []string{fmt.Sprintf(`form-data; name="file"; filename="%s"`, filename)},
		"Content-Type":        []string{contentType},
	})
	if err != nil {
		t.Fatalf("failed to create multipart part: %v", err)
	}
	if _, err := part.Write(fileBytes); err != nil {
		t.Fatalf("failed to write multipart part: %v", err)
	}
	if err := w.WriteField("id", storageID); err != nil {
		t.Fatalf("failed to write id field: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close multipart writer: %v", err)
	}

	ctx := newTestRequestCtxStorage("POST")
	ctx.Request.Header.SetContentType(w.FormDataContentType())
	ctx.Request.SetBody(buf.Bytes())
	return ctx
}

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

// TestGetFile_PDF_SetsAttachmentAndNosniff verifies that a content type
// outside the render-safe inline set is served as an attachment, with
// X-Content-Type-Options always set regardless of content type.
func TestGetFile_PDF_SetsAttachmentAndNosniff(t *testing.T) {
	// given
	backend := newMockBackend()
	backend.objects["app-1/2026/05/file-pdf.pdf"] = "pdf bytes"

	repo := newMockStorageRepo()
	repo.records["file-pdf"] = &Storage{
		ID:                "file-pdf",
		UploaderPublicKey: "user-pk-1",
		Filename:          "report.pdf",
		ContentType:       "application/pdf",
		SizeBytes:         9,
		StoragePath:       "app-1/2026/05/file-pdf.pdf",
		CreatedAt:         time.Now().Unix(),
		Status:            string(StorageStatusReady),
	}

	svc := &mockStorageService{repo: repo, backend: backend}
	ep := newTestEndpointsStorage(svc, true)

	ctx := newTestRequestCtxStorage("GET")
	setStorageAuthUser(ctx, storageTestUser("user-pk-1"))
	ctx.SetUserValue("storageID", "file-pdf")

	// when
	ep.GetFile(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Equal(t, "nosniff", string(ctx.Response.Header.Peek("X-Content-Type-Options")))
	assert.Equal(t, `attachment; filename="report.pdf"`, string(ctx.Response.Header.Peek("Content-Disposition")))
}

// TestGetFile_JPEG_SetsInlineDisposition verifies that a content type in the
// render-safe set is still served inline, so previews keep working.
func TestGetFile_JPEG_SetsInlineDisposition(t *testing.T) {
	// given
	backend := newMockBackend()
	backend.objects["app-1/2026/05/file-jpg.jpg"] = "jpeg bytes"

	repo := newMockStorageRepo()
	repo.records["file-jpg"] = &Storage{
		ID:                "file-jpg",
		UploaderPublicKey: "user-pk-1",
		Filename:          "photo.jpg",
		ContentType:       "image/jpeg",
		SizeBytes:         10,
		StoragePath:       "app-1/2026/05/file-jpg.jpg",
		CreatedAt:         time.Now().Unix(),
		Status:            string(StorageStatusReady),
	}

	svc := &mockStorageService{repo: repo, backend: backend}
	ep := newTestEndpointsStorage(svc, true)

	ctx := newTestRequestCtxStorage("GET")
	setStorageAuthUser(ctx, storageTestUser("user-pk-1"))
	ctx.SetUserValue("storageID", "file-jpg")

	// when
	ep.GetFile(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Equal(t, "nosniff", string(ctx.Response.Header.Peek("X-Content-Type-Options")))
	assert.Equal(t, `inline; filename="photo.jpg"`, string(ctx.Response.Header.Peek("Content-Disposition")))
}

// TestSanitizeFilenameForHeader verifies the header-splicing characters are
// stripped from a user-controlled filename before it lands in the response.
func TestSanitizeFilenameForHeader(t *testing.T) {
	got := sanitizeFilenameForHeader("evil\"; x=1\r\nSet-Cookie: a=b\\.txt")
	assert.NotContains(t, got, "\"")
	assert.NotContains(t, got, "\\")
	assert.NotContains(t, got, "\r")
	assert.NotContains(t, got, "\n")
	assert.Equal(t, "evil; x=1Set-Cookie: a=b.txt", got)
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

// TestUploadUserAvatar_RejectsPDF verifies that a PDF avatar upload is
// rejected with 400 before it ever reaches storage or the user repository.
func TestUploadUserAvatar_RejectsPDF(t *testing.T) {
	// given
	svc := &mockStorageService{repo: newMockStorageRepo(), backend: newMockBackend()}
	ep := &Endpoints{
		service:  svc,
		appRepo:  &mockAppRepo{isMember: true},
		userRepo: &mockUserRepoStorage{},
	}

	ctx := newAvatarUploadRequestCtx(t, "malware.pdf", "application/pdf", []byte("%PDF-1.4"), "avatar-1")
	setStorageAuthUser(ctx, storageTestUser("user-pk-1"))

	// when
	ep.UploadUserAvatar(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

// TestUploadUserAvatar_AcceptsPNG verifies that a PNG avatar upload passes
// the content-type gate and completes successfully.
func TestUploadUserAvatar_AcceptsPNG(t *testing.T) {
	// given
	svc := &mockStorageService{
		repo:         newMockStorageRepo(),
		backend:      newMockBackend(),
		uploadResult: &Storage{ID: "avatar-2", ContentType: "image/png", Filename: "avatar.png"},
	}
	ep := &Endpoints{
		service:  svc,
		appRepo:  &mockAppRepo{isMember: true},
		userRepo: &mockUserRepoStorage{},
	}

	ctx := newAvatarUploadRequestCtx(t, "avatar.png", "image/png", []byte("fake png bytes"), "avatar-2")
	setStorageAuthUser(ctx, storageTestUser("user-pk-1"))

	// when
	ep.UploadUserAvatar(ctx)

	// then
	assert.Equal(t, fasthttp.StatusCreated, ctx.Response.StatusCode())
}

// TestDetectContentType_PDF verifies detectContentType recognises the
// document extensions added alongside issue #220.
func TestDetectContentType_PDF(t *testing.T) {
	assert.Equal(t, "application/pdf", detectContentType("report.pdf"))
}

// TestDetectContentType_UnknownExtension_ReturnsOctetStream verifies the
// fallback for a genuinely unrecognised extension is preserved.
func TestDetectContentType_UnknownExtension_ReturnsOctetStream(t *testing.T) {
	assert.Equal(t, "application/octet-stream", detectContentType("mystery.xyz123"))
}

// TestIsValidContentType covers the accept/reject table for the header-
// injection fix (issue #220 follow-up). mime.ParseMediaType itself rejects
// every CRLF/LF payload below, including the control-char-in-quoted-
// parameter case — not only the explicit byte scan.
func TestIsValidContentType(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"CRLF header injection", "text/plain\r\nSet-Cookie: a=b", false},
		{"CRLF blank line then body", "text/plain\r\n\r\ninjected", false},
		{"bare LF", "text/plain\nX: y", false},
		{"plain pdf", "application/pdf", true},
		{"jpeg with charset param", "image/jpeg; charset=utf-8", true},
		{"octet-stream", "application/octet-stream", true},
		{"empty", "", false},
		{"control char in quoted param value", "text/plain; name=\"a\rb\"", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, isValidContentType(c.in))
		})
	}
}

// TestInitChunkedUpload_CRLFContentType_Returns400AndNotPersisted drives the
// exploit path (issue #220 follow-up): a JSON contentType field carrying a
// \r\n escape decodes, via encoding/json, into a literal CRLF that must be
// rejected before the storage row is persisted.
func TestInitChunkedUpload_CRLFContentType_Returns400AndNotPersisted(t *testing.T) {
	// given
	repo := newMockStorageRepo()
	svc := &mockStorageService{repo: repo, backend: newMockBackend()}
	ep := newTestEndpointsStorage(svc, true)

	body := `{"id":"chunked-evil","filename":"a.txt","contentType":"text/plain\r\nSet-Cookie: a=b","totalSize":10,"chunkSize":10,"totalChunks":1}`

	ctx := newTestRequestCtxStorage("POST")
	ctx.QueryArgs().Set("applicationId", "app-1")
	ctx.Request.SetBody([]byte(body))
	setStorageAuthUser(ctx, storageTestUser("user-pk-1"))

	// when
	ep.InitChunkedUpload(ctx)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
	_, err := repo.GetByID("chunked-evil")
	assert.Error(t, err, "rejected upload must not be persisted")
}

// TestGetFile_PoisonedContentType_FallsBackToOctetStream verifies the
// defense-in-depth fallback in GetFile: a row predating the
// isValidContentType gate must not have its content type spliced into the
// response header unvalidated.
func TestGetFile_PoisonedContentType_FallsBackToOctetStream(t *testing.T) {
	// given
	backend := newMockBackend()
	backend.objects["app-1/2026/05/file-evil.bin"] = "data"

	repo := newMockStorageRepo()
	repo.records["file-evil"] = &Storage{
		ID:                "file-evil",
		UploaderPublicKey: "user-pk-1",
		Filename:          "evil.bin",
		ContentType:       "text/plain\r\nSet-Cookie: a=b",
		SizeBytes:         4,
		StoragePath:       "app-1/2026/05/file-evil.bin",
		CreatedAt:         time.Now().Unix(),
		Status:            string(StorageStatusReady),
	}

	svc := &mockStorageService{repo: repo, backend: backend}
	ep := newTestEndpointsStorage(svc, true)

	ctx := newTestRequestCtxStorage("GET")
	setStorageAuthUser(ctx, storageTestUser("user-pk-1"))
	ctx.SetUserValue("storageID", "file-evil")

	// when
	ep.GetFile(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.Equal(t, "application/octet-stream", string(ctx.Response.Header.ContentType()))
}
