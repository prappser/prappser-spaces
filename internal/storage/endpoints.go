package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/httputil"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

// EventService is the interface for producing space-generated events.
type EventService interface {
	ProduceEvent(ctx context.Context, e *event.Event) (*event.Event, error)
}

// storageService is the narrow interface Endpoints needs from *Service.
// The concrete *Service satisfies it; tests inject a mock.
type storageService interface {
	Upload(ctx context.Context, appID *string, uploaderPublicKey string, spaceID *string, req *UploadRequest, data io.Reader, baseURL string) (*Storage, error)
	Get(ctx context.Context, id string, baseURL string) (*Storage, error)
	GetData(ctx context.Context, id string) (io.ReadCloser, *Storage, error)
	GetThumbnail(ctx context.Context, id string) (io.ReadCloser, *Storage, error)
	Delete(ctx context.Context, id, requestorPublicKey string) error
	InitChunkedUpload(ctx context.Context, appID *string, uploaderPublicKey string, spaceID *string, req *ChunkedUploadInitRequest) (*ChunkedUploadInitResponse, error)
	UploadChunk(ctx context.Context, storageID string, chunkIndex int, data io.Reader) error
	CompleteChunkedUpload(ctx context.Context, storageID string, baseURL string) (*Storage, error)
	CleanupApplicationStorage(ctx context.Context, appID string) error
}

// appMemberChecker is the narrow interface Endpoints needs from *application.Repository.
type appMemberChecker interface {
	IsMember(appID, publicKey string) (bool, error)
	GetApplicationsByMemberPublicKey(publicKey string) ([]*application.Application, error)
}

type Endpoints struct {
	service             storageService
	appRepo             appMemberChecker
	eventService        EventService
	userRepo            user.UserRepository
	externalURLOverride string
}

func NewEndpoints(service storageService, appRepo appMemberChecker, eventService EventService, userRepo user.UserRepository, externalURLOverride string) *Endpoints {
	return &Endpoints{
		service:             service,
		appRepo:             appRepo,
		eventService:        eventService,
		userRepo:            userRepo,
		externalURLOverride: externalURLOverride,
	}
}

func (e *Endpoints) Upload(ctx *fasthttp.RequestCtx) {
	appIDStr := string(ctx.QueryArgs().Peek("applicationId"))

	var appID *string
	var publicKey string
	var spaceID *string

	if appIDStr != "" {
		aid, pk, sid, ok := e.checkAuthorization(ctx)
		if !ok {
			return
		}
		appID = &aid
		publicKey = pk
		spaceID = sid
	} else {
		authenticatedUser, ok := ctx.UserValue("user").(*user.User)
		if !ok || authenticatedUser == nil {
			log.Error().Msg("[STORAGE] Unauthorized upload attempt")
			ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
			return
		}
		publicKey = authenticatedUser.PublicKey
		if authenticatedUser.SpaceID != "" {
			spaceID = &authenticatedUser.SpaceID
		}
	}

	contentType := string(ctx.Request.Header.ContentType())
	if !strings.HasPrefix(contentType, "multipart/form-data") {
		ctx.Error("Content-Type must be multipart/form-data", fasthttp.StatusBadRequest)
		return
	}

	form, err := ctx.MultipartForm()
	if err != nil {
		ctx.Error("Failed to parse multipart form", fasthttp.StatusBadRequest)
		return
	}

	files := form.File["file"]
	if len(files) == 0 {
		ctx.Error("No file uploaded", fasthttp.StatusBadRequest)
		return
	}

	fileHeader := files[0]
	file, err := fileHeader.Open()
	if err != nil {
		ctx.Error("Failed to open uploaded file", fasthttp.StatusInternalServerError)
		return
	}
	defer file.Close()

	storageID := ""
	if ids := form.Value["id"]; len(ids) > 0 {
		storageID = ids[0]
	}
	if storageID == "" {
		ctx.Error("Storage ID is required", fasthttp.StatusBadRequest)
		return
	}

	checksum := ""
	if checksums := form.Value["checksum"]; len(checksums) > 0 {
		checksum = checksums[0]
	}

	req := &UploadRequest{
		ID:          storageID,
		Filename:    fileHeader.Filename,
		ContentType: fileHeader.Header.Get("Content-Type"),
		SizeBytes:   fileHeader.Size,
		Checksum:    checksum,
	}

	if req.ContentType == "" || req.ContentType == "application/octet-stream" {
		req.ContentType = detectContentType(fileHeader.Filename)
	}

	baseURL := httputil.PublicURL(ctx, e.externalURLOverride)
	stored, err := e.service.Upload(ctx, appID, publicKey, spaceID, req, file, baseURL)
	if err != nil {
		log.Error().Err(err).Msg("Failed to upload file")
		ctx.Error(err.Error(), fasthttp.StatusBadRequest)
		return
	}

	if appID != nil {
		evt := &event.Event{
			ID:               newEventID(),
			Type:             event.EventTypeApplicationFileCreated,
			CreatorPublicKey: publicKey,
			ApplicationID:    *appID,
			Data: map[string]interface{}{
				"version":       1,
				"applicationId": *appID,
				"fileId":        stored.ID,
				"filename":      stored.Filename,
				"contentType":   stored.ContentType,
				"sizeBytes":     stored.SizeBytes,
				"remoteUrl":     fmt.Sprintf("%s/storage/%s", baseURL, stored.ID),
			},
		}
		if _, err := e.eventService.ProduceEvent(ctx, evt); err != nil {
			log.Error().Err(err).Str("fileId", stored.ID).Msg("[STORAGE] Failed to produce application_file_created event")
		}
	}

	response, _ := json.Marshal(stored)
	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusCreated)
	ctx.SetBody(response)
}

func (e *Endpoints) UploadUserAvatar(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}
	publicKey := authenticatedUser.PublicKey

	contentType := string(ctx.Request.Header.ContentType())
	if !strings.HasPrefix(contentType, "multipart/form-data") {
		ctx.Error("Content-Type must be multipart/form-data", fasthttp.StatusBadRequest)
		return
	}

	form, err := ctx.MultipartForm()
	if err != nil {
		ctx.Error("Failed to parse multipart form", fasthttp.StatusBadRequest)
		return
	}

	files := form.File["file"]
	if len(files) == 0 {
		ctx.Error("No file uploaded", fasthttp.StatusBadRequest)
		return
	}

	fileHeader := files[0]
	file, err := fileHeader.Open()
	if err != nil {
		ctx.Error("Failed to open uploaded file", fasthttp.StatusInternalServerError)
		return
	}
	defer file.Close()

	storageID := ""
	if ids := form.Value["id"]; len(ids) > 0 {
		storageID = ids[0]
	}
	if storageID == "" {
		ctx.Error("Storage ID is required", fasthttp.StatusBadRequest)
		return
	}

	checksum := ""
	if checksums := form.Value["checksum"]; len(checksums) > 0 {
		checksum = checksums[0]
	}

	req := &UploadRequest{
		ID:          storageID,
		Filename:    fileHeader.Filename,
		ContentType: fileHeader.Header.Get("Content-Type"),
		SizeBytes:   fileHeader.Size,
		Checksum:    checksum,
	}

	if req.ContentType == "" || req.ContentType == "application/octet-stream" {
		req.ContentType = detectContentType(fileHeader.Filename)
	}

	if !avatarContentTypes[req.ContentType] {
		ctx.Error("Avatar must be a JPEG, PNG, GIF, or WebP image", fasthttp.StatusBadRequest)
		return
	}

	var avatarSpaceID *string
	if authenticatedUser.SpaceID != "" {
		avatarSpaceID = &authenticatedUser.SpaceID
	}

	stored, err := e.service.Upload(ctx, nil, publicKey, avatarSpaceID, req, file, httputil.PublicURL(ctx, e.externalURLOverride))
	if err != nil {
		log.Error().Err(err).Msg("[STORAGE] Failed to upload avatar")
		ctx.Error("Failed to upload avatar", fasthttp.StatusInternalServerError)
		return
	}

	if err := e.userRepo.UpdateAvatarStorageID(publicKey, &stored.ID); err != nil {
		log.Error().Err(err).Str("storageId", stored.ID).Msg("[STORAGE] Failed to update avatar storage id")
		ctx.Error("Failed to update avatar", fasthttp.StatusInternalServerError)
		return
	}

	// Fan out UserSettingsChanged to every app the user is a member of so member-list UIs refresh.
	// Best-effort: errors are logged but do not fail the response.
	apps, err := e.appRepo.GetApplicationsByMemberPublicKey(publicKey)
	if err != nil {
		log.Warn().Err(err).Str("publicKey", publicKey).Msg("[STORAGE] Failed to look up member apps for UserSettingsChanged fan-out")
	} else {
		for _, app := range apps {
			evt := &event.Event{
				ID:               newEventID(),
				Type:             event.EventTypeUserSettingsChanged,
				CreatorPublicKey: publicKey,
				ApplicationID:    app.ID,
				Data: map[string]interface{}{
					"version":         1,
					"userPublicKey":   publicKey,
					"avatarStorageId": stored.ID,
					"applicationId":   app.ID,
				},
			}
			if app.SpaceID != nil {
				evt.SpaceID = *app.SpaceID
			}
			if _, evtErr := e.eventService.ProduceEvent(ctx, evt); evtErr != nil {
				log.Warn().Err(evtErr).Str("applicationId", app.ID).Msg("[STORAGE] Failed to produce UserSettingsChanged event")
			}
		}
	}

	// Delete previous avatar after successful upload and DB update (best-effort)
	if authenticatedUser.AvatarStorageID != nil {
		if delErr := e.service.Delete(ctx, *authenticatedUser.AvatarStorageID, publicKey); delErr != nil {
			log.Warn().Err(delErr).Str("storageId", *authenticatedUser.AvatarStorageID).Msg("[STORAGE] Failed to delete previous avatar")
		}
	}

	response, _ := json.Marshal(stored)
	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusCreated)
	ctx.SetBody(response)
}

func (e *Endpoints) InitChunkedUpload(ctx *fasthttp.RequestCtx) {
	appID, publicKey, spaceID, ok := e.checkAuthorization(ctx)
	if !ok {
		return
	}

	var req ChunkedUploadInitRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		ctx.Error("Invalid request body", fasthttp.StatusBadRequest)
		return
	}

	// A JSON body has no per-part Content-Type header to fall back from,
	// unlike the multipart paths above, so resolve empty/generic here too —
	// otherwise the service's isValidContentType gate rejects empty as invalid.
	if req.ContentType == "" || req.ContentType == "application/octet-stream" {
		req.ContentType = detectContentType(req.Filename)
	}

	response, err := e.service.InitChunkedUpload(ctx, &appID, publicKey, spaceID, &req)
	if err != nil {
		ctx.Error(err.Error(), fasthttp.StatusBadRequest)
		return
	}

	responseBody, _ := json.Marshal(response)
	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusCreated)
	ctx.SetBody(responseBody)
}

func (e *Endpoints) UploadChunk(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}
	publicKey := authenticatedUser.PublicKey

	storageID, ok := ctx.UserValue("storageID").(string)
	if !ok || storageID == "" {
		ctx.Error("Storage ID is required", fasthttp.StatusBadRequest)
		return
	}

	chunkIndexStr, ok := ctx.UserValue("chunkIndex").(string)
	if !ok {
		ctx.Error("Chunk index is required", fasthttp.StatusBadRequest)
		return
	}

	chunkIndex, err := strconv.Atoi(chunkIndexStr)
	if err != nil {
		ctx.Error("Invalid chunk index", fasthttp.StatusBadRequest)
		return
	}

	stored, err := e.service.Get(ctx, storageID, "")
	if err != nil {
		ctx.Error("Storage not found", fasthttp.StatusNotFound)
		return
	}

	if stored.UploaderPublicKey != publicKey {
		ctx.Error("Not authorized", fasthttp.StatusForbidden)
		return
	}

	body := ctx.PostBody()
	if err := e.service.UploadChunk(ctx, storageID, chunkIndex, bytes.NewReader(body)); err != nil {
		ctx.Error(err.Error(), fasthttp.StatusBadRequest)
		return
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
}

func (e *Endpoints) CompleteChunkedUpload(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}
	publicKey := authenticatedUser.PublicKey

	storageID, ok := ctx.UserValue("storageID").(string)
	if !ok || storageID == "" {
		ctx.Error("Storage ID is required", fasthttp.StatusBadRequest)
		return
	}

	stored, err := e.service.Get(ctx, storageID, "")
	if err != nil {
		ctx.Error("Storage not found", fasthttp.StatusNotFound)
		return
	}

	if stored.UploaderPublicKey != publicKey {
		ctx.Error("Not authorized", fasthttp.StatusForbidden)
		return
	}

	baseURL := httputil.PublicURL(ctx, e.externalURLOverride)
	completedStorage, err := e.service.CompleteChunkedUpload(ctx, storageID, baseURL)
	if err != nil {
		ctx.Error(err.Error(), fasthttp.StatusBadRequest)
		return
	}

	if completedStorage.ApplicationID != nil {
		evt := &event.Event{
			ID:               newEventID(),
			Type:             event.EventTypeApplicationFileCreated,
			CreatorPublicKey: publicKey,
			ApplicationID:    *completedStorage.ApplicationID,
			Data: map[string]interface{}{
				"version":       1,
				"applicationId": *completedStorage.ApplicationID,
				"fileId":        completedStorage.ID,
				"filename":      completedStorage.Filename,
				"contentType":   completedStorage.ContentType,
				"sizeBytes":     completedStorage.SizeBytes,
				"remoteUrl":     fmt.Sprintf("%s/storage/%s", baseURL, completedStorage.ID),
			},
		}
		if _, err := e.eventService.ProduceEvent(ctx, evt); err != nil {
			log.Error().Err(err).Str("fileId", completedStorage.ID).Msg("[STORAGE] Failed to produce application_file_created event")
		}
	}

	response, _ := json.Marshal(completedStorage)
	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(response)
}

func (e *Endpoints) GetFile(ctx *fasthttp.RequestCtx) {
	stored, _, ok := e.getStorageAndCheckAccess(ctx)
	if !ok {
		return
	}

	storageID := stored.ID
	reader, stored, err := e.service.GetData(ctx, storageID)
	if err != nil {
		log.Error().Err(err).Str("storageId", storageID).Msg("[STORAGE] GetData failed")
		if errors.Is(err, ErrBlobNotFound) {
			ctx.Error("file not found", fasthttp.StatusNotFound)
			return
		}
		ctx.Error("Failed to retrieve file", fasthttp.StatusInternalServerError)
		return
	}
	defer reader.Close()

	disposition := "attachment"
	if inlineContentTypes[stored.ContentType] {
		disposition = "inline"
	}
	filename := sanitizeFilenameForHeader(stored.Filename)

	// A row predating the isValidContentType gate in Service.Upload/
	// InitChunkedUpload could still hold a poisoned value; never splice it
	// into a response header unvalidated.
	contentType := stored.ContentType
	if !isValidContentType(contentType) {
		contentType = "application/octet-stream"
	}
	ctx.SetContentType(contentType)
	ctx.Response.Header.Set("X-Content-Type-Options", "nosniff")
	ctx.Response.Header.Set("Content-Disposition", disposition+"; filename=\""+filename+"\"")
	ctx.Response.Header.Set("Content-Length", strconv.FormatInt(stored.SizeBytes, 10))

	if _, err := io.Copy(ctx, reader); err != nil {
		log.Error().Err(err).Msg("Failed to stream file")
	}
}

// inlineContentTypes is the render-safe set the app knows how to preview
// inline. Everything else is served as an attachment. This is the old
// upload allowlist, repurposed for serving instead of upload validation.
var inlineContentTypes = map[string]bool{
	"image/jpeg": true,
	"image/png":  true,
	"image/gif":  true,
	"image/webp": true,
	"video/mp4":  true,
	"video/webm": true,
	"video/mov":  true,
}

// avatarContentTypes is the sole content-type gate on the avatar upload path
// (Upload itself no longer validates, see service.go). Deliberately narrower
// than inlineContentTypes: no image/svg+xml (active content, not safe as an
// avatar) and no video types (a video avatar was only ever allowed as a side
// effect of the old shared allowlist).
var avatarContentTypes = map[string]bool{
	"image/jpeg": true,
	"image/png":  true,
	"image/gif":  true,
	"image/webp": true,
}

// sanitizeFilenameForHeader strips characters that would let a stored
// filename break out of the quoted Content-Disposition header value.
// Filenames are user-controlled and are spliced into the header unescaped.
func sanitizeFilenameForHeader(filename string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '"', '\\', '\r', '\n':
			return -1
		}
		return r
	}, filename)
}

func (e *Endpoints) GetThumbnail(ctx *fasthttp.RequestCtx) {
	stored, _, ok := e.getStorageAndCheckAccess(ctx)
	if !ok {
		return
	}

	storageID := stored.ID
	reader, _, err := e.service.GetThumbnail(ctx, storageID)
	if err != nil {
		ctx.Error("Thumbnail not available", fasthttp.StatusNotFound)
		return
	}
	defer reader.Close()

	ctx.SetContentType("image/jpeg")

	if _, err := io.Copy(ctx, reader); err != nil {
		log.Error().Err(err).Msg("Failed to stream thumbnail")
	}
}

func (e *Endpoints) DeleteFile(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}
	publicKey := authenticatedUser.PublicKey

	storageID, ok := ctx.UserValue("storageID").(string)
	if !ok || storageID == "" {
		ctx.Error("Storage ID is required", fasthttp.StatusBadRequest)
		return
	}

	// Fetch record before deletion to capture metadata for the event
	stored, err := e.service.Get(ctx, storageID, "")
	if err != nil {
		ctx.Error("Storage not found", fasthttp.StatusNotFound)
		return
	}
	appID := stored.ApplicationID

	if err := e.service.Delete(ctx, storageID, publicKey); err != nil {
		errMsg := err.Error()
		switch {
		case strings.Contains(errMsg, "not authorized"):
			ctx.Error("Not authorized to delete this file", fasthttp.StatusForbidden)
		case strings.Contains(errMsg, "not found"):
			ctx.Error("Storage not found", fasthttp.StatusNotFound)
		default:
			ctx.Error("Failed to delete file", fasthttp.StatusInternalServerError)
		}
		return
	}

	if appID != nil {
		evt := &event.Event{
			ID:               newEventID(),
			Type:             event.EventTypeApplicationFileDeleted,
			CreatorPublicKey: publicKey,
			ApplicationID:    *appID,
			Data: map[string]interface{}{
				"version":       1,
				"applicationId": *appID,
				"fileId":        storageID,
			},
		}
		if _, err := e.eventService.ProduceEvent(ctx, evt); err != nil {
			log.Error().Err(err).Str("fileId", storageID).Msg("[STORAGE] Failed to produce application_file_deleted event")
		}
	}

	ctx.SetStatusCode(fasthttp.StatusNoContent)
}

func (e *Endpoints) checkAuthorization(ctx *fasthttp.RequestCtx) (appID, publicKey string, spaceID *string, ok bool) {
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return "", "", nil, false
	}
	publicKey = authenticatedUser.PublicKey
	if authenticatedUser.SpaceID != "" {
		spaceID = &authenticatedUser.SpaceID
	}

	appID = string(ctx.QueryArgs().Peek("applicationId"))
	if appID == "" {
		ctx.Error("applicationId is required", fasthttp.StatusBadRequest)
		return "", "", nil, false
	}

	isMember, err := e.appRepo.IsMember(appID, publicKey)
	if err != nil {
		ctx.Error("Failed to verify membership", fasthttp.StatusInternalServerError)
		return "", "", nil, false
	}
	if !isMember {
		ctx.Error("Not a member of this application", fasthttp.StatusForbidden)
		return "", "", nil, false
	}

	return appID, publicKey, spaceID, true
}

func (e *Endpoints) getStorageAndCheckAccess(ctx *fasthttp.RequestCtx) (stored *Storage, publicKey string, ok bool) {
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return nil, "", false
	}
	publicKey = authenticatedUser.PublicKey

	storageID, ok := ctx.UserValue("storageID").(string)
	if !ok || storageID == "" {
		ctx.Error("Storage ID is required", fasthttp.StatusBadRequest)
		return nil, "", false
	}

	stored, err := e.service.Get(ctx, storageID, "")
	if err != nil {
		ctx.Error("Storage not found", fasthttp.StatusNotFound)
		return nil, "", false
	}

	if stored.Status != string(StorageStatusReady) {
		ctx.Error("Storage not found", fasthttp.StatusNotFound)
		return nil, "", false
	}

	// User-scoped files (applicationID == nil, e.g. avatars) are intentionally accessible to any
	// authenticated user. Avatars must be visible to other platform users (e.g. in member lists).
	// The UUID storage ID acts as a capability token — only users who received the ID via the
	// profile endpoint can request the file, so UUID-based access is sufficient security here.
	if stored.ApplicationID != nil {
		isMember, err := e.appRepo.IsMember(*stored.ApplicationID, publicKey)
		if err != nil {
			ctx.Error("Failed to verify membership", fasthttp.StatusInternalServerError)
			return nil, "", false
		}
		if !isMember {
			ctx.Error("Not a member of this application", fasthttp.StatusForbidden)
			return nil, "", false
		}
	}

	return stored, publicKey, true
}

// newEventID generates a UUID v7 (time-ordered) for event IDs, falling back to v4 on clock error.
func newEventID() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.New().String()
	}
	return id.String()
}

// detectContentType mirrors FilePickerService._getMimeTypeFromExtension in
// the Dart client (file_picker_service.dart) so a file uploaded without an
// explicit MIME type gets labelled the same way the client would have
// labelled it. The two tables must stay in sync.
func detectContentType(filename string) string {
	dotIndex := strings.LastIndex(filename, ".")
	if dotIndex == -1 || dotIndex == len(filename)-1 {
		return "application/octet-stream"
	}
	ext := strings.ToLower(filename[dotIndex+1:])
	switch ext {
	case "jpg", "jpeg":
		return "image/jpeg"
	case "png":
		return "image/png"
	case "gif":
		return "image/gif"
	case "webp":
		return "image/webp"
	case "bmp":
		return "image/bmp"
	case "svg":
		return "image/svg+xml"
	case "mp4":
		return "video/mp4"
	case "webm":
		return "video/webm"
	case "mov":
		return "video/mov"
	case "avi":
		return "video/x-msvideo"
	case "mkv":
		return "video/x-matroska"
	case "mp3":
		return "audio/mpeg"
	case "wav":
		return "audio/wav"
	case "ogg":
		return "audio/ogg"
	case "flac":
		return "audio/flac"
	case "pdf":
		return "application/pdf"
	case "doc":
		return "application/msword"
	case "docx":
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case "xls":
		return "application/vnd.ms-excel"
	case "xlsx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case "ppt":
		return "application/vnd.ms-powerpoint"
	case "pptx":
		return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
	case "txt":
		return "text/plain"
	case "csv":
		return "text/csv"
	case "json":
		return "application/json"
	case "xml":
		return "application/xml"
	case "html":
		return "text/html"
	case "zip":
		return "application/zip"
	case "rar":
		return "application/x-rar-compressed"
	case "7z":
		return "application/x-7z-compressed"
	default:
		return "application/octet-stream"
	}
}
