package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/prappser/prappser_server/internal/application"
	"github.com/prappser/prappser_server/internal/event"
	"github.com/prappser/prappser_server/internal/user"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

// EventService is the interface for producing server-generated events.
type EventService interface {
	ProduceEvent(ctx context.Context, e *event.Event) (*event.Event, error)
}

type Endpoints struct {
	service      *Service
	appRepo      *application.Repository
	eventService EventService
	userRepo     user.UserRepository
}

func NewEndpoints(service *Service, appRepo *application.Repository, eventService EventService, userRepo user.UserRepository) *Endpoints {
	return &Endpoints{
		service:      service,
		appRepo:      appRepo,
		eventService: eventService,
		userRepo:     userRepo,
	}
}

func (e *Endpoints) Upload(ctx *fasthttp.RequestCtx) {
	appID, publicKey, ok := e.checkAuthorization(ctx)
	if !ok {
		return
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

	stored, err := e.service.Upload(ctx, &appID, publicKey, req, file)
	if err != nil {
		log.Error().Err(err).Msg("Failed to upload file")
		ctx.Error(err.Error(), fasthttp.StatusBadRequest)
		return
	}

	evt := &event.Event{
		ID:               newEventID(),
		Type:             event.EventTypeApplicationFileCreated,
		CreatorPublicKey: publicKey,
		ApplicationID:    appID,
		Data: map[string]interface{}{
			"version":       1,
			"applicationId": appID,
			"fileId":        stored.ID,
			"filename":      stored.Filename,
			"contentType":   stored.ContentType,
			"sizeBytes":     stored.SizeBytes,
			"remoteUrl":     fmt.Sprintf("%s/storage/%s", e.service.ExternalURL(), stored.ID),
		},
	}
	if _, err := e.eventService.ProduceEvent(ctx, evt); err != nil {
		log.Error().Err(err).Str("fileId", stored.ID).Msg("[STORAGE] Failed to produce application_file_created event")
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

	stored, err := e.service.Upload(ctx, nil, publicKey, req, file)
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
	appID, publicKey, ok := e.checkAuthorization(ctx)
	if !ok {
		return
	}

	var req ChunkedUploadInitRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		ctx.Error("Invalid request body", fasthttp.StatusBadRequest)
		return
	}

	response, err := e.service.InitChunkedUpload(ctx, &appID, publicKey, &req)
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

	stored, err := e.service.Get(ctx, storageID)
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

	stored, err := e.service.Get(ctx, storageID)
	if err != nil {
		ctx.Error("Storage not found", fasthttp.StatusNotFound)
		return
	}

	if stored.UploaderPublicKey != publicKey {
		ctx.Error("Not authorized", fasthttp.StatusForbidden)
		return
	}

	completedStorage, err := e.service.CompleteChunkedUpload(ctx, storageID)
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
				"remoteUrl":     fmt.Sprintf("%s/storage/%s", e.service.ExternalURL(), completedStorage.ID),
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
		ctx.Error("Failed to retrieve file", fasthttp.StatusInternalServerError)
		return
	}
	defer reader.Close()

	ctx.SetContentType(stored.ContentType)
	ctx.Response.Header.Set("Content-Disposition", "inline; filename=\""+stored.Filename+"\"")
	ctx.Response.Header.Set("Content-Length", strconv.FormatInt(stored.SizeBytes, 10))

	if _, err := io.Copy(ctx, reader); err != nil {
		log.Error().Err(err).Msg("Failed to stream file")
	}
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
	stored, err := e.service.Get(ctx, storageID)
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

func (e *Endpoints) checkAuthorization(ctx *fasthttp.RequestCtx) (appID, publicKey string, ok bool) {
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return "", "", false
	}
	publicKey = authenticatedUser.PublicKey

	appID = string(ctx.QueryArgs().Peek("applicationId"))
	if appID == "" {
		ctx.Error("applicationId is required", fasthttp.StatusBadRequest)
		return "", "", false
	}

	isMember, err := e.appRepo.IsMember(appID, publicKey)
	if err != nil {
		ctx.Error("Failed to verify membership", fasthttp.StatusInternalServerError)
		return "", "", false
	}
	if !isMember {
		ctx.Error("Not a member of this application", fasthttp.StatusForbidden)
		return "", "", false
	}

	return appID, publicKey, true
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

	stored, err := e.service.Get(ctx, storageID)
	if err != nil {
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
	case "mp4":
		return "video/mp4"
	case "webm":
		return "video/webm"
	case "mov":
		return "video/mov"
	default:
		return "application/octet-stream"
	}
}
