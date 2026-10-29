package spaceprofile

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/storage"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

const maxNameLength = 64

type StorageGetter interface {
	GetByID(id string) (*storage.Storage, error)
}

type EventProducer interface {
	ProduceEvent(ctx context.Context, event *event.Event) (*event.Event, error)
}

type SpaceProfileEndpoints struct {
	repo    *Repository
	storage StorageGetter
	events  EventProducer
}

func NewSpaceProfileEndpoints(repo *Repository, storage StorageGetter, events EventProducer) *SpaceProfileEndpoints {
	return &SpaceProfileEndpoints{repo: repo, storage: storage, events: events}
}

// UpdateProfile handles PUT /space/profile. The image must already be
// uploaded by the owner through POST /storage/upload without an application,
// which keeps it readable by every account on the space.
func (e *SpaceProfileEndpoints) UpdateProfile(ctx *fasthttp.RequestCtx) {
	u, ok := ctx.UserValue("user").(*user.User)
	if !ok || u == nil {
		log.Error().Msg("[SPACE_PROFILE] UpdateProfile without authenticated user")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}
	if u.Role != user.RoleOwner {
		log.Error().Str("role", u.Role).Msg("[SPACE_PROFILE] UpdateProfile by non-owner")
		ctx.Error("Forbidden", fasthttp.StatusForbidden)
		return
	}

	var body struct {
		Name            string  `json:"name"`
		AvatarStorageID *string `json:"avatarStorageId"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &body); err != nil {
		log.Error().Err(err).Msg("[SPACE_PROFILE] Invalid request body")
		ctx.Error("Invalid request body", fasthttp.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(body.Name)
	if utf8.RuneCountInString(name) > maxNameLength {
		log.Error().Msg("[SPACE_PROFILE] Name too long")
		ctx.Error("name is too long", fasthttp.StatusBadRequest)
		return
	}
	if body.AvatarStorageID != nil {
		f, err := e.storage.GetByID(*body.AvatarStorageID)
		if err != nil || f.Status != string(storage.StorageStatusReady) || f.ApplicationID != nil ||
			f.UploaderPublicKey != u.PublicKey || !storage.IsAvatarContentType(f.ContentType) {
			log.Error().Err(err).Str("storageId", *body.AvatarStorageID).Msg("[SPACE_PROFILE] Unusable avatar storage id")
			ctx.Error("avatarStorageId must be an image you uploaded", fasthttp.StatusBadRequest)
			return
		}
	}

	p := Profile{Name: name, AvatarStorageID: body.AvatarStorageID, UpdatedAt: time.Now().Unix()}
	if err := e.repo.Save(p); err != nil {
		log.Error().Err(err).Msg("[SPACE_PROFILE] Failed to save")
		ctx.Error("Failed to save space profile", fasthttp.StatusInternalServerError)
		return
	}

	e.announce(ctx, u.PublicKey)

	resp, err := json.Marshal(p)
	if err != nil {
		log.Error().Err(err).Msg("[SPACE_PROFILE] Failed to encode")
		ctx.Error("Failed to save space profile", fasthttp.StatusInternalServerError)
		return
	}
	ctx.SetContentType("application/json")
	ctx.SetBody(resp)
}

// announce fans space_profile_changed out to every live app, so accounts in
// any app re-read the profile. Best-effort: the profile is already saved,
// and accounts also re-read it when they connect.
// ponytail: one event per app, fine for personal spaces; a space-scoped
// broadcast would replace it if a space grows to many apps.
func (e *SpaceProfileEndpoints) announce(ctx context.Context, ownerPublicKey string) {
	apps, err := e.repo.listLiveApplications()
	if err != nil {
		log.Warn().Err(err).Msg("[SPACE_PROFILE] Failed to list apps for space_profile_changed")
		return
	}
	for _, app := range apps {
		evt := &event.Event{
			ID:               newEventID(),
			Type:             event.EventTypeSpaceProfileChanged,
			CreatorPublicKey: ownerPublicKey,
			ApplicationID:    app.ID,
			Data:             map[string]interface{}{"version": 1, "applicationId": app.ID},
		}
		if app.SpaceID != nil {
			evt.SpaceID = *app.SpaceID
		}
		if _, err := e.events.ProduceEvent(ctx, evt); err != nil {
			log.Warn().Err(err).Str("applicationId", app.ID).Msg("[SPACE_PROFILE] Failed to produce space_profile_changed")
		}
	}
}

func newEventID() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.New().String()
	}
	return id.String()
}
