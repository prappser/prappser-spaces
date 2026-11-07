package profile

import (
	"errors"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

type ProfileEndpoints struct {
	userRepo     userRepository
	appRepo      appLister
	eventService EventService
}

func NewProfileEndpoints(userRepo userRepository, appRepo appLister, eventService EventService) *ProfileEndpoints {
	return &ProfileEndpoints{
		userRepo:     userRepo,
		appRepo:      appRepo,
		eventService: eventService,
	}
}

func (e *ProfileEndpoints) UpdateProfile(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("[PROFILE] Unauthorized")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}
	publicKey := authenticatedUser.PublicKey

	var req UpdateProfileRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		ctx.Error("Invalid request body", fasthttp.StatusBadRequest)
		return
	}

	if req.DisplayName == nil && req.Locale == nil && req.NotifyMode == nil && req.NotificationsSeenAt == nil {
		ctx.Error("displayName, locale, notifyMode or notificationsSeenAt required", fasthttp.StatusBadRequest)
		return
	}

	var displayName, locale string
	if req.DisplayName != nil {
		var err error
		if displayName, err = user.NormalizeUsername(*req.DisplayName); err != nil {
			ctx.Error(err.Error(), fasthttp.StatusBadRequest)
			return
		}
	}
	if req.Locale != nil {
		var err error
		if locale, err = normalizeLocale(*req.Locale); err != nil {
			ctx.Error(err.Error(), fasthttp.StatusBadRequest)
			return
		}
	}

	if req.NotifyMode != nil && *req.NotifyMode != user.NotifyModeAll && *req.NotifyMode != user.NotifyModeChat {
		ctx.Error("notifyMode must be all or chat", fasthttp.StatusBadRequest)
		return
	}

	if req.NotificationsSeenAt != nil && (*req.NotificationsSeenAt < 0 || *req.NotificationsSeenAt > time.Now().Unix()+300) {
		log.Error().Int64("notificationsSeenAt", *req.NotificationsSeenAt).Msg("[PROFILE] notificationsSeenAt out of range")
		ctx.Error("notificationsSeenAt must be between 0 and now plus 5 minutes", fasthttp.StatusBadRequest)
		return
	}

	nameChanged := req.DisplayName != nil && displayName != authenticatedUser.Username
	localeChanged := req.Locale != nil && locale != authenticatedUser.Locale

	modeChanged := req.NotifyMode != nil && *req.NotifyMode != authenticatedUser.NotifyMode

	if !nameChanged && !localeChanged && !modeChanged && req.NotificationsSeenAt == nil {
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(authenticatedUser)
		return
	}

	if localeChanged {
		if err := e.userRepo.UpdateLocale(publicKey, locale); err != nil {
			log.Error().Err(err).Str("publicKey", publicKey).Msg("[PROFILE] Failed to update locale")
			ctx.Error("Failed to update profile", fasthttp.StatusInternalServerError)
			return
		}
	}

	if nameChanged {
		if err := e.userRepo.UpdateUsername(publicKey, displayName); err != nil {
			if errors.Is(err, user.ErrUsernameTaken) {
				log.Debug().Str("publicKey", publicKey).Msg("[PROFILE] Username already used for password login")
				ctx.Error("username already used for password login on this space", fasthttp.StatusConflict)
				return
			}
			log.Error().Err(err).Str("publicKey", publicKey).Msg("[PROFILE] Failed to update username")
			ctx.Error("Failed to update profile", fasthttp.StatusInternalServerError)
			return
		}
	}
	if modeChanged {
		if err := e.userRepo.UpdateNotifyMode(publicKey, *req.NotifyMode); err != nil {
			log.Error().Err(err).Str("publicKey", publicKey).Msg("[PROFILE] Failed to update notify mode")
			ctx.Error("Failed to update profile", fasthttp.StatusInternalServerError)
			return
		}
	}

	if req.NotificationsSeenAt != nil {
		if err := e.userRepo.UpdateNotificationsSeenAt(publicKey, *req.NotificationsSeenAt); err != nil {
			log.Error().Err(err).Str("publicKey", publicKey).Msg("[PROFILE] Failed to update notifications seen at")
			ctx.Error("Failed to update profile", fasthttp.StatusInternalServerError)
			return
		}
	}

	updatedUser, err := e.userRepo.GetUserByPublicKey(publicKey)
	if err != nil || updatedUser == nil {
		log.Error().Err(err).Str("publicKey", publicKey).Msg("[PROFILE] Failed to reload user after update")
		ctx.Error("Failed to update profile", fasthttp.StatusInternalServerError)
		return
	}

	if nameChanged {
		e.fanOutSettingsChanged(ctx, updatedUser)
	}

	response, _ := json.Marshal(updatedUser)
	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(response)
}

func normalizeLocale(raw string) (string, error) {
	base, _, _ := strings.Cut(strings.NewReplacer("_", "-").Replace(strings.TrimSpace(raw)), "-")
	if len(base) < 2 || len(base) > 3 {
		return "", errors.New("locale must be a 2 or 3 letter language code")
	}
	for _, c := range base {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return "", errors.New("locale must be a 2 or 3 letter language code")
		}
	}
	return strings.ToLower(base), nil
}

func (e *ProfileEndpoints) fanOutSettingsChanged(ctx *fasthttp.RequestCtx, updatedUser *user.User) {
	publicKey, displayName := updatedUser.PublicKey, updatedUser.Username
	apps, err := e.appRepo.GetApplicationsByMemberPublicKey(publicKey)
	if err != nil {
		log.Warn().Err(err).Str("publicKey", publicKey).Msg("[PROFILE] Failed to look up member apps for UserSettingsChanged fan-out")
	} else {
		for _, app := range apps {
			data := map[string]interface{}{
				"version":       1,
				"userPublicKey": publicKey,
				"displayName":   displayName,
				"applicationId": app.ID,
			}
			// Echo the user's current avatarStorageId when non-nil: old clients treat an absent
			// avatarStorageId as "cleared" and would wipe avatars on a rename.
			if updatedUser.AvatarStorageID != nil {
				data["avatarStorageId"] = *updatedUser.AvatarStorageID
			}

			evt := &event.Event{
				ID:               newEventID(),
				Type:             event.EventTypeUserSettingsChanged,
				CreatorPublicKey: publicKey,
				ApplicationID:    app.ID,
				Data:             data,
			}
			if app.SpaceID != nil {
				evt.SpaceID = *app.SpaceID
			}
			if _, evtErr := e.eventService.ProduceEvent(ctx, evt); evtErr != nil {
				log.Warn().Err(evtErr).Str("applicationId", app.ID).Msg("[PROFILE] Failed to produce UserSettingsChanged event")
			}
		}
	}
}

// newEventID generates a UUID v7 (time-ordered) for event IDs, falling back to v4 on clock error.
func newEventID() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.New().String()
	}
	return id.String()
}
