package profile

import (
	"errors"

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

// UpdateProfile handles PATCH /users/me, updating the authenticated user's display name.
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

	displayName, err := user.NormalizeUsername(req.DisplayName)
	if err != nil {
		ctx.Error(err.Error(), fasthttp.StatusBadRequest)
		return
	}

	// Short-circuit: no write, no fan-out when the name hasn't actually changed.
	if displayName == authenticatedUser.Username {
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetContentType("application/json")
		json.NewEncoder(ctx).Encode(authenticatedUser)
		return
	}

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

	updatedUser, err := e.userRepo.GetUserByPublicKey(publicKey)
	if err != nil || updatedUser == nil {
		log.Error().Err(err).Str("publicKey", publicKey).Msg("[PROFILE] Failed to reload user after update")
		ctx.Error("Failed to update profile", fasthttp.StatusInternalServerError)
		return
	}

	// Fan out UserSettingsChanged to every app the user is a member of so member-list UIs refresh.
	// Best-effort: errors are logged but do not fail the response.
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

	response, _ := json.Marshal(updatedUser)
	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(response)
}

// newEventID generates a UUID v7 (time-ordered) for event IDs, falling back to v4 on clock error.
func newEventID() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.New().String()
	}
	return id.String()
}
