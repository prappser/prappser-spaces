package space

import (
	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

// UserRoleUpdater upgrades a user's instance role (e.g., guest -> user on space claim).
type UserRoleUpdater interface {
	UpdateUserRole(publicKey string, role string) error
}

type SpaceEndpoints struct {
	service         *SpaceService
	userRoleUpdater UserRoleUpdater
}

func NewSpaceEndpoints(service *SpaceService, userRoleUpdater UserRoleUpdater) *SpaceEndpoints {
	return &SpaceEndpoints{service: service, userRoleUpdater: userRoleUpdater}
}

// CreateSpace handles POST /spaces
func (se *SpaceEndpoints) CreateSpace(ctx *fasthttp.RequestCtx) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &body); err != nil {
		log.Error().Err(err).Msg("[SPACE] Failed to parse request body")
		ctx.Error("Invalid request body", fasthttp.StatusBadRequest)
		return
	}

	if body.Name == "" {
		ctx.Error("Name is required", fasthttp.StatusBadRequest)
		return
	}

	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("[SPACE] Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	space, err := se.service.CreateSpace(body.Name, &authenticatedUser.PublicKey)
	if err != nil {
		log.Error().Err(err).Msg("[SPACE] Failed to create space")
		ctx.Error("Failed to create space", fasthttp.StatusInternalServerError)
		return
	}

	ctx.SetStatusCode(fasthttp.StatusCreated)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(space)
}

// ListSpaces handles GET /spaces
func (se *SpaceEndpoints) ListSpaces(ctx *fasthttp.RequestCtx) {
	spaces, err := se.service.ListSpaces()
	if err != nil {
		log.Error().Err(err).Msg("[SPACE] Failed to list spaces")
		ctx.Error("Failed to list spaces", fasthttp.StatusInternalServerError)
		return
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(spaces)
}

// DeleteSpace handles DELETE /spaces/:id
func (se *SpaceEndpoints) DeleteSpace(ctx *fasthttp.RequestCtx) {
	spaceID, ok := ctx.UserValue("spaceID").(string)
	if !ok || spaceID == "" {
		ctx.Error("Space ID is required", fasthttp.StatusBadRequest)
		return
	}

	if err := se.service.DeleteSpace(spaceID); err != nil {
		if err.Error() == "space not found" {
			ctx.Error("Space not found", fasthttp.StatusNotFound)
			return
		}
		log.Error().Err(err).Msg("[SPACE] Failed to delete space")
		ctx.Error("Failed to delete space", fasthttp.StatusInternalServerError)
		return
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(map[string]string{"message": "Space deleted successfully"})
}

// GetMySpace handles GET /spaces/mine
func (se *SpaceEndpoints) GetMySpace(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("[SPACE] Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	space, err := se.service.GetMySpace(authenticatedUser.PublicKey)
	if err != nil {
		log.Error().Err(err).Msg("[SPACE] Failed to get space")
		ctx.Error("Failed to get space", fasthttp.StatusInternalServerError)
		return
	}
	if space == nil {
		ctx.Error("Space not found", fasthttp.StatusNotFound)
		return
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(space)
}

// CreateClaimInvite handles POST /spaces/:id/claim-invite
func (se *SpaceEndpoints) CreateClaimInvite(ctx *fasthttp.RequestCtx) {
	spaceID, ok := ctx.UserValue("spaceID").(string)
	if !ok || spaceID == "" {
		ctx.Error("Space ID is required", fasthttp.StatusBadRequest)
		return
	}

	response, err := se.service.GenerateClaimInvite(spaceID)
	if err != nil {
		if err.Error() == "space not found" {
			ctx.Error("Space not found", fasthttp.StatusNotFound)
			return
		}
		log.Error().Err(err).Msg("[SPACE] Failed to generate claim invite")
		ctx.Error("Failed to generate claim invite", fasthttp.StatusInternalServerError)
		return
	}

	ctx.SetStatusCode(fasthttp.StatusCreated)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(response)
}

// ClaimSpace handles POST /spaces/claim
func (se *SpaceEndpoints) ClaimSpace(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("[SPACE] Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &body); err != nil || body.Token == "" {
		ctx.Error("Token is required", fasthttp.StatusBadRequest)
		return
	}

	spaceID, err := se.service.ValidateClaimToken(body.Token)
	if err != nil {
		log.Error().Err(err).Msg("[SPACE] Invalid claim token")
		ctx.Error("Invalid or expired claim token", fasthttp.StatusBadRequest)
		return
	}

	space, err := se.service.ClaimSpace(spaceID, authenticatedUser.PublicKey)
	if err != nil {
		log.Error().Err(err).Msg("[SPACE] Failed to claim space")
		ctx.Error(err.Error(), fasthttp.StatusConflict)
		return
	}

	// Upgrade user role from guest to user on successful claim.
	if authenticatedUser.Role == user.RoleGuest && se.userRoleUpdater != nil {
		if err := se.userRoleUpdater.UpdateUserRole(authenticatedUser.PublicKey, user.RoleUser); err != nil {
			log.Error().Err(err).Msg("[SPACE] Failed to upgrade user role after claim")
			// Non-fatal: space is claimed, role upgrade can be retried.
		}
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(space)
}
