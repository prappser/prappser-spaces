package application

import (
	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

type ApplicationEndpoints struct {
	appService      *ApplicationService
	spacePublicKey string
}

func NewApplicationEndpoints(appService *ApplicationService, spacePublicKey string) *ApplicationEndpoints {
	return &ApplicationEndpoints{
		appService:      appService,
		spacePublicKey: spacePublicKey,
	}
}

// RegisterApplication handles POST /applications/register
func (ae *ApplicationEndpoints) RegisterApplication(ctx *fasthttp.RequestCtx) {
	// Get authenticated user from context
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	// Parse request body
	var app Application
	if err := json.Unmarshal(ctx.PostBody(), &app); err != nil {
		log.Error().Err(err).Msg("Failed to parse request body")
		ctx.Error("Invalid request body", fasthttp.StatusBadRequest)
		return
	}

	// Validate request
	if app.ID == "" {
		ctx.Error("Application ID is required", fasthttp.StatusBadRequest)
		return
	}
	if app.Name == "" {
		ctx.Error("Application name is required", fasthttp.StatusBadRequest)
		return
	}
	// Validate members (service layer will validate owner exists)
	if len(app.Members) == 0 {
		ctx.Error("Application must have at least one member", fasthttp.StatusBadRequest)
		return
	}

	// Set space public key for the application
	app.SpacePublicKey = &ae.spacePublicKey

	// Set space ID from authenticated user's JWT claims
	if authenticatedUser.SpaceID != "" {
		app.SpaceID = &authenticatedUser.SpaceID
	}

	// Register the application
	_, err := ae.appService.RegisterApplication(authenticatedUser.PublicKey, &app)
	if err != nil {
		log.Error().Err(err).Msg("Failed to register application")
		ctx.Error("Failed to register application", fasthttp.StatusInternalServerError)
		return
	}

	// Return created with no content
	ctx.SetStatusCode(fasthttp.StatusCreated)
}

// ListApplications handles GET /applications
func (ae *ApplicationEndpoints) ListApplications(ctx *fasthttp.RequestCtx) {
	// Get authenticated user from context
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	// Get user's applications
	apps, err := ae.appService.ListApplications(authenticatedUser.PublicKey)
	if err != nil {
		log.Error().Err(err).Msg("Failed to list applications")
		ctx.Error("Failed to list applications", fasthttp.StatusInternalServerError)
		return
	}

	// Return applications (space_public_key now comes from database)
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(apps)
}

// GetApplication handles GET /applications/{id}
func (ae *ApplicationEndpoints) GetApplication(ctx *fasthttp.RequestCtx) {
	// Get authenticated user from context
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	// Extract application ID from path
	appID := ctx.UserValue("appID").(string)
	if appID == "" {
		ctx.Error("Application ID is required", fasthttp.StatusBadRequest)
		return
	}

	// Get the application
	app, err := ae.appService.GetApplication(appID, authenticatedUser)
	if err != nil {
		if err.Error() == "unauthorized" {
			ctx.Error("Forbidden", fasthttp.StatusForbidden)
			return
		}
		log.Error().Err(err).Msg("Failed to get application")
		ctx.Error("Application not found", fasthttp.StatusNotFound)
		return
	}

	// Return application (space_public_key now comes from database)
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(app)
}

// GetApplicationState handles GET /applications/{id}/state
func (ae *ApplicationEndpoints) GetApplicationState(ctx *fasthttp.RequestCtx) {
	// Get authenticated user from context
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	// Extract application ID from path
	appID := ctx.UserValue("appID").(string)
	if appID == "" {
		ctx.Error("Application ID is required", fasthttp.StatusBadRequest)
		return
	}

	// Get the application state
	state, err := ae.appService.GetApplicationState(appID, authenticatedUser)
	if err != nil {
		if err.Error() == "unauthorized" {
			ctx.Error("Forbidden", fasthttp.StatusForbidden)
			return
		}
		log.Error().Err(err).Msg("Failed to get application state")
		ctx.Error("Application not found", fasthttp.StatusNotFound)
		return
	}

	// Return state
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(state)
}

// DeleteApplication handles DELETE /applications/{id}
func (ae *ApplicationEndpoints) DeleteApplication(ctx *fasthttp.RequestCtx) {
	// Get authenticated user from context
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	// Extract application ID from path
	appID := ctx.UserValue("appID").(string)
	if appID == "" {
		ctx.Error("Application ID is required", fasthttp.StatusBadRequest)
		return
	}

	// Delete the application
	err := ae.appService.DeleteApplication(appID, authenticatedUser)
	if err != nil {
		if err.Error() == "unauthorized" {
			ctx.Error("Forbidden", fasthttp.StatusForbidden)
			return
		}
		if err.Error() == "application not found" {
			ctx.Error("Application not found", fasthttp.StatusNotFound)
			return
		}
		log.Error().Err(err).Msg("Failed to delete application")
		ctx.Error("Failed to delete application", fasthttp.StatusInternalServerError)
		return
	}

	// Return success response
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	response := map[string]string{
		"message": "Application deleted successfully",
	}
	json.NewEncoder(ctx).Encode(response)
}

// LeaveApplication handles DELETE /applications/{id}/members/me
func (ae *ApplicationEndpoints) LeaveApplication(ctx *fasthttp.RequestCtx) {
	// Get authenticated user from context
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	// Extract application ID from path
	appID := ctx.UserValue("appID").(string)
	if appID == "" {
		ctx.Error("Application ID is required", fasthttp.StatusBadRequest)
		return
	}

	// Leave the application
	err := ae.appService.LeaveApplication(appID, authenticatedUser)
	if err != nil {
		if err.Error() == "not a member of this application" {
			ctx.Error("Not a member of this application", fasthttp.StatusForbidden)
			return
		}
		log.Error().Err(err).Msg("Failed to leave application")
		ctx.Error("Failed to leave application", fasthttp.StatusInternalServerError)
		return
	}

	// Return success response
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	response := map[string]string{
		"message": "Left application successfully",
	}
	json.NewEncoder(ctx).Encode(response)
}
