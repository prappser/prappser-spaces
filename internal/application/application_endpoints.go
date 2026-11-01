package application

import (
	"errors"
	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

type ApplicationEndpoints struct {
	appService *ApplicationService
}

func NewApplicationEndpoints(appService *ApplicationService) *ApplicationEndpoints {
	return &ApplicationEndpoints{appService: appService}
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

	_, err := ae.appService.RegisterApplication(authenticatedUser, &app)
	if WriteMoveError(ctx, err) {
		return
	}
	if errors.Is(err, ErrOwnerNotCaller) {
		log.Error().Err(err).Msg("Application owner is not the caller")
		body, _ := json.Marshal(map[string]string{"error": err.Error(), "code": "owner_not_caller"})
		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetContentType("application/json")
		ctx.SetBody(body)
		return
	}
	if errors.Is(err, ErrNotApplicationOwner) {
		log.Error().Err(err).Msg("Application owned by another account")
		ctx.Error("Forbidden", fasthttp.StatusForbidden)
		return
	}
	if errors.Is(err, ErrAppLimitReached) {
		log.Error().Err(err).Msg("Application limit reached")
		body, _ := json.Marshal(map[string]string{"error": err.Error(), "code": "app_limit_reached"})
		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetContentType("application/json")
		ctx.SetBody(body)
		return
	}
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
	apps, err := ae.appService.ListApplications(authenticatedUser)
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
		if WriteMoveError(ctx, err) {
			return
		}
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

type agentReadRequest struct {
	Enabled *bool `json:"enabled"`
}

// SetAgentRead handles PUT /applications/{id}/agent-read
func (ae *ApplicationEndpoints) SetAgentRead(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}
	appID, _ := ctx.UserValue("appID").(string)
	if appID == "" {
		ctx.Error("Application ID is required", fasthttp.StatusBadRequest)
		return
	}

	var req agentReadRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil || req.Enabled == nil {
		log.Error().Err(err).Msg("Invalid agent-read request body")
		ctx.Error("enabled is required", fasthttp.StatusBadRequest)
		return
	}

	err := ae.appService.SetAgentRead(appID, authenticatedUser, *req.Enabled)
	if WriteMoveError(ctx, err) {
		return
	}
	if errors.Is(err, ErrNotApplicationOwner) {
		log.Error().Err(err).Msg("Only the application owner can change agent access")
		ctx.Error("Forbidden", fasthttp.StatusForbidden)
		return
	}
	if errors.Is(err, ErrNotFound) {
		log.Error().Err(err).Msg("Application not found")
		ctx.Error("Application not found", fasthttp.StatusNotFound)
		return
	}
	if err != nil {
		log.Error().Err(err).Msg("Failed to set agent access")
		ctx.Error("Failed to set agent access", fasthttp.StatusInternalServerError)
		return
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(map[string]bool{"agentReadEnabled": *req.Enabled})
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
		if WriteMoveError(ctx, err) {
			return
		}
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
		if WriteMoveError(ctx, err) {
			return
		}
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
	if WriteMoveError(ctx, err) {
		return
	}
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
