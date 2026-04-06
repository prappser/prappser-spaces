package invitation

import (
	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

type InvitationEndpoints struct {
	invitationService *InvitationService
}

func NewInvitationEndpoints(invitationService *InvitationService) *InvitationEndpoints {
	return &InvitationEndpoints{
		invitationService: invitationService,
	}
}

// CreateInviteRequest represents the request body for creating an invitation
type CreateInviteRequest struct {
	ExpiresInHours *int   `json:"expiresInHours,omitempty"`
	Role           string `json:"role,omitempty"`
	MaxUses        *int   `json:"maxUses,omitempty"`
}

// CreateInvite handles POST /applications/{id}/invites
func (ie *InvitationEndpoints) CreateInvite(ctx *fasthttp.RequestCtx) {
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

	// Parse request body
	var req CreateInviteRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		log.Error().Err(err).Msg("Failed to parse request body")
		ctx.Error("Invalid request body", fasthttp.StatusBadRequest)
		return
	}

	// Set default role if not provided
	if req.Role == "" {
		req.Role = "member"
	}

	// TODO: Verify user is owner of the application

	// Create invitation
	opts := CreateInvitationOptions{
		ApplicationID:      appID,
		CreatedByPublicKey: authenticatedUser.PublicKey,
		Role:               req.Role,
		MaxUses:            req.MaxUses,
		ExpiresInHours:     req.ExpiresInHours,
	}

	response, err := ie.invitationService.CreateInvitation(opts)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create invitation")
		ctx.Error("Failed to create invitation", fasthttp.StatusInternalServerError)
		return
	}

	// Return created invitation
	ctx.SetStatusCode(fasthttp.StatusCreated)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(response)
}

// GetInviteInfo handles GET /invites/{token}/info
// This is a public endpoint (no auth required)
func (ie *InvitationEndpoints) GetInviteInfo(ctx *fasthttp.RequestCtx) {
	// Extract token from path
	token := ctx.UserValue("token").(string)
	if token == "" {
		ctx.Error("Token is required", fasthttp.StatusBadRequest)
		return
	}

	// Get invite info
	info, err := ie.invitationService.GetInviteInfo(token)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get invite info")
		// Invalid token format
		ctx.Error("Invalid invite token", fasthttp.StatusBadRequest)
		return
	}

	// Check if invitation was revoked (not found in database)
	if !info.IsValid && info.ApplicationName == "" {
		log.Info().Str("inviteID", info.InviteID).Msg("Invitation not found (revoked)")
		ctx.Error("This invitation has been revoked", fasthttp.StatusNotFound)
		return
	}

	// Check if invitation expired or reached max uses
	if !info.IsValid {
		if info.IsExpired {
			log.Info().Str("inviteID", info.InviteID).Msg("Invitation expired")
			ctx.Error("This invitation has expired", fasthttp.StatusGone)
		} else {
			log.Info().Str("inviteID", info.InviteID).Msg("Invitation reached maximum uses")
			ctx.Error("This invitation has reached maximum uses", fasthttp.StatusGone)
		}
		return
	}

	// Return invite info
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(info)
}

// CheckInvitationRequest represents the request body for checking invitation usage
type CheckInvitationRequest struct {
	Token         string `json:"token"`
	UserPublicKey string `json:"userPublicKey"`
}

// CheckInvitation handles POST /invites/check
// This is a public endpoint (no auth required) for checking if a user can use an invitation
func (ie *InvitationEndpoints) CheckInvitation(ctx *fasthttp.RequestCtx) {
	// Parse request body
	var req CheckInvitationRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		log.Error().Err(err).Msg("Failed to parse request body")
		ctx.Error("Invalid request body", fasthttp.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Token == "" {
		ctx.Error("Token is required", fasthttp.StatusBadRequest)
		return
	}
	if req.UserPublicKey == "" {
		ctx.Error("User public key is required", fasthttp.StatusBadRequest)
		return
	}

	// Check invitation usage
	result, err := ie.invitationService.CheckInvitationUsage(req.Token, req.UserPublicKey)
	if err != nil {
		log.Error().Err(err).Msg("Failed to check invitation usage")
		ctx.Error("Failed to check invitation", fasthttp.StatusInternalServerError)
		return
	}

	// Return result
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(result)
}

// JoinRequest represents the request body for joining via invitation
type JoinRequest struct {
	PublicKey string `json:"publicKey"`
	Username  string `json:"username"`
}

// JoinApplication handles POST /invites/{token}/join
// This is a PUBLIC endpoint (no authentication required)
// It will create the user if they don't exist
func (ie *InvitationEndpoints) JoinApplication(ctx *fasthttp.RequestCtx) {
	log.Debug().Msg("[JOIN] Join application request received")

	// Extract token from path
	token := ctx.UserValue("token").(string)
	if token == "" {
		log.Error().Msg("[JOIN] Token is missing")
		ctx.Error("Token is required", fasthttp.StatusBadRequest)
		return
	}

	// Parse request body to get user info
	var req JoinRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		log.Error().Err(err).Msg("[JOIN] Failed to parse request body")
		ctx.Error("Invalid request body", fasthttp.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.PublicKey == "" {
		log.Error().Msg("[JOIN] Public key is missing")
		ctx.Error("Public key is required", fasthttp.StatusBadRequest)
		return
	}
	if req.Username == "" {
		log.Error().Msg("[JOIN] Username is missing")
		ctx.Error("Username is required", fasthttp.StatusBadRequest)
		return
	}

	log.Debug().Str("username", req.Username).Str("token", token).Msg("[JOIN] Joining application")

	// Join via invitation service (handles user creation, validation, transaction, event production)
	result, err := ie.invitationService.Join(token, req.PublicKey, req.Username)
	if err != nil {
		log.Error().Err(err).Msg("Failed to join application")

		// Determine appropriate status code based on error message
		errorMsg := err.Error()
		switch {
		case errorMsg == "invalid token: failed to parse token: token is expired":
			ctx.Error("Invitation expired", fasthttp.StatusGone)
		case errorMsg == "invitation expired":
			ctx.Error("Invitation expired", fasthttp.StatusGone)
		case errorMsg == "invitation has reached maximum uses":
			ctx.Error("Invitation has reached maximum uses", fasthttp.StatusGone)
		case errorMsg == "invitation not found or revoked: invitation not found":
			ctx.Error("Invitation not found or revoked", fasthttp.StatusNotFound)
		default:
			ctx.Error("Failed to join application", fasthttp.StatusInternalServerError)
		}
		return
	}

	// Return success response
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(result)
}

// RevokeInvite handles DELETE /applications/{appID}/invites/{inviteID}
func (ie *InvitationEndpoints) RevokeInvite(ctx *fasthttp.RequestCtx) {
	// Get authenticated user from context
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	// Extract IDs from path
	appID := ctx.UserValue("appID").(string)
	inviteID := ctx.UserValue("inviteID").(string)

	if appID == "" || inviteID == "" {
		ctx.Error("Application ID and Invite ID are required", fasthttp.StatusBadRequest)
		return
	}

	// TODO: Verify user is owner of the application using authenticatedUser.PublicKey
	_ = authenticatedUser // Will be used in owner verification TODO

	// Get invitation to verify it exists
	invite, err := ie.invitationService.repo.GetByID(inviteID)
	if err != nil {
		log.Error().Err(err).Msg("Invitation not found")
		ctx.Error("Invitation not found", fasthttp.StatusNotFound)
		return
	}

	// Verify invite belongs to the application
	if invite.ApplicationID != appID {
		ctx.Error("Invitation does not belong to this application", fasthttp.StatusBadRequest)
		return
	}

	// Revoke invitation (hard delete)
	if err := ie.invitationService.RevokeInvitation(inviteID); err != nil {
		log.Error().Err(err).Msg("Failed to revoke invitation")
		ctx.Error("Failed to revoke invitation", fasthttp.StatusInternalServerError)
		return
	}

	// TODO: Produce invite_revoked event

	// Return success (204 No Content)
	ctx.SetStatusCode(fasthttp.StatusNoContent)
}

// ListInvites handles GET /applications/{appID}/invites
func (ie *InvitationEndpoints) ListInvites(ctx *fasthttp.RequestCtx) {
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

	// TODO: Verify user is owner or admin of the application

	_ = authenticatedUser // Will be used in TODO above

	// Get invites for application
	invites, err := ie.invitationService.GetInvitesForApp(appID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get invites")
		ctx.Error("Failed to get invites", fasthttp.StatusInternalServerError)
		return
	}

	// Return invites
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(invites)
}
