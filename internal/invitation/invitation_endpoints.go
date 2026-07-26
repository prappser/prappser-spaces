package invitation

import (
	"context"
	"io"
	"strconv"

	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/httputil"
	"github.com/prappser/prappser-spaces/internal/storage"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

// inviteIconResolver is the narrow interface Endpoints needs from *InvitationService.
type inviteIconResolver interface {
	GetInviteIconStorageID(token string) (storageID string, applicationID string, err error)
}

// iconStorageReader is the narrow interface Endpoints needs from *storage.Service.
type iconStorageReader interface {
	GetData(ctx context.Context, id string) (io.ReadCloser, *storage.Storage, error)
}

type InvitationEndpoints struct {
	invitationService   *InvitationService
	iconResolver        inviteIconResolver
	iconReader          iconStorageReader
	externalURLOverride string
}

func NewInvitationEndpoints(invitationService *InvitationService, storageService iconStorageReader, externalURLOverride string) *InvitationEndpoints {
	return &InvitationEndpoints{
		invitationService:   invitationService,
		iconResolver:        invitationService,
		iconReader:          storageService,
		externalURLOverride: externalURLOverride,
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
		SpaceID:            spaceIDPtr(authenticatedUser.SpaceID),
		SpaceURL:           httputil.PublicURL(ctx, ie.externalURLOverride),
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

// GetInviteInfo handles GET /invites/{token}
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
		log.Debug().Str("inviteID", info.InviteID).Msg("Invitation not found (revoked)")
		ctx.Error("This invitation has been revoked", fasthttp.StatusNotFound)
		return
	}

	// Check if invitation expired or reached max uses
	if !info.IsValid {
		if info.IsExpired {
			log.Debug().Str("inviteID", info.InviteID).Msg("Invitation expired")
			ctx.Error("This invitation has expired", fasthttp.StatusGone)
		} else {
			log.Debug().Str("inviteID", info.InviteID).Msg("Invitation reached maximum uses")
			ctx.Error("This invitation has reached maximum uses", fasthttp.StatusGone)
		}
		return
	}

	// Return invite info
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(info)
}

// GetInviteIcon handles GET /invites/{token}/icon
// This is a public endpoint (no auth required) gated only by a valid invite token.
// The icon is not sensitive, so this deliberately does not check expiry or max-uses.
func (ie *InvitationEndpoints) GetInviteIcon(ctx *fasthttp.RequestCtx) {
	token, _ := ctx.UserValue("token").(string)
	if token == "" {
		ctx.Error("Token is required", fasthttp.StatusBadRequest)
		return
	}

	storageID, applicationID, err := ie.iconResolver.GetInviteIconStorageID(token)
	if err != nil {
		log.Debug().Err(err).Msg("[INVITE] Failed to resolve invite icon storage ID")
		ctx.Error("Icon not found", fasthttp.StatusNotFound)
		return
	}

	reader, stored, err := ie.iconReader.GetData(ctx, storageID)
	if err != nil {
		log.Debug().Err(err).Str("storageId", storageID).Msg("[INVITE] Failed to load invite icon data")
		ctx.Error("Icon not found", fasthttp.StatusNotFound)
		return
	}
	defer reader.Close()

	if stored.Status != string(storage.StorageStatusReady) {
		ctx.Error("Icon not found", fasthttp.StatusNotFound)
		return
	}

	// Storage.ApplicationID is nil for space-scoped uploads (avatars, and app icons uploaded during
	// initial app registration, which have no app context yet). Only reject when the storage object
	// is explicitly tied to a DIFFERENT application than the invite - this catches the IDOR where an
	// attacker points their own app's Icon field at a victim's app-scoped storage ID.
	// Residual gap: a storage object with a nil ApplicationID can still be cross-referenced by another
	// application's Icon field. That's a deliberate trade-off - tightening it would 404 the common
	// case of registration-time icons, which are uploaded with no app context at all.
	if stored.ApplicationID != nil && *stored.ApplicationID != applicationID {
		log.Warn().
			Str("storageId", storageID).
			Str("storageApplicationId", *stored.ApplicationID).
			Str("inviteApplicationId", applicationID).
			Msg("[INVITE] Rejected invite icon request: storage object belongs to a different application")
		ctx.Error("Icon not found", fasthttp.StatusNotFound)
		return
	}

	ctx.SetContentType(stored.ContentType)
	ctx.Response.Header.Set("Content-Length", strconv.FormatInt(stored.SizeBytes, 10))
	// Bytes are immutable per storageId, so this is safe to cache for a while. The token in the URL is
	// a bearer credential (same one accepted by /invites/{token}/join), so keep this private to avoid
	// inviting shared proxies/CDNs to retain a credential-bearing URL.
	ctx.Response.Header.Set("Cache-Control", "private, max-age=3600")

	if _, err := io.Copy(ctx, reader); err != nil {
		log.Error().Err(err).Str("storageId", storageID).Msg("[INVITE] Failed to stream invite icon")
	}
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

// spaceIDPtr converts a space ID string to a pointer, returning nil for empty strings.
func spaceIDPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
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
