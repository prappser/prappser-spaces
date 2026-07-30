package invitation

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
)

const (
	MaxExpirationHours = 48
)

type EventService interface {
	AcceptEvent(ctx context.Context, e *event.Event, submitter *user.User) (*event.Event, error)
	ProduceEvent(ctx context.Context, e *event.Event) (*event.Event, error)
}

type InvitationService struct {
	repo           InvitationRepository
	privateKey     ed25519.PrivateKey
	publicKey      ed25519.PublicKey
	appRepo        application.ApplicationRepository
	db             *sql.DB
	userRepository user.UserRepository
	eventService   EventService
}

func NewInvitationService(repo InvitationRepository, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey, appRepo application.ApplicationRepository, db *sql.DB, userRepository user.UserRepository, eventService EventService) *InvitationService {
	return &InvitationService{
		repo:           repo,
		privateKey:     privateKey,
		publicKey:      publicKey,
		appRepo:        appRepo,
		db:             db,
		userRepository: userRepository,
		eventService:   eventService,
	}
}

// CreateInvitationOptions contains options for creating an invitation
type CreateInvitationOptions struct {
	ApplicationID      string
	CreatedByPublicKey string
	Role               string
	MaxUses            *int
	ExpiresInHours     *int
	SpaceID            *string
	SpaceURL           string
}

// CreateInvitation creates a new invitation and generates a JWT token
func (s *InvitationService) CreateInvitation(opts CreateInvitationOptions) (*InvitationResponse, error) {
	// Validate inputs
	if opts.ApplicationID == "" {
		return nil, fmt.Errorf("application ID is required")
	}
	if opts.CreatedByPublicKey == "" {
		return nil, fmt.Errorf("creator public key is required")
	}
	if opts.Role == "" {
		opts.Role = "member" // default
	}

	// Validate expiration
	if opts.ExpiresInHours != nil {
		if *opts.ExpiresInHours < 0 || *opts.ExpiresInHours > MaxExpirationHours {
			return nil, fmt.Errorf("expiration hours must be between 0 and %d", MaxExpirationHours)
		}
	}

	// Validate max uses
	if opts.MaxUses != nil && *opts.MaxUses < 1 {
		return nil, fmt.Errorf("max uses must be at least 1")
	}

	// Create invitation
	now := time.Now().Unix()
	invite := &Invitation{
		ID:                 uuid.New().String(), // TODO: Use UUID v7
		ApplicationID:      opts.ApplicationID,
		CreatedByPublicKey: opts.CreatedByPublicKey,
		Role:               opts.Role,
		MaxUses:            opts.MaxUses,
		UsedCount:          0,
		CreatedAt:          now,
		SpaceID:            opts.SpaceID,
	}

	// Save to database
	if err := s.repo.Create(invite); err != nil {
		return nil, fmt.Errorf("failed to create invitation: %w", err)
	}

	// Generate JWT token
	var expiresAt *int64
	if opts.ExpiresInHours != nil {
		exp := time.Now().Add(time.Duration(*opts.ExpiresInHours) * time.Hour).Unix()
		expiresAt = &exp
	}

	token, err := s.GenerateToken(invite.ID, opts.SpaceURL, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Build response - use HTTPS PWA URL for sharing
	pwaURL := "https://prappser-app.netlify.app"
	response := &InvitationResponse{
		ID:        invite.ID,
		Token:     token,
		URL:       fmt.Sprintf("%s/join?token=%s", pwaURL, token),
		DeepLink:  fmt.Sprintf("prappser://join?token=%s", token),
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}

	return response, nil
}

// GenerateToken creates a signed JWT token for an invitation
func (s *InvitationService) GenerateToken(inviteID, spaceURL string, expiresAt *int64) (string, error) {
	now := time.Now()

	issuedAt := now.Unix()
	notBefore := now.Unix()

	// Create token with custom claims
	mapClaims := jwt.MapClaims{
		"id":       inviteID,
		"spaceUrl": spaceURL,
		"iat":      issuedAt,
		"nbf":      notBefore,
	}
	// Only include exp claim if it's not nil (JWT requires exp to be numeric if present)
	if expiresAt != nil {
		mapClaims["exp"] = *expiresAt
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, mapClaims)

	// Sign token
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken verifies a JWT token and returns the claims
func (s *InvitationService) ValidateToken(tokenString string) (*InviteTokenClaims, error) {
	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method - accept EdDSA
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Extract claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		idStr, ok := claims["id"].(string)
		if !ok || idStr == "" {
			return nil, fmt.Errorf("missing or invalid id claim")
		}
		iatFloat, ok := claims["iat"].(float64)
		if !ok {
			return nil, fmt.Errorf("missing or invalid iat claim")
		}

		inviteClaims := &InviteTokenClaims{
			InviteID: idStr,
			IssuedAt: int64(iatFloat),
		}

		if spaceURL, ok := claims["spaceUrl"].(string); ok {
			inviteClaims.SpaceURL = spaceURL
		}

		if expFloat, ok := claims["exp"].(float64); ok {
			expInt := int64(expFloat)
			inviteClaims.ExpiresAt = &expInt
		}

		return inviteClaims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

// GetInviteInfo returns public information about an invitation (no auth required)
// This is used by the join screen to display invite details before authentication
func (s *InvitationService) GetInviteInfo(tokenString string) (*InviteInfo, error) {
	log.Debug().Msg("[INVITE] GetInviteInfo called")

	// Validate token
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		log.Debug().Err(err).Msg("[INVITE] Token validation failed")
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	log.Debug().
		Str("inviteId", claims.InviteID).
		Msg("[INVITE] Token validated")

	// Check expiration from JWT
	isExpired := false
	if claims.ExpiresAt != nil {
		isExpired = time.Now().Unix() > *claims.ExpiresAt
	}

	// Get invitation from database
	invite, err := s.repo.GetByID(claims.InviteID)
	if err != nil {
		log.Debug().
			Str("inviteId", claims.InviteID).
			Err(err).
			Msg("[INVITE] Invite not found in database")
		return &InviteInfo{
			InviteID:  claims.InviteID,
			IsExpired: isExpired,
			IsValid:   false,
		}, nil
	}
	log.Debug().
		Str("inviteId", invite.ID).
		Msg("[INVITE] Invite found in database")

	// Check max uses
	isMaxUsesReached := false
	if invite.MaxUses != nil && invite.UsedCount >= *invite.MaxUses {
		isMaxUsesReached = true
	}

	// Fetch actual application name
	log.Debug().
		Str("appId", invite.ApplicationID).
		Msg("[INVITE] Fetching application details")
	applicationName := "Unknown Application"
	var applicationIcon *string
	app, err := s.appRepo.GetApplicationByID(invite.ApplicationID)
	if err == nil && app != nil {
		applicationName = app.Name
		applicationIcon = app.Icon
		log.Debug().
			Str("appName", app.Name).
			Msg("[INVITE] Application found")
	} else {
		log.Debug().
			Err(err).
			Msg("[INVITE] Application fetch failed, using fallback")
	}

	// Fetch actual creator username
	log.Debug().
		Str("publicKey", invite.CreatedByPublicKey[:min(20, len(invite.CreatedByPublicKey))]+"...").
		Msg("[INVITE] Fetching creator details")
	creatorUsername := "Unknown User"
	creator, err := s.userRepository.GetUserByPublicKey(invite.CreatedByPublicKey)
	if err == nil && creator != nil {
		creatorUsername = creator.Username
		log.Debug().
			Str("username", creator.Username).
			Msg("[INVITE] Creator found")
	} else {
		log.Debug().
			Err(err).
			Msg("[INVITE] Creator fetch failed, using fallback")
	}

	info := &InviteInfo{
		InviteID:        invite.ID,
		ApplicationName: applicationName,
		ApplicationIcon: applicationIcon,
		CreatorUsername: creatorUsername,
		Role:            invite.Role,
		ExpiresAt:       claims.ExpiresAt,
		IsExpired:       isExpired,
		IsValid:         !isExpired && !isMaxUsesReached,
	}

	log.Debug().
		Str("inviteId", invite.ID).
		Bool("isValid", info.IsValid).
		Bool("isExpired", isExpired).
		Bool("isMaxUsesReached", isMaxUsesReached).
		Msg("[INVITE] GetInviteInfo complete")

	return info, nil
}

// GetInviteIconStorageID resolves the storage ID for an invite's application icon (no auth required),
// along with the invite's application ID so callers can verify the storage object actually belongs
// to that application. The JWT's own expiry is still enforced by ValidateToken; only the invite's
// max-uses/revocation-style checks are deliberately skipped here - the icon is not sensitive, and the
// join dialog already surfaces an error state for expired/exhausted invites via
// GetInviteInfo/CheckInvitationUsage.
func (s *InvitationService) GetInviteIconStorageID(tokenString string) (storageID string, applicationID string, err error) {
	log.Debug().Msg("[INVITE] GetInviteIconStorageID called")

	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		log.Debug().Err(err).Msg("[INVITE] Token validation failed")
		return "", "", fmt.Errorf("invalid token: %w", err)
	}
	log.Debug().
		Str("inviteId", claims.InviteID).
		Msg("[INVITE] Token validated")

	invite, err := s.repo.GetByID(claims.InviteID)
	if err != nil {
		log.Debug().
			Str("inviteId", claims.InviteID).
			Err(err).
			Msg("[INVITE] Invite not found in database")
		return "", "", fmt.Errorf("invite not found: %w", err)
	}

	app, err := s.appRepo.GetApplicationByID(invite.ApplicationID)
	if err != nil || app == nil {
		log.Debug().
			Str("appId", invite.ApplicationID).
			Err(err).
			Msg("[INVITE] Application fetch failed")
		return "", "", fmt.Errorf("application not found: %w", err)
	}

	if app.Icon == nil || !strings.HasPrefix(*app.Icon, "storage:") {
		log.Debug().
			Str("appId", invite.ApplicationID).
			Msg("[INVITE] Application has no custom storage icon")
		return "", "", fmt.Errorf("application has no custom icon")
	}

	return strings.TrimPrefix(*app.Icon, "storage:"), invite.ApplicationID, nil
}

// CheckInvitationUsage checks if an invitation can be used by a specific user
func (s *InvitationService) CheckInvitationUsage(tokenString, userPublicKey string) (*CheckInvitationResult, error) {
	result := &CheckInvitationResult{
		Valid:          false,
		AlreadyUsed:    false,
		IsMember:       false,
		IsExpired:      false,
		MaxUsesReached: false,
	}

	// Validate token
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		result.Message = "Invalid or malformed invitation link"
		return result, nil
	}

	// Check expiration
	if claims.ExpiresAt != nil && time.Now().Unix() > *claims.ExpiresAt {
		result.IsExpired = true
		result.Message = "This invitation has expired"
		return result, nil
	}

	// Get invitation
	invite, err := s.repo.GetByID(claims.InviteID)
	if err != nil {
		result.Message = "Invitation not found or has been revoked"
		return result, nil
	}

	// Get application info
	app, err := s.appRepo.GetApplicationByID(invite.ApplicationID)
	if err == nil && app != nil {
		result.ApplicationName = app.Name
	}
	result.Role = invite.Role

	// Check max uses
	if invite.MaxUses != nil && invite.UsedCount >= *invite.MaxUses {
		result.MaxUsesReached = true
		result.Message = "This invitation has reached its maximum number of uses"
		return result, nil
	}

	// Check if user has already used this invitation
	alreadyUsed, err := s.repo.HasBeenUsedBy(invite.ID, userPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check invitation usage: %w", err)
	}

	if alreadyUsed {
		// Check if still a member
		isMember, _ := s.appRepo.IsMember(invite.ApplicationID, userPublicKey)
		result.IsMember = isMember

		if isMember {
			// User is still a member - cannot rejoin
			result.AlreadyUsed = true
			result.Message = "You have already joined this application"
			return result, nil
		}

		// User previously joined but is no longer a member - allow rejoin
		// Fall through to normal validation (treat as new join)
	}

	// Check if user is already a member (without using invitation)
	isMember, err := s.appRepo.IsMember(invite.ApplicationID, userPublicKey)
	if err == nil && isMember {
		result.IsMember = true
		result.Message = "You are already a member of this application"
		return result, nil
	}

	// Invitation is valid and can be used
	result.Valid = true
	result.Message = "Invitation is valid and ready to use"
	return result, nil
}

// RevokeInvitation deletes an invitation (hard delete)
func (s *InvitationService) RevokeInvitation(inviteID string) error {
	return s.repo.Delete(inviteID)
}

// GetInvitesForApp returns all active invitations for an application
func (s *InvitationService) GetInvitesForApp(appID string) ([]*Invitation, error) {
	return s.repo.GetByApplicationID(appID)
}

// JoinResult contains the result of a successful join operation
type JoinResult struct {
	ApplicationID string `json:"applicationId"`
	MemberID      string `json:"memberId"`
	IsNewMember   bool   `json:"isNewMember"`
	LastEventID   string `json:"lastEventId,omitempty"`
}

// Join handles the complete join flow with transaction. devicePublicKey is
// optional; when empty it defaults to userPublicKey (device #1's key equals
// the account key).
func (s *InvitationService) Join(tokenString, userPublicKey, userName, devicePublicKey string) (*JoinResult, error) {
	log.Debug().
		Str("username", userName).
		Str("publicKey", userPublicKey[:min(20, len(userPublicKey))]+"...").
		Msg("[INVITE] Join attempt started")

	// Validate token
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		log.Debug().Err(err).Msg("[INVITE] Join failed: token validation failed")
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	log.Debug().
		Str("inviteId", claims.InviteID).
		Msg("[INVITE] Token validated")

	// Check expiration
	if claims.ExpiresAt != nil && time.Now().Unix() > *claims.ExpiresAt {
		log.Debug().
			Str("inviteId", claims.InviteID).
			Msg("[INVITE] Join failed: invitation expired")
		return nil, fmt.Errorf("invitation expired")
	}

	// Get invitation
	invite, err := s.repo.GetByID(claims.InviteID)
	if err != nil {
		log.Debug().
			Str("inviteId", claims.InviteID).
			Err(err).
			Msg("[INVITE] Join failed: invitation not found")
		return nil, fmt.Errorf("invitation not found or revoked: %w", err)
	}
	log.Debug().
		Str("inviteId", invite.ID).
		Str("appId", invite.ApplicationID).
		Msg("[INVITE] Invitation found")

	// Check max uses
	if invite.MaxUses != nil && invite.UsedCount >= *invite.MaxUses {
		log.Debug().
			Str("inviteId", invite.ID).
			Int("usedCount", invite.UsedCount).
			Int("maxUses", *invite.MaxUses).
			Msg("[INVITE] Join failed: max uses reached")
		return nil, fmt.Errorf("invitation has reached maximum uses")
	}

	// Create user if doesn't exist (for member authentication)
	log.Debug().Str("publicKey", userPublicKey[:min(20, len(userPublicKey))]+"...").Str("username", userName).Msg("[JOIN_SERVICE] Checking if user exists")
	existingUser, err := s.userRepository.GetUserByPublicKey(userPublicKey)
	isNewAccount := err != nil || existingUser == nil
	if isNewAccount {
		log.Debug().Str("username", userName).Msg("[JOIN_SERVICE] User not found, creating member user")

		// Validate public key is not empty
		if userPublicKey == "" {
			return nil, fmt.Errorf("public key cannot be empty")
		}

		// Create user with guest role
		newUser := &user.User{
			PublicKey: userPublicKey,
			Username:  userName,
			Role:      user.RoleGuest,
			CreatedAt: time.Now().Unix(),
		}

		if err := s.userRepository.CreateUser(newUser); err != nil {
			log.Error().Err(err).Str("username", userName).Msg("[JOIN_SERVICE] Failed to create user")
			return nil, fmt.Errorf("failed to create user: %w", err)
		}

		log.Debug().Str("username", userName).Msg("[JOIN_SERVICE] User created successfully")

		// Re-fetch so existingUser is populated for the event payload below
		existingUser, err = s.userRepository.GetUserByPublicKey(userPublicKey)
		if err != nil || existingUser == nil {
			return nil, fmt.Errorf("failed to fetch newly created user: %w", err)
		}
	} else {
		log.Debug().Str("username", userName).Msg("[JOIN_SERVICE] User already exists")
	}

	// Join is PUBLIC and unauthenticated - it never proves possession of
	// userPublicKey's private key. A client-supplied devicePublicKey is only
	// honored on the new-account branch, where it names the caller's own
	// brand-new account and device together. For an EXISTING account, a
	// caller presenting any valid invite token could otherwise bind an
	// arbitrary device key to someone else's account and mint JWTs as them -
	// so existing accounts always get device #1 (their own key) regardless
	// of what the request claims, and adding further devices to an existing
	// account must go through the delegation flow in RegisterDevice.
	joiningDevicePublicKey := userPublicKey
	if isNewAccount && devicePublicKey != "" {
		joiningDevicePublicKey = devicePublicKey
	}
	if err := s.userRepository.EnsureDevice(joiningDevicePublicKey, userPublicKey, nil, time.Now().Unix()); err != nil {
		log.Error().Err(err).Str("username", userName).Msg("[JOIN_SERVICE] Failed to ensure device")
		return nil, fmt.Errorf("failed to ensure device: %w", err)
	}

	// Check if user is already a member (idempotent)
	isMember, err := s.appRepo.IsMember(invite.ApplicationID, userPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check membership: %w", err)
	}

	if isMember {
		// User is already a member - return success with existing data (idempotent)
		log.Debug().
			Str("applicationId", invite.ApplicationID).
			Str("userPublicKey", userPublicKey[:min(20, len(userPublicKey))]+"...").
			Msg("[JOIN_SERVICE] User is already a member, returning success (idempotent)")

		member, err := s.appRepo.GetMemberByPublicKey(invite.ApplicationID, userPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get member: %w", err)
		}

		return &JoinResult{
			ApplicationID: invite.ApplicationID,
			MemberID:      member.ID,
			IsNewMember:   false,
		}, nil
	}

	// Build member_added event data with user snapshot at time of joining
	memberAddedData := map[string]interface{}{
		"applicationId":   invite.ApplicationID,
		"memberPublicKey": userPublicKey,
		"userDisplayName": existingUser.Username,
		"role":            invite.Role,
		"inviteId":        invite.ID,
		"version":         1,
	}
	if existingUser.AvatarStorageID != nil {
		memberAddedData["userAvatarStorageId"] = *existingUser.AvatarStorageID
	}

	// Create member_added event and submit it for execution
	// This creates the member record so the user can immediately access the application
	evt := &event.Event{
		ID:               uuid.New().String(),
		Type:             "member_added",
		CreatorPublicKey: userPublicKey,
		Data:             memberAddedData,
		CreatedAt:        time.Now().Unix(),
		ApplicationID:    invite.ApplicationID,
	}

	// Set space ID from invitation so the event is tagged to the correct space
	if invite.SpaceID != nil {
		evt.SpaceID = *invite.SpaceID
	}

	log.Debug().
		Str("eventId", evt.ID).
		Str("inviteId", invite.ID).
		Msg("[INVITE] Producing member_added event")

	// Produce event (validates, sequences, persists, and executes - no authorization needed)
	// Authorization was already done by validating the invitation token
	producedEvt, err := s.eventService.ProduceEvent(context.Background(), evt)
	if err != nil {
		log.Error().
			Str("inviteId", invite.ID).
			Err(err).
			Msg("[INVITE] Failed to produce member_added event")
		return nil, fmt.Errorf("failed to produce member_added event: %w", err)
	}

	log.Debug().
		Str("applicationId", invite.ApplicationID).
		Str("userPublicKey", userPublicKey[:min(20, len(userPublicKey))]+"...").
		Msg("[INVITE] member_added event produced and executed")

	// Begin transaction for invitation usage tracking
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Increment invitation used count
	if err := s.repo.IncrementUseCount(invite.ID); err != nil {
		return nil, fmt.Errorf("failed to increment use count: %w", err)
	}

	// Record usage in invitation_uses table
	useID := uuid.New().String()
	if err := s.repo.RecordUse(invite.ID, userPublicKey, useID); err != nil {
		return nil, fmt.Errorf("failed to record invitation use: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Info().
		Str("inviteId", invite.ID).
		Str("applicationId", invite.ApplicationID).
		Str("username", userName).
		Str("userPublicKey", userPublicKey[:min(20, len(userPublicKey))]+"...").
		Str("role", invite.Role).
		Msg("[INVITE] Join successful - new member added")

	return &JoinResult{
		ApplicationID: invite.ApplicationID,
		MemberID:      "", // Member ID generated by event execution
		IsNewMember:   true,
		LastEventID:   producedEvt.ID,
	}, nil
}
