package invitation

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
)

const (
	MaxExpirationHours = 48

	// pqUniqueViolation is the PostgreSQL SQLSTATE code for a unique
	// constraint violation - defined locally rather than shared from
	// internal/user, matching the same local-duplication convention as
	// internal/storage/service.go (see its doc comment) for a single string
	// literal.
	pqUniqueViolation = "23505"
)

// ErrDeviceConflict is returned by Join when an assertion's presented device
// key already belongs to a different account, or has been revoked (#111
// G6) - the caller should respond 409.
var ErrDeviceConflict = errors.New("device already registered to a different account")

// Sentinel errors for the #110 join-proof / grants-flags gates. Each maps to
// a distinct HTTP status in invitation_endpoints.go's error switch.
var (
	// ErrIdentityNotGranted is returned by Join when a space configured not
	// to anchor new accounts (grants_identity=false) is presented with a
	// brand-new, non-assertion-backed account (D6).
	ErrIdentityNotGranted = errors.New("invitation does not grant identity")
	// ErrMembershipNotGranted is returned by Join for a preview-only invite
	// (grants_membership=false) - defence in depth, since no real
	// membership-free preview exists yet (D7).
	ErrMembershipNotGranted = errors.New("invitation does not grant membership")
	// ErrAccountKeyNotProven is returned by Join when a non-assertion-backed
	// request presents a device key that neither equals the account's own
	// public key nor is an already-enrolled, unrevoked device of that same
	// account (D5/G2).
	ErrAccountKeyNotProven = errors.New("account key not proven")
	// ErrMaxUsesReached is returned by InvitationRepository.IncrementUseCount
	// when the atomic claim loses a TOCTOU race against another concurrent
	// join (D11).
	ErrMaxUsesReached = errors.New("invitation has reached maximum uses")
	// ErrNotAppAuthorized is returned by AuthorizeAppRole when the caller is
	// not a member of the application, or holds a role outside the allowed
	// set (#125) - invitation_endpoints.go maps it to 403.
	ErrNotAppAuthorized = errors.New("not authorized for this application")
)

// memberNotFoundMsg is the exact error string both application.Repository
// and application.MemoryRepository return from GetMemberByPublicKey for "no
// rows" - neither wraps it with %w, so AuthorizeAppRole compares by message
// (#125) to tell a not-found lookup apart from a real DB error.
const memberNotFoundMsg = "member not found"

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
	// spacePublicKey is this space's own base64-encoded Ed25519 public key -
	// the expected audience for an assertion presented on Join (#111).
	spacePublicKey string
}

func NewInvitationService(repo InvitationRepository, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey, appRepo application.ApplicationRepository, db *sql.DB, userRepository user.UserRepository, eventService EventService, spacePublicKey string) *InvitationService {
	return &InvitationService{
		repo:           repo,
		privateKey:     privateKey,
		publicKey:      publicKey,
		appRepo:        appRepo,
		db:             db,
		userRepository: userRepository,
		eventService:   eventService,
		spacePublicKey: spacePublicKey,
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
	// GrantsMembership and GrantsIdentity are nil-means-true (wire spec):
	// nil defaults to true, matching the DB column defaults.
	GrantsMembership *bool
	GrantsIdentity   *bool
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

	// [D8] grantsMembership/grantsIdentity default to true. A preview-only
	// invite (grantsMembership=false) can never mint identities either -
	// forcing grantsIdentity off here deletes that nonsense state before it
	// ever reaches the row.
	grantsMembership := true
	if opts.GrantsMembership != nil {
		grantsMembership = *opts.GrantsMembership
	}
	grantsIdentity := true
	if opts.GrantsIdentity != nil {
		grantsIdentity = *opts.GrantsIdentity
	}
	if !grantsMembership {
		grantsIdentity = false
	}

	// [D9] Identity-granting invites default to single-use - a multi-use
	// link that mints identities is an account-farm vector. An explicit
	// maxUses always wins.
	maxUses := opts.MaxUses
	if grantsIdentity && maxUses == nil {
		one := 1
		maxUses = &one
	}

	// Create invitation
	now := time.Now().Unix()
	invite := &Invitation{
		ID:                 uuid.New().String(), // TODO: Use UUID v7
		ApplicationID:      opts.ApplicationID,
		CreatedByPublicKey: opts.CreatedByPublicKey,
		Role:               opts.Role,
		MaxUses:            maxUses,
		UsedCount:          0,
		CreatedAt:          now,
		SpaceID:            opts.SpaceID,
		GrantsMembership:   grantsMembership,
		GrantsIdentity:     grantsIdentity,
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
			InviteID:         claims.InviteID,
			IsExpired:        isExpired,
			IsValid:          false,
			GrantsMembership: true,
			GrantsIdentity:   true,
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
		InviteID:         invite.ID,
		ApplicationName:  applicationName,
		ApplicationIcon:  applicationIcon,
		CreatorUsername:  creatorUsername,
		Role:             invite.Role,
		ExpiresAt:        claims.ExpiresAt,
		IsExpired:        isExpired,
		IsValid:          !isExpired && !isMaxUsesReached,
		GrantsMembership: invite.GrantsMembership,
		GrantsIdentity:   invite.GrantsIdentity,
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
		// [G5] Defaults for return paths before the invite row is loaded
		// below; overwritten with the real values once GetByID succeeds.
		GrantsMembership: true,
		GrantsIdentity:   true,
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

	// [G5] Now that the real invite row is loaded, every return path below
	// carries its actual flags instead of the pre-load defaults above.
	result.GrantsMembership = invite.GrantsMembership
	result.GrantsIdentity = invite.GrantsIdentity

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

// AuthorizeAppRole verifies that callerPublicKey is a member of appID
// holding one of the allowed roles (#125), closing the gap where any
// authenticated space user could manage another application's invites.
// Returns ErrNotAppAuthorized when the caller is not a member or holds a
// disallowed role. Other repository errors (real DB failures, not a
// not-found lookup) propagate as-is so the endpoint can surface a 500
// instead of silently treating them as unauthorized.
func (s *InvitationService) AuthorizeAppRole(appID, callerPublicKey string, allowed ...application.MemberRole) error {
	member, err := s.appRepo.GetMemberByPublicKey(appID, callerPublicKey)
	if err != nil {
		if err.Error() == memberNotFoundMsg {
			return ErrNotAppAuthorized
		}
		return err
	}

	for _, role := range allowed {
		if member.Role == role {
			return nil
		}
	}
	return ErrNotAppAuthorized
}

// RevokeInvitation deletes an invitation (hard delete) and produces an
// invite_revoked event (#125) so other members' clients pick up the change.
// invite is the already-fetched row (the caller, invitation_endpoints.go,
// already loaded it to check invite.ApplicationID == the path appID) - this
// takes it directly instead of re-fetching by ID, keeping one lookup total.
// revokedByPublicKey becomes the event's CreatorPublicKey - the caller was
// already verified as the application owner via AuthorizeAppRole before this
// runs. Event production uses ProduceEvent (skips authorization, like Join's
// member_added) since the endpoint already did that check; if it fails, only
// a warning is logged - the delete already happened, and RevokeInvite's own
// response to the client already reflects success.
func (s *InvitationService) RevokeInvitation(invite *Invitation, revokedByPublicKey string) error {
	if err := s.repo.Delete(invite.ID); err != nil {
		return err
	}

	evt := &event.Event{
		ID:               uuid.New().String(),
		Type:             event.EventTypeInviteRevoked,
		CreatorPublicKey: revokedByPublicKey,
		Data: map[string]interface{}{
			"version":       1,
			"applicationId": invite.ApplicationID,
			"inviteId":      invite.ID,
		},
		CreatedAt:     time.Now().Unix(),
		ApplicationID: invite.ApplicationID,
	}
	if invite.SpaceID != nil {
		evt.SpaceID = *invite.SpaceID
	}

	if _, err := s.eventService.ProduceEvent(context.Background(), evt); err != nil {
		log.Warn().Err(err).Str("inviteId", invite.ID).Msg("[INVITE] Failed to produce invite_revoked event")
	}

	return nil
}

// GetInvitesForApp returns all active invitations for an application
func (s *InvitationService) GetInvitesForApp(appID string) ([]*Invitation, error) {
	return s.repo.GetByApplicationID(appID)
}

// isUniqueViolation reports whether err is a Postgres unique constraint
// violation (see pqUniqueViolation) - used by Join to detect a concurrent
// create race on userPublicKey (#111 G9).
func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == pqUniqueViolation
}

// JoinResult contains the result of a successful join operation
type JoinResult struct {
	ApplicationID string `json:"applicationId"`
	MemberID      string `json:"memberId"`
	IsNewMember   bool   `json:"isNewMember"`
	LastEventID   string `json:"lastEventId,omitempty"`
}

// Join handles the complete join flow. proof is a signed join-proof JWS
// (join_proof.go) that carries the joining account's public key, username,
// and enrolling device's public key as claims, bound to this specific
// invite (D4) and signed by the enrolling device's own key (PoP, D3).
// assertion is optional (#111): a cross-space identity assertion vouching
// for the account named in proof, verified against this space's own key as
// audience and the proof's device public key as the bound device. See the
// doc comments below for exactly how it affects account creation and
// issuer pinning - an assertion never adds a device to an ALREADY-known
// account (D5). deviceName is optional (#127): a display name for the
// enrolling device, normalized once here into *string (nil when empty or
// invalid) - lenient, since Join never fails over a cosmetic field.
func (s *InvitationService) Join(tokenString, proof, assertion, deviceName string) (*JoinResult, error) {
	log.Debug().Msg("[INVITE] Join attempt started")

	var normalizedDeviceName *string
	if normalized, ok := user.NormalizeDeviceName(deviceName); ok {
		normalizedDeviceName = &normalized
	}

	// Validate token
	claims, err := s.ValidateToken(tokenString)
	if err != nil {
		log.Debug().Err(err).Msg("[INVITE] Join failed: token validation failed")
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	log.Debug().
		Str("inviteId", claims.InviteID).
		Msg("[INVITE] Token validated")

	now := time.Now()

	// [#110] Verify the join proof up front - it is the sole source of
	// userPublicKey/userName/presentedDevicePublicKey below, bound to this
	// invite (D4) and signed by the device it names (PoP, D3). Unlike the
	// old {publicKey, username, devicePublicKey} request fields, a mismatch
	// between the claimed account and the signing device is now
	// structurally impossible to smuggle past this point.
	proofClaims, err := verifyJoinProof(proof, claims.InviteID, now)
	if err != nil {
		log.Debug().Err(err).Msg("[JOIN] proof verification failed")
		return nil, err
	}
	userPublicKey := proofClaims.PublicKey
	userName := proofClaims.Username
	presentedDevicePublicKey := proofClaims.DevicePublicKey

	log.Debug().
		Str("username", userName).
		Str("publicKey", userPublicKey[:min(20, len(userPublicKey))]+"...").
		Msg("[INVITE] Join proof verified")

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

	// [D7] A preview-only invite never mints membership - reject before any
	// write. Defence in depth: no real membership-free preview exists yet,
	// this is what actually enforces the flag today.
	if !invite.GrantsMembership {
		log.Debug().Str("inviteId", invite.ID).Msg("[JOIN] Join failed: invitation does not grant membership")
		return nil, ErrMembershipNotGranted
	}

	// #111: verify the assertion (if any) up front - it is never touched
	// again below except for its Issuer, once we already know it's genuinely
	// about userPublicKey and bound to the device presenting it.
	assertionPresented := assertion != ""
	var assertionIssuer string
	if assertionPresented {
		verifiedClaims, err := user.VerifyAssertion(assertion, s.spacePublicKey, presentedDevicePublicKey, now)
		if err != nil {
			log.Debug().Err(err).Msg("[JOIN] assertion verification failed")
			return nil, fmt.Errorf("invalid assertion: %w", user.ErrInvalidAssertion)
		}
		if verifiedClaims.UserID != userPublicKey {
			log.Debug().Msg("[JOIN] assertion is for a different public key than presented")
			return nil, fmt.Errorf("invalid assertion: %w", user.ErrInvalidAssertion)
		}
		assertionIssuer = verifiedClaims.Issuer
	}

	// Create user if doesn't exist (for member authentication)
	log.Debug().Str("publicKey", userPublicKey[:min(20, len(userPublicKey))]+"...").Str("username", userName).Msg("[JOIN_SERVICE] Checking if user exists")
	existingUser, err := s.userRepository.GetUserByPublicKey(userPublicKey)
	isNewAccount := err != nil || existingUser == nil

	// [D6] grants_identity=false: a space that doesn't anchor new accounts
	// must reject a brand-new, non-assertion-backed account outright -
	// existing accounts and assertion-backed joins pass.
	if isNewAccount && !assertionPresented && !invite.GrantsIdentity {
		log.Debug().Msg("[JOIN] Join failed: invitation does not grant identity to a new account")
		return nil, ErrIdentityNotGranted
	}

	// [G2] PoP gate for every non-assertion join, not just new accounts: the
	// presented device key must either equal the account key, or already be
	// an enrolled, unrevoked device of that SAME account. Without this an
	// attacker could name a victim's publicKey while only proving possession
	// of their own, unrelated device key - for a known account that enrolls
	// the attacker's device against the victim's identity; for a brand-new
	// account it mints one nobody but the attacker can ever authenticate
	// into again. GetDevice returns nil for a key nobody has registered, so
	// this single gate also subsumes D5 for brand-new accounts.
	if !assertionPresented && presentedDevicePublicKey != userPublicKey {
		d, err := s.userRepository.GetDevice(presentedDevicePublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to look up device: %w", err)
		}
		if d == nil || d.UserPublicKey != userPublicKey || d.RevokedAt != nil {
			log.Debug().Msg("[JOIN] Join failed: presented device key not proven to belong to this account")
			return nil, ErrAccountKeyNotProven
		}
	}

	if isNewAccount {
		log.Debug().Str("username", userName).Msg("[JOIN_SERVICE] User not found, creating member user")

		// Validate public key is not empty
		if userPublicKey == "" {
			return nil, fmt.Errorf("public key cannot be empty")
		}

		if assertionPresented {
			// [G6] pre-create guard: reject if the presented device key
			// already belongs to a different account, or has been revoked -
			// before we ever create a row for it.
			d, err := s.userRepository.GetDevice(presentedDevicePublicKey)
			if err != nil {
				return nil, fmt.Errorf("failed to look up device: %w", err)
			}
			if d != nil && (d.UserPublicKey != userPublicKey || d.RevokedAt != nil) {
				return nil, ErrDeviceConflict
			}
		}

		// Create user with guest role. Issuer stays empty (COALESCE ->
		// self) on the plain-join path; an assertion pins it to the
		// vouching space (or, for a self-mint, the account's own key -
		// D9 - which is issuer==publicKey either way).
		newUser := &user.User{
			PublicKey: userPublicKey,
			Username:  userName,
			Role:      user.RoleGuest,
			CreatedAt: now.Unix(),
		}
		if assertionPresented {
			newUser.Issuer = assertionIssuer
		}

		if err := s.userRepository.CreateUser(newUser); err != nil {
			if assertionPresented && isUniqueViolation(err) {
				// [G9] Lost a create race to a concurrent join - fall
				// through to the known-account path below with the row
				// that won, instead of failing the whole join.
				log.Debug().Msg("[JOIN_SERVICE] Create race lost to a concurrent join, falling through to known-account path")
				isNewAccount = false
			} else {
				log.Error().Err(err).Str("username", userName).Msg("[JOIN_SERVICE] Failed to create user")
				return nil, fmt.Errorf("failed to create user: %w", err)
			}
		} else {
			log.Debug().Str("username", userName).Msg("[JOIN_SERVICE] User created successfully")
			// Join is PUBLIC and unauthenticated - it never proves
			// possession of userPublicKey's private key on its own. A
			// client-supplied devicePublicKey is only ever honored here,
			// for a BRAND-NEW account, where the caller names its own
			// account and device together (and, with an assertion present,
			// the dpk binding already proved possession of that device).
			if err := s.userRepository.EnsureDevice(presentedDevicePublicKey, userPublicKey, normalizedDeviceName, now.Unix()); err != nil {
				log.Error().Err(err).Str("username", userName).Msg("[JOIN_SERVICE] Failed to ensure device")
				return nil, fmt.Errorf("failed to ensure device: %w", err)
			}
		}

		// Re-fetch so existingUser is populated for the event payload below
		// (also picks up the row that won the create race above).
		existingUser, err = s.userRepository.GetUserByPublicKey(userPublicKey)
		if err != nil || existingUser == nil {
			return nil, fmt.Errorf("failed to fetch newly created user: %w", err)
		}
	} else {
		log.Debug().Str("username", userName).Msg("[JOIN_SERVICE] User already exists")
	}

	if !isNewAccount {
		// KNOWN ACCOUNT - existing accounts always keep device #1 (their
		// own key) regardless of what the request claims; adding further
		// devices to an existing account must go through the delegation
		// flow in RegisterDevice. An assertion NEVER adds a device here
		// either (D5) - the only EnsureDevice on the assertion path is in
		// the row-creating branch above.
		issuer := existingUser.Issuer
		if assertionPresented {
			if issuer == existingUser.PublicKey && assertionIssuer != issuer {
				// D5: one-way self->vouched re-pin. UpdateUserIssuer's own
				// SQL guard (WHERE issuer = public_key) enforces this is
				// only ever applied to a still-self-pinned account.
				if err := s.userRepository.UpdateUserIssuer(existingUser.PublicKey, assertionIssuer); err != nil {
					return nil, fmt.Errorf("failed to update user issuer: %w", err)
				}
				log.Info().
					Str("publicKey", existingUser.PublicKey[:min(20, len(existingUser.PublicKey))]+"...").
					Str("issuer", assertionIssuer).
					Msg("[ASSERTION] Re-pinned self->vouched")
				issuer = assertionIssuer
			} else if issuer != existingUser.PublicKey && assertionIssuer != issuer {
				log.Warn().
					Str("pinnedIssuer", issuer).
					Str("presentedIssuer", assertionIssuer).
					Msg("[ASSERTION] Ignoring different issuer for already-pinned account")
			}
		}

		// Legacy roster backfill, narrowed to self-registered accounts only
		// (#111 G3) - a vouched account got a real device row at first
		// contact and must never have the account key backfilled into it.
		if issuer == existingUser.PublicKey {
			devices, err := s.userRepository.ListDevices(userPublicKey)
			if err != nil {
				return nil, fmt.Errorf("failed to list devices: %w", err)
			}
			if len(devices) == 0 {
				// row is the account key, not necessarily this joining
				// device - the name is only actually right when the joiner
				// IS the account-key device. Cosmetic and renameable, so no
				// branch to special-case the mismatch.
				if err := s.userRepository.EnsureDevice(userPublicKey, userPublicKey, normalizedDeviceName, now.Unix()); err != nil {
					log.Error().Err(err).Str("username", userName).Msg("[JOIN_SERVICE] Failed to ensure device")
					return nil, fmt.Errorf("failed to ensure device: %w", err)
				}
			}
		}
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

	// [D11] Atomically claim a use before producing the event - the
	// conditional UPDATE in IncrementUseCount closes the TOCTOU race the
	// earlier precheck alone can't. This never ran for the already-a-member
	// path above, which returns before reaching here.
	// ponytail: a raced single-use invite can still orphan a created account
	// if this claim fails after CreateUser already ran above - the account
	// row persists but membership never happens (bounded blast radius: no
	// membership grant). A proper fix claims the use before user creation
	// and needs rework of the idempotent re-join path.
	if err := s.repo.IncrementUseCount(invite.ID); err != nil {
		log.Debug().
			Str("inviteId", invite.ID).
			Err(err).
			Msg("[INVITE] Join failed: could not claim invitation use")
		return nil, fmt.Errorf("failed to claim invitation use: %w", err)
	}

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

	// Record usage in invitation_uses table. No transaction wrapper here -
	// the previous s.db.Begin()/Commit() never actually enclosed
	// IncrementUseCount and RecordUse in anything but its own connection;
	// both repo calls use s.db directly, so it provided no atomicity.
	useID := uuid.New().String()
	if err := s.repo.RecordUse(invite.ID, userPublicKey, useID); err != nil {
		return nil, fmt.Errorf("failed to record invitation use: %w", err)
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
