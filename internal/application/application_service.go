package application

import (
	"errors"
	"fmt"
	"time"

	"github.com/prappser/prappser-spaces/internal/user"
)

// Event represents a domain event (avoiding import cycle with event package)
type Event struct {
	ID               string
	Type             string
	CreatorPublicKey string
	Data             map[string]interface{}
	CreatedAt        int64
	ApplicationID    string
	SequenceNumber   int64
}

// EventProducer interface removed - events are now client-produced via POST /events
// Server only validates, sequences, and applies events

var (
	ErrAppLimitReached = errors.New("app limit reached")
	ErrOwnerNotCaller  = errors.New("application owner must be the caller")
	ErrAgentReadOff    = errors.New("agent access is off for this application")
	ErrNotMember       = errors.New("unauthorized: not a member of this application")
)

type ApplicationService struct {
	appRepo           ApplicationRepository
	maxAppsPerAccount int
	spacePublicKey    string
}

func NewApplicationService(appRepo ApplicationRepository, maxAppsPerAccount int, spacePublicKey string) *ApplicationService {
	return &ApplicationService{
		appRepo:           appRepo,
		maxAppsPerAccount: maxAppsPerAccount,
		spacePublicKey:    spacePublicKey,
	}
}

func (s *ApplicationService) RegisterApplication(caller *user.User, app *Application) (*Application, error) {
	if caller == nil || caller.PublicKey == "" {
		return nil, fmt.Errorf("caller public key is required")
	}
	if app.ID == "" {
		return nil, fmt.Errorf("application ID cannot be empty")
	}
	if app.Name == "" {
		return nil, fmt.Errorf("application name cannot be empty")
	}

	var owner *Member
	ownerCount := 0
	for i, member := range app.Members {
		if member.ID == "" {
			return nil, fmt.Errorf("member ID cannot be empty")
		}
		if member.Role == MemberRoleOwner {
			ownerCount++
			owner = &app.Members[i]
		}
	}
	if ownerCount == 0 {
		return nil, fmt.Errorf("application must have at least one owner member")
	}
	if ownerCount > 1 {
		return nil, fmt.Errorf("application must have exactly one owner member")
	}
	for _, group := range app.ComponentGroups {
		if group.ID == "" {
			return nil, fmt.Errorf("component group ID cannot be empty")
		}
		for _, component := range group.Components {
			if component.ID == "" {
				return nil, fmt.Errorf("component ID cannot be empty")
			}
		}
	}

	if owner.PublicKey != caller.PublicKey {
		return nil, ErrOwnerNotCaller
	}

	other, err := s.appRepo.HasOtherOwner(app.ID, caller.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check application owner: %w", err)
	}
	if other {
		return nil, ErrNotApplicationOwner
	}

	app.SpacePublicKey = &s.spacePublicKey
	if caller.SpaceID != "" {
		app.SpaceID = &caller.SpaceID
	}

	if s.maxAppsPerAccount > 0 && caller.Role != user.RoleOwner {
		live, err := s.appRepo.IsApplicationLive(app.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to check application existence: %w", err)
		}
		if !live {
			count, err := s.appRepo.CountOwnedApplications(caller.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("failed to count applications: %w", err)
			}
			if count >= s.maxAppsPerAccount {
				return nil, fmt.Errorf("%w: limit is %d", ErrAppLimitReached, s.maxAppsPerAccount)
			}
		}
	}

	if err := s.appRepo.MoveGuard(app.ID, caller.PublicKey, true); err != nil {
		var moved *MovedError
		if errors.Is(err, ErrApplicationMoving) {
			return nil, err
		}
		if !errors.As(err, &moved) {
			return nil, fmt.Errorf("failed to check move state: %w", err)
		}
	}

	now := time.Now().Unix()
	app.CreatedAt = now
	app.UpdatedAt = now

	if err := s.appRepo.RegisterApplication(app); err != nil {
		return nil, fmt.Errorf("failed to register application: %w", err)
	}

	return s.appRepo.GetApplicationByID(app.ID)
}

func (s *ApplicationService) GetApplication(appID string, requestingUser *user.User) (*Application, error) {
	if err := s.appRepo.MoveGuard(appID, requestingUser.PublicKey, false); err != nil {
		return nil, err
	}
	app, err := s.appRepo.GetApplicationByID(appID)
	if err != nil {
		return nil, err
	}

	// Verify membership - user must be a member of the application
	isMember, err := s.appRepo.IsMember(appID, requestingUser.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check membership: %w", err)
	}
	if !isMember {
		return nil, ErrNotMember
	}
	if !app.AgentAllowed(requestingUser) {
		return nil, ErrAgentReadOff
	}

	return app, nil
}

func (s *ApplicationService) GetApplicationState(appID string, requestingUser *user.User) (*ApplicationState, error) {
	if err := s.appRepo.MoveGuard(appID, requestingUser.PublicKey, false); err != nil {
		return nil, err
	}
	state, err := s.appRepo.GetApplicationState(appID)
	if err != nil {
		return nil, err
	}

	// Verify membership - user must be a member of the application
	isMember, err := s.appRepo.IsMember(appID, requestingUser.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to check membership: %w", err)
	}
	if !isMember {
		return nil, ErrNotMember
	}

	return state, nil
}

func (s *ApplicationService) ListApplications(caller *user.User) ([]*Application, error) {
	apps, err := s.appRepo.GetApplicationsByMemberPublicKey(caller.PublicKey)
	if err != nil {
		return nil, err
	}
	allowed := apps[:0]
	for _, app := range apps {
		if app.AgentAllowed(caller) {
			allowed = append(allowed, app)
		}
	}
	return allowed, nil
}

func (s *ApplicationService) SetAgentRead(appID string, caller *user.User, enabled bool) error {
	if err := s.appRepo.MoveGuard(appID, caller.PublicKey, true); err != nil {
		return err
	}
	app, err := s.appRepo.GetApplicationByID(appID)
	if err != nil {
		return err
	}
	ownerPublicKey, err := app.GetOwnerPublicKey()
	if err != nil {
		return fmt.Errorf("failed to get owner: %w", err)
	}
	if ownerPublicKey != caller.PublicKey {
		return ErrNotApplicationOwner
	}
	return s.appRepo.SetAgentReadEnabled(appID, enabled)
}

func (s *ApplicationService) DeleteApplication(appID string, requestingUser *user.User) error {
	if err := s.appRepo.MoveGuard(appID, requestingUser.PublicKey, true); err != nil {
		return err
	}
	// First verify the application exists and the user owns it
	app, err := s.appRepo.GetApplicationByID(appID)
	if err != nil {
		return err
	}

	// Verify ownership
	ownerPublicKey, err := app.GetOwnerPublicKey()
	if err != nil {
		return fmt.Errorf("failed to get owner: %w", err)
	}
	if ownerPublicKey != requestingUser.PublicKey {
		return fmt.Errorf("unauthorized")
	}

	// Delete the application
	// Note: Client will submit application_deleted event via POST /events
	if err := s.appRepo.DeleteApplication(appID); err != nil {
		// TODO: Consider compensating event if deletion fails
		return fmt.Errorf("failed to delete application: %w", err)
	}

	return nil
}

// LeaveApplication validates that the user is a member of the application.
// In the client-produced events architecture, this endpoint is deprecated.
// Clients should submit member_removed or application_deleted events via POST /events.
// This method is kept for backward compatibility but just performs validation.
func (s *ApplicationService) LeaveApplication(appID string, requestingUser *user.User) error {
	if err := s.appRepo.MoveGuard(appID, requestingUser.PublicKey, false); err != nil {
		return err
	}

	// Verify user is a member of the application
	_, err := s.appRepo.GetMemberByPublicKey(appID, requestingUser.PublicKey)
	if err != nil {
		return fmt.Errorf("not a member of this application")
	}

	// Client-produced events architecture:
	// Client should submit member_removed or application_deleted event via POST /events
	// Server validates, sequences, and applies the event
	// This endpoint returns success but does NOT produce events

	return nil
}
