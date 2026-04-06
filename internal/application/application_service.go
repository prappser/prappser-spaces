package application

import (
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

type ApplicationService struct {
	appRepo ApplicationRepository
}

func NewApplicationService(appRepo ApplicationRepository) *ApplicationService {
	return &ApplicationService{
		appRepo: appRepo,
	}
}

func (s *ApplicationService) RegisterApplication(ownerPublicKey string, app *Application) (*Application, error) {
	// Validate application
	if app.ID == "" {
		return nil, fmt.Errorf("application ID cannot be empty")
	}
	if app.Name == "" {
		return nil, fmt.Errorf("application name cannot be empty")
	}

	// Validate that there is exactly one owner in members
	ownerCount := 0
	for _, member := range app.Members {
		if member.Role == MemberRoleOwner {
			ownerCount++
		}
	}
	if ownerCount == 0 {
		return nil, fmt.Errorf("application must have at least one owner member")
	}
	if ownerCount > 1 {
		return nil, fmt.Errorf("application must have exactly one owner member")
	}

	// Set timestamps
	now := time.Now().Unix()
	app.CreatedAt = now
	app.UpdatedAt = now

	// Create application
	if err := s.appRepo.CreateApplication(app); err != nil {
		return nil, fmt.Errorf("failed to create application: %w", err)
	}

	// Create members
	for _, member := range app.Members {
		if member.ID == "" {
			return nil, fmt.Errorf("member ID cannot be empty")
		}
		member.ApplicationID = app.ID

		if err := s.appRepo.CreateMember(&member); err != nil {
			return nil, fmt.Errorf("failed to create member: %w", err)
		}
	}

	// Create component groups and components
	for _, group := range app.ComponentGroups {
		if group.ID == "" {
			return nil, fmt.Errorf("component group ID cannot be empty")
		}
		group.ApplicationID = app.ID

		if err := s.appRepo.CreateComponentGroup(&group); err != nil {
			return nil, fmt.Errorf("failed to create component group: %w", err)
		}

		// Create components for this group
		for _, component := range group.Components {
			if component.ID == "" {
				return nil, fmt.Errorf("component ID cannot be empty")
			}
			component.ComponentGroupID = group.ID
			component.ApplicationID = app.ID

			if err := s.appRepo.CreateComponent(&component); err != nil {
				return nil, fmt.Errorf("failed to create component: %w", err)
			}
		}
	}

	// Return the complete application
	return s.appRepo.GetApplicationByID(app.ID)
}

func (s *ApplicationService) GetApplication(appID string, requestingUser *user.User) (*Application, error) {
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
		return nil, fmt.Errorf("unauthorized: not a member of this application")
	}

	return app, nil
}

func (s *ApplicationService) GetApplicationState(appID string, requestingUser *user.User) (*ApplicationState, error) {
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
		return nil, fmt.Errorf("unauthorized: not a member of this application")
	}

	return state, nil
}

func (s *ApplicationService) ListApplications(memberPublicKey string) ([]*Application, error) {
	return s.appRepo.GetApplicationsByMemberPublicKey(memberPublicKey)
}

func (s *ApplicationService) DeleteApplication(appID string, requestingUser *user.User) error {
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

