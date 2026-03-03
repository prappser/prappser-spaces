package event

import (
	"errors"
	"fmt"

	"github.com/prappser/prappser_server/internal/application"
	"github.com/prappser/prappser_server/internal/user"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
)

// AuthorizeEvent checks if the submitter has permission to submit the given event for the application.
//
// Authorization Rules by Event Type:
//   - application_deleted: Only the application owner can delete the entire application
//   - member_removed: Members can remove themselves; owners can remove any member
//   - member_added: Any member can add others (authorization handled by invitation system)
//   - member_role_changed: Only owners can change member roles
//   - application_data_changed: Any member can update application data
//   - invite_revoked: Only owners can revoke invitations
//
// Returns ErrUnauthorized if:
//   - Submitter is nil
//   - Application is nil
//   - Submitter is not a member of the application
//   - Submitter lacks required role for the event type
//   - Event type is unknown
func AuthorizeEvent(event *Event, submitter *user.User, app *application.Application) error {
	if submitter == nil {
		return fmt.Errorf("%w: submitter is required", ErrUnauthorized)
	}
	if app == nil {
		return fmt.Errorf("%w: application is required", ErrUnauthorized)
	}

	member := findMember(app, submitter.PublicKey)
	if member == nil {
		return fmt.Errorf("%w: user is not a member of this application", ErrUnauthorized)
	}

	isOwner := member.Role == application.MemberRoleOwner

	switch event.Type {
	case EventTypeApplicationDeleted:
		if !isOwner {
			return fmt.Errorf("%w: only owner can delete application", ErrUnauthorized)
		}

	case EventTypeMemberRemoved:
		memberKey, ok := event.Data["memberPublicKey"].(string)
		if !ok {
			return fmt.Errorf("%w: memberPublicKey not found in event data", ErrUnauthorized)
		}

		if memberKey != submitter.PublicKey && !isOwner {
			return fmt.Errorf("%w: can only remove self unless owner", ErrUnauthorized)
		}

	case EventTypeMemberAdded:
		// Any member can add other members (via invite)
		// Authorization is implicitly granted by the invite system

	case EventTypeMemberRoleChanged:
		if !isOwner {
			return fmt.Errorf("%w: only owner can change member roles", ErrUnauthorized)
		}

	case EventTypeApplicationDataChanged:
		// Any member can update application data

	case EventTypeInviteRevoked:
		if !isOwner {
			return fmt.Errorf("%w: only owner can revoke invites", ErrUnauthorized)
		}

	case EventTypeComponentDataChanged:
		// Any member can update component data

	case EventTypeApplicationAfterEditModeChanged:
		// Any member can modify application structure

	case EventTypeMemberDetailsChanged:
		// Members can only update their own details within an application
		memberKey, ok := event.Data["memberPublicKey"].(string)
		if !ok || memberKey != submitter.PublicKey {
			return fmt.Errorf("%w: can only update own member details", ErrUnauthorized)
		}

	default:
		return fmt.Errorf("%w: unknown event type: %s", ErrUnauthorized, event.Type)
	}

	return nil
}

// AuthorizeUserScopedEvent checks authorization for user-scoped events (no application context).
func AuthorizeUserScopedEvent(event *Event, submitter *user.User) error {
	if submitter == nil {
		return fmt.Errorf("%w: submitter is required", ErrUnauthorized)
	}

	switch event.Type {
	case EventTypeUserSettingsChanged:
		userPK, ok := event.Data["userPublicKey"].(string)
		if !ok || userPK != submitter.PublicKey {
			return fmt.Errorf("%w: can only update own user settings", ErrUnauthorized)
		}
	case EventTypeApplicationCreated:
		userPK, ok := event.Data["userPublicKey"].(string)
		if !ok || userPK != submitter.PublicKey {
			return fmt.Errorf("%w: can only create application events for own user", ErrUnauthorized)
		}
	default:
		return fmt.Errorf("%w: unknown user-scoped event type: %s", ErrUnauthorized, event.Type)
	}

	return nil
}

// findMember searches for a member in the application by their public key.
// Returns nil if the member is not found.
func findMember(app *application.Application, publicKey string) *application.Member {
	for i := range app.Members {
		if app.Members[i].PublicKey == publicKey {
			return &app.Members[i]
		}
	}
	return nil
}
