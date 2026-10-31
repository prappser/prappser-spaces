package event

import (
	"errors"
	"fmt"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/user"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
)

// AuthorizeEvent checks if the submitter has permission to submit the given event for the application.
//
// Authorization Rules by Event Type:
//   - application_deleted: Owner only; admins are excluded on purpose
//   - member_removed: Target must be a current member and not the owner; members can remove themselves, owners and admins can remove others
//   - member_added: Space-produced only; unreachable through AcceptEvent
//   - member_role_changed: Owners and admins can change the role of another non-owner member; oldRole must match its current role
//   - application_data_changed: Any member can update application data
//   - invite_revoked: Owners and admins can revoke invitations
//   - reminder_changed: Any member can create/edit/cancel a reminder rule
//   - reminder_fired: Space-produced only; unreachable through AcceptEvent
//   - application_moved: Space-produced only; unreachable through AcceptEvent
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

	canManage := member.Role == application.MemberRoleOwner || member.Role == application.MemberRoleAdmin

	switch event.Type {
	case EventTypeApplicationDeleted:
		if member.Role != application.MemberRoleOwner {
			return fmt.Errorf("%w: only owner can delete application", ErrUnauthorized)
		}

	case EventTypeMemberRemoved:
		memberKey, ok := event.Data["memberPublicKey"].(string)
		if !ok {
			return fmt.Errorf("%w: memberPublicKey not found in event data", ErrUnauthorized)
		}

		target := findMember(app, memberKey)
		if target == nil {
			return fmt.Errorf("%w: target is not a member of this application", ErrUnauthorized)
		}
		if target.Role == application.MemberRoleOwner {
			return fmt.Errorf("%w: owner cannot be removed, delete the application instead", ErrUnauthorized)
		}
		if memberKey != submitter.PublicKey && !canManage {
			return fmt.Errorf("%w: only owner or admin can remove other members", ErrUnauthorized)
		}

	case EventTypeMemberAdded:
		return fmt.Errorf("%w: member_added is space-produced and cannot be submitted by clients", ErrUnauthorized)

	case EventTypeMemberRoleChanged:
		if !canManage {
			return fmt.Errorf("%w: only owner or admin can change member roles", ErrUnauthorized)
		}
		memberKey, _ := event.Data["memberPublicKey"].(string)
		if memberKey == submitter.PublicKey {
			return fmt.Errorf("%w: cannot change own role", ErrUnauthorized)
		}
		target := findMember(app, memberKey)
		if target == nil || target.Role == application.MemberRoleOwner {
			return fmt.Errorf("%w: target must be a non-owner member of this application", ErrUnauthorized)
		}
		oldRole, _ := event.Data["oldRole"].(string)
		if application.MemberRole(oldRole) != target.Role {
			return fmt.Errorf("%w: oldRole does not match the member's current role", ErrUnauthorized)
		}

	case EventTypeApplicationDataChanged:
		// Any member can update application data

	case EventTypeInviteRevoked:
		if !canManage {
			return fmt.Errorf("%w: only owner or admin can revoke invites", ErrUnauthorized)
		}

	case EventTypeComponentDataChanged:
		// Any member can update component data

	case EventTypeReminderChanged:
		// Any member can create/edit/cancel a reminder rule, same tier as
		// component_data_changed

	case EventTypeApplicationAfterEditModeChanged:
		// Any member can modify application structure

	case EventTypeMemberDetailsChanged:
		// Members can only update their own details within an application
		memberKey, ok := event.Data["memberPublicKey"].(string)
		if !ok || memberKey != submitter.PublicKey {
			return fmt.Errorf("%w: can only update own member details", ErrUnauthorized)
		}

	case EventTypeApplicationFileCreated, EventTypeApplicationFileDeleted:
		return fmt.Errorf("%w: file events are space-produced and cannot be submitted by clients", ErrUnauthorized)

	case EventTypeReminderFired:
		return fmt.Errorf("%w: reminder_fired is space-produced and cannot be submitted by clients", ErrUnauthorized)

	case EventTypeSpaceProfileChanged:
		return fmt.Errorf("%w: space_profile_changed is space-produced and cannot be submitted by clients", ErrUnauthorized)
	case EventTypeApplicationMoved:
		return fmt.Errorf("%w: application_moved is space-produced and cannot be submitted by clients", ErrUnauthorized)

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
	case EventTypeTemplateChanged:
		userPK, ok := event.Data["userPublicKey"].(string)
		if !ok || userPK != submitter.PublicKey {
			return fmt.Errorf("%w: can only sync own templates", ErrUnauthorized)
		}
		// Backlog replay routes user-scoped events by creator_public_key
		// (event_repository.go:150), which the endpoint copies verbatim from
		// the request body, so it must be pinned to the submitter too.
		if event.CreatorPublicKey != submitter.PublicKey {
			return fmt.Errorf("%w: creatorPublicKey must be the submitter", ErrUnauthorized)
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
