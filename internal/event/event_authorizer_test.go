package event

import (
	"errors"
	"strings"
	"testing"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/user"
)

// ---- #44: template_changed authorization. Pure unit tests against
// AuthorizeUserScopedEvent directly - no DB, no fakes. ----

func TestAuthorizeUserScopedEvent_TemplateChanged_OwnAccount(t *testing.T) {
	submitter := &user.User{PublicKey: "pk-1"}
	evt := &Event{
		Type:             EventTypeTemplateChanged,
		CreatorPublicKey: "pk-1",
		Data:             validTemplateChangedData(),
	}

	if err := AuthorizeUserScopedEvent(evt, submitter); err != nil {
		t.Fatalf("Expected own-account template sync to be authorized, got: %v", err)
	}
}

func TestAuthorizeUserScopedEvent_TemplateChanged_ForeignUserPublicKey(t *testing.T) {
	submitter := &user.User{PublicKey: "pk-1"}
	data := validTemplateChangedData()
	data["userPublicKey"] = "pk-2"
	evt := &Event{
		Type:             EventTypeTemplateChanged,
		CreatorPublicKey: "pk-1",
		Data:             data,
	}

	err := AuthorizeUserScopedEvent(evt, submitter)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for foreign userPublicKey, got: %v", err)
	}
}

func TestAuthorizeEvent_SpaceProfileChanged_ShouldRejectClientSubmission(t *testing.T) {
	// given
	submitter := &user.User{PublicKey: "pk-1"}
	app := &application.Application{ID: "app-1", Members: []application.Member{{PublicKey: "pk-1", Role: application.MemberRoleOwner}}}
	evt := &Event{Type: EventTypeSpaceProfileChanged, Data: map[string]interface{}{"applicationId": "app-1"}}

	// when
	err := AuthorizeEvent(evt, submitter, app)

	// then
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for a client-submitted space_profile_changed, got: %v", err)
	}
}

func roleTestApp() *application.Application {
	return &application.Application{ID: "app-1", Members: []application.Member{
		{PublicKey: "owner-pk", Role: application.MemberRoleOwner},
		{PublicKey: "admin-pk", Role: application.MemberRoleAdmin},
		{PublicKey: "admin2-pk", Role: application.MemberRoleAdmin},
		{PublicKey: "member-pk", Role: application.MemberRoleMember},
	}}
}

func authorizeRoleChange(submitterPK, targetPK string) error {
	oldRole := "member"
	if target := findMember(roleTestApp(), targetPK); target != nil {
		oldRole = string(target.Role)
	}
	return authorizeRoleChangeFrom(submitterPK, targetPK, oldRole)
}

func authorizeRoleChangeFrom(submitterPK, targetPK, oldRole string) error {
	evt := &Event{Type: EventTypeMemberRoleChanged, Data: map[string]interface{}{
		"applicationId": "app-1", "memberPublicKey": targetPK, "oldRole": oldRole, "newRole": "admin",
	}}
	return AuthorizeEvent(evt, &user.User{PublicKey: submitterPK}, roleTestApp())
}

func authorizeRemoval(submitterPK, targetPK string) error {
	evt := &Event{Type: EventTypeMemberRemoved, Data: map[string]interface{}{
		"applicationId": "app-1", "memberPublicKey": targetPK,
	}}
	return AuthorizeEvent(evt, &user.User{PublicKey: submitterPK}, roleTestApp())
}

func TestAuthorizeEvent_MemberRoleChanged_ShouldAllowAdminToPromoteMember(t *testing.T) {
	// when
	err := authorizeRoleChange("admin-pk", "member-pk")

	// then
	if err != nil {
		t.Fatalf("Expected admin to change a member's role, got: %v", err)
	}
}

func TestAuthorizeEvent_MemberRoleChanged_ShouldAllowAdminToDemoteAdmin(t *testing.T) {
	// when
	err := authorizeRoleChange("admin-pk", "admin2-pk")

	// then
	if err != nil {
		t.Fatalf("Expected admin to change another admin's role, got: %v", err)
	}
}

func TestAuthorizeEvent_MemberRoleChanged_ShouldRejectPlainMember(t *testing.T) {
	// when
	err := authorizeRoleChange("member-pk", "admin-pk")

	// then
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for a plain member, got: %v", err)
	}
}

func TestAuthorizeEvent_MemberRoleChanged_ShouldRejectOwnRoleChange(t *testing.T) {
	// when
	err := authorizeRoleChange("admin-pk", "admin-pk")

	// then
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for changing own role, got: %v", err)
	}
}

func TestAuthorizeEvent_MemberRoleChanged_ShouldRejectOwnerChangingOwnRole(t *testing.T) {
	// when
	err := authorizeRoleChange("owner-pk", "owner-pk")

	// then
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for owner changing own role, got: %v", err)
	}
	if !strings.Contains(err.Error(), "cannot change own role") {
		t.Fatalf("Expected the self-change guard to reject, got: %v", err)
	}
}

func TestAuthorizeEvent_MemberRoleChanged_ShouldRejectOwnerTarget(t *testing.T) {
	// when
	err := authorizeRoleChange("admin-pk", "owner-pk")

	// then
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for changing the owner's role, got: %v", err)
	}
}

func TestAuthorizeEvent_MemberRoleChanged_ShouldRejectNonMemberTarget(t *testing.T) {
	// when
	err := authorizeRoleChange("admin-pk", "stranger-pk")

	// then
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for a non-member target, got: %v", err)
	}
}

func TestAuthorizeEvent_MemberRoleChanged_ShouldRejectStaleOldRole(t *testing.T) {
	// when
	err := authorizeRoleChangeFrom("admin-pk", "member-pk", "viewer")

	// then
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for an oldRole that is not the target's current role, got: %v", err)
	}
}

func TestAuthorizeEvent_MemberRemoved_ShouldRejectMissingMemberPublicKey(t *testing.T) {
	// given
	evt := &Event{Type: EventTypeMemberRemoved, Data: map[string]interface{}{"applicationId": "app-1"}}

	// when
	err := AuthorizeEvent(evt, &user.User{PublicKey: "admin-pk"}, roleTestApp())

	// then
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for a missing memberPublicKey, got: %v", err)
	}
}

func TestAuthorizeEvent_MemberRemoved_ShouldRejectNonStringMemberPublicKey(t *testing.T) {
	// given
	evt := &Event{Type: EventTypeMemberRemoved, Data: map[string]interface{}{"applicationId": "app-1", "memberPublicKey": 42}}

	// when
	err := AuthorizeEvent(evt, &user.User{PublicKey: "admin-pk"}, roleTestApp())

	// then
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for a non-string memberPublicKey, got: %v", err)
	}
}

func TestAuthorizeEvent_MemberRemoved_ShouldAllowAdminToRemoveAdmin(t *testing.T) {
	// when
	err := authorizeRemoval("admin-pk", "admin2-pk")

	// then
	if err != nil {
		t.Fatalf("Expected admin to remove another admin, got: %v", err)
	}
}

func TestAuthorizeEvent_MemberRemoved_ShouldRejectAdminRemovingOwner(t *testing.T) {
	// when
	err := authorizeRemoval("admin-pk", "owner-pk")

	// then
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for removing the owner, got: %v", err)
	}
}

func TestAuthorizeEvent_MemberRemoved_ShouldRejectNonMemberTarget(t *testing.T) {
	// when
	err := authorizeRemoval("admin-pk", "stranger-pk")

	// then
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for a non-member target, got: %v", err)
	}
}

func TestAuthorizeEvent_MemberRemoved_ShouldRejectMemberRemovingOther(t *testing.T) {
	// when
	err := authorizeRemoval("member-pk", "admin-pk")

	// then
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for a plain member removing another, got: %v", err)
	}
}

func TestAuthorizeEvent_MemberRemoved_ShouldAllowMemberToRemoveSelf(t *testing.T) {
	// when
	err := authorizeRemoval("member-pk", "member-pk")

	// then
	if err != nil {
		t.Fatalf("Expected a member to remove themselves, got: %v", err)
	}
}

func TestAuthorizeEvent_MemberRemoved_ShouldRejectOwnerRemovingSelf(t *testing.T) {
	// when
	err := authorizeRemoval("owner-pk", "owner-pk")

	// then
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for the owner leaving, got: %v", err)
	}
}

func TestAuthorizeEvent_MemberAdded_ShouldRejectClientSubmission(t *testing.T) {
	// given
	evt := &Event{Type: EventTypeMemberAdded, Data: map[string]interface{}{"applicationId": "app-1", "memberPublicKey": "new-pk", "role": "member"}}

	// when
	err := AuthorizeEvent(evt, &user.User{PublicKey: "owner-pk"}, roleTestApp())

	// then
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for a client-submitted member_added, got: %v", err)
	}
}

func TestAuthorizeEvent_InviteRevoked_ShouldAllowAdmin(t *testing.T) {
	// given
	evt := &Event{Type: EventTypeInviteRevoked, Data: map[string]interface{}{"applicationId": "app-1", "inviteId": "inv-1"}}

	// when
	err := AuthorizeEvent(evt, &user.User{PublicKey: "admin-pk"}, roleTestApp())

	// then
	if err != nil {
		t.Fatalf("Expected admin to revoke an invite, got: %v", err)
	}
}

func TestAuthorizeEvent_ApplicationDeleted_ShouldRejectAdmin(t *testing.T) {
	// given
	evt := &Event{Type: EventTypeApplicationDeleted, Data: map[string]interface{}{"applicationId": "app-1"}}

	// when
	err := AuthorizeEvent(evt, &user.User{PublicKey: "admin-pk"}, roleTestApp())

	// then
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for admin deleting the app, got: %v", err)
	}
}
