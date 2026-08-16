package event

import (
	"errors"
	"testing"

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

func TestAuthorizeUserScopedEvent_TemplateChanged_ForgedCreatorPublicKey(t *testing.T) {
	submitter := &user.User{PublicKey: "pk-1"}
	// data.userPublicKey matches the submitter, but the envelope's
	// CreatorPublicKey (which backlog replay routes by) is forged to a
	// victim account.
	evt := &Event{
		Type:             EventTypeTemplateChanged,
		CreatorPublicKey: "pk-2",
		Data:             validTemplateChangedData(),
	}

	err := AuthorizeUserScopedEvent(evt, submitter)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Expected ErrUnauthorized for forged creatorPublicKey, got: %v", err)
	}
}
