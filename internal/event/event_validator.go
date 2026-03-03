package event

import (
	"errors"
	"fmt"
)

var (
	ErrValidation = errors.New("validation error")
)

func ValidateEvent(event *Event) error {
	if event.ID == "" {
		return fmt.Errorf("%w: event.id is required", ErrValidation)
	}
	if event.Type == "" {
		return fmt.Errorf("%w: event.type is required", ErrValidation)
	}
	if event.CreatorPublicKey == "" {
		return fmt.Errorf("%w: event.creatorPublicKey is required", ErrValidation)
	}
	if event.Data == nil {
		return fmt.Errorf("%w: event.data is required", ErrValidation)
	}

	switch event.Type {
	case EventTypeMemberAdded:
		return validateMemberAddedData(event.Data)
	case EventTypeMemberRemoved:
		return validateMemberRemovedData(event.Data)
	case EventTypeMemberRoleChanged:
		return validateMemberRoleChangedData(event.Data)
	case EventTypeApplicationDataChanged:
		return validateApplicationDataChangedData(event.Data)
	case EventTypeApplicationDeleted:
		return validateApplicationDeletedData(event.Data)
	case EventTypeInviteRevoked:
		return validateInviteRevokedData(event.Data)
	case EventTypeComponentDataChanged:
		return validateComponentDataChangedData(event.Data)
	case EventTypeApplicationAfterEditModeChanged:
		return validateApplicationAfterEditModeChangedData(event.Data)
	case EventTypeUserSettingsChanged:
		return validateUserSettingsChangedData(event.Data)
	case EventTypeMemberDetailsChanged:
		return validateMemberDetailsChangedData(event.Data)
	case EventTypeApplicationCreated:
		return validateApplicationCreatedData(event.Data)
	default:
		return fmt.Errorf("%w: unknown event type: %s", ErrValidation, event.Type)
	}
}

func validateMemberAddedData(data map[string]interface{}) error {
	if _, ok := data["applicationId"].(string); !ok || data["applicationId"] == "" {
		return fmt.Errorf("%w: applicationId is required", ErrValidation)
	}
	if _, ok := data["memberPublicKey"].(string); !ok || data["memberPublicKey"] == "" {
		return fmt.Errorf("%w: memberPublicKey is required", ErrValidation)
	}
	if _, ok := data["memberName"].(string); !ok || data["memberName"] == "" {
		return fmt.Errorf("%w: memberName is required", ErrValidation)
	}
	if _, ok := data["role"].(string); !ok || data["role"] == "" {
		return fmt.Errorf("%w: role is required", ErrValidation)
	}
	return nil
}

func validateMemberRemovedData(data map[string]interface{}) error {
	if _, ok := data["applicationId"].(string); !ok || data["applicationId"] == "" {
		return fmt.Errorf("%w: applicationId is required", ErrValidation)
	}
	if _, ok := data["memberPublicKey"].(string); !ok || data["memberPublicKey"] == "" {
		return fmt.Errorf("%w: memberPublicKey is required", ErrValidation)
	}
	return nil
}

func validateMemberRoleChangedData(data map[string]interface{}) error {
	if _, ok := data["applicationId"].(string); !ok || data["applicationId"] == "" {
		return fmt.Errorf("%w: applicationId is required", ErrValidation)
	}
	if _, ok := data["memberPublicKey"].(string); !ok || data["memberPublicKey"] == "" {
		return fmt.Errorf("%w: memberPublicKey is required", ErrValidation)
	}
	if _, ok := data["oldRole"].(string); !ok || data["oldRole"] == "" {
		return fmt.Errorf("%w: oldRole is required", ErrValidation)
	}
	if _, ok := data["newRole"].(string); !ok || data["newRole"] == "" {
		return fmt.Errorf("%w: newRole is required", ErrValidation)
	}
	return nil
}

func validateApplicationDataChangedData(data map[string]interface{}) error {
	if _, ok := data["applicationId"].(string); !ok || data["applicationId"] == "" {
		return fmt.Errorf("%w: applicationId is required", ErrValidation)
	}
	return nil
}

func validateApplicationDeletedData(data map[string]interface{}) error {
	if _, ok := data["applicationId"].(string); !ok || data["applicationId"] == "" {
		return fmt.Errorf("%w: applicationId is required", ErrValidation)
	}
	return nil
}

func validateInviteRevokedData(data map[string]interface{}) error {
	if _, ok := data["applicationId"].(string); !ok || data["applicationId"] == "" {
		return fmt.Errorf("%w: applicationId is required", ErrValidation)
	}
	if _, ok := data["inviteId"].(string); !ok || data["inviteId"] == "" {
		return fmt.Errorf("%w: inviteId is required", ErrValidation)
	}
	return nil
}

func validateComponentDataChangedData(data map[string]interface{}) error {
	// Client-side validation only - server trusts client data
	return nil
}

func validateApplicationAfterEditModeChangedData(data map[string]interface{}) error {
	// Client-side validation only - server trusts client data
	return nil
}

func validateUserSettingsChangedData(data map[string]interface{}) error {
	if _, ok := data["userPublicKey"].(string); !ok || data["userPublicKey"] == "" {
		return fmt.Errorf("%w: userPublicKey is required", ErrValidation)
	}
	return nil
}

func validateMemberDetailsChangedData(data map[string]interface{}) error {
	if _, ok := data["applicationId"].(string); !ok || data["applicationId"] == "" {
		return fmt.Errorf("%w: applicationId is required", ErrValidation)
	}
	if _, ok := data["memberPublicKey"].(string); !ok || data["memberPublicKey"] == "" {
		return fmt.Errorf("%w: memberPublicKey is required", ErrValidation)
	}
	return nil
}

func validateApplicationCreatedData(data map[string]interface{}) error {
	if _, ok := data["userPublicKey"].(string); !ok || data["userPublicKey"] == "" {
		return fmt.Errorf("%w: userPublicKey is required", ErrValidation)
	}
	if _, ok := data["applicationId"].(string); !ok || data["applicationId"] == "" {
		return fmt.Errorf("%w: applicationId is required", ErrValidation)
	}
	if _, ok := data["applicationName"].(string); !ok || data["applicationName"] == "" {
		return fmt.Errorf("%w: applicationName is required", ErrValidation)
	}
	return nil
}
