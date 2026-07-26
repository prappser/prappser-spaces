package profile

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/user"
)

const maxDisplayNameRunes = 64

// UpdateProfileRequest is the PATCH /users/me request body.
type UpdateProfileRequest struct {
	DisplayName string `json:"displayName"`
}

// EventService is the interface for producing space-generated events.
type EventService interface {
	ProduceEvent(ctx context.Context, e *event.Event) (*event.Event, error)
}

// appLister is the narrow interface Endpoints needs from *application.Repository.
type appLister interface {
	GetApplicationsByMemberPublicKey(publicKey string) ([]*application.Application, error)
}

// userRepository is the narrow interface Endpoints needs from user.UserRepository.
type userRepository interface {
	GetUserByPublicKey(publicKey string) (*user.User, error)
	UpdateUsername(publicKey, username string) error
}

// validateDisplayName trims whitespace and validates the result, returning the trimmed value.
func validateDisplayName(displayName string) (string, error) {
	trimmed := strings.TrimSpace(displayName)
	if trimmed == "" {
		return "", fmt.Errorf("displayName cannot be empty")
	}
	runeCount := 0
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("displayName cannot contain control characters")
		}
		runeCount++
	}
	if runeCount > maxDisplayNameRunes {
		return "", fmt.Errorf("displayName cannot exceed %d characters", maxDisplayNameRunes)
	}
	return trimmed, nil
}
