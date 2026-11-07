package profile

import (
	"context"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/user"
)

// UpdateProfileRequest is the PATCH /users/me request body.
type UpdateProfileRequest struct {
	DisplayName         *string `json:"displayName"`
	Locale              *string `json:"locale"`
	NotifyMode          *string `json:"notifyMode"`
	Timezone            *string `json:"timezone"`
	NotificationsSeenAt *int64  `json:"notificationsSeenAt"`
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
	UpdateLocale(publicKey, locale string) error
	UpdateNotifyMode(publicKey, mode string) error
	UpdateTimezone(publicKey, tz string) error
	UpdateNotificationsSeenAt(publicKey string, at int64) error
}
