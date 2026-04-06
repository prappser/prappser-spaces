package invitation

import (
	"time"
)

// Invitation represents an invitation to join an application
type Invitation struct {
	ID                 string  `json:"id"`
	ApplicationID      string  `json:"applicationId"`
	CreatedByPublicKey string  `json:"createdByPublicKey"`
	Role               string  `json:"role"`
	MaxUses            *int    `json:"maxUses,omitempty"`
	UsedCount          int     `json:"usedCount"`
	CreatedAt          int64   `json:"createdAt"`
	SpaceID            *string `json:"spaceId,omitempty"`
}

// InvitationUse tracks when a user joins via an invitation
type InvitationUse struct {
	ID             string `json:"id"`
	InvitationID   string `json:"invitationId"`
	UserPublicKey  string `json:"userPublicKey"`
	UsedAt         int64  `json:"usedAt"`
}

// InvitationResponse is returned when creating an invitation
type InvitationResponse struct {
	ID        string  `json:"id"`
	Token     string  `json:"token"`
	URL       string  `json:"url"`
	DeepLink  string  `json:"deepLink"`
	ExpiresAt *int64  `json:"expiresAt,omitempty"`
	CreatedAt int64   `json:"createdAt"`
}

// InvitationOptions contains options for creating an invitation
type InvitationOptions struct {
	ExpiresInHours *int   `json:"expiresInHours,omitempty"`
	Role           string `json:"role,omitempty"`
	MaxUses        *int   `json:"maxUses,omitempty"`
}

// InviteInfo is public information about an invitation
type InviteInfo struct {
	InviteID        string  `json:"inviteId"`
	ApplicationName string  `json:"applicationName"`
	ApplicationIcon *string `json:"applicationIcon,omitempty"`
	CreatorUsername string  `json:"creatorUsername"`
	Role            string  `json:"role"`
	ExpiresAt       *int64  `json:"expiresAt,omitempty"`
	IsExpired       bool    `json:"isExpired"`
	IsValid         bool    `json:"isValid"`
}

// CheckInvitationResult contains status information about invitation usage
type CheckInvitationResult struct {
	Valid           bool   `json:"valid"`
	AlreadyUsed     bool   `json:"alreadyUsed"`
	IsMember        bool   `json:"isMember"`
	IsExpired       bool   `json:"isExpired"`
	MaxUsesReached  bool   `json:"maxUsesReached"`
	ApplicationName string `json:"applicationName,omitempty"`
	Role            string `json:"role,omitempty"`
	Message         string `json:"message"`
}

// InviteTokenClaims represents JWT claims for invitation tokens
type InviteTokenClaims struct {
	InviteID  string `json:"id"`
	SpaceURL string `json:"spaceUrl"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt *int64 `json:"exp,omitempty"`
}

// JoinResponse is returned when successfully joining an application
type JoinResponse struct {
	Success     bool                   `json:"success"`
	Application map[string]interface{} `json:"application"`
	Member      map[string]interface{} `json:"member"`
}

// UpdateTimestamp updates the created timestamp to current time
func (i *Invitation) UpdateTimestamp() {
	i.CreatedAt = time.Now().Unix()
}

// IsExpired checks if the invitation has expired based on JWT expiration
func (c *InviteTokenClaims) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return time.Now().Unix() > *c.ExpiresAt
}

// IsMaxUsesReached checks if invitation has reached max uses
func (i *Invitation) IsMaxUsesReached() bool {
	if i.MaxUses == nil {
		return false
	}
	return i.UsedCount >= *i.MaxUses
}
