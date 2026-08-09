package application

import (
	"fmt"
	"time"
)

type Application struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Icon            *string          `json:"icon,omitempty"`
	SpacePublicKey *string          `json:"spacePublicKey,omitempty"`
	SpaceID         *string          `json:"spaceId,omitempty"`
	CreatedAt       int64            `json:"createdAt"`
	UpdatedAt       int64            `json:"updatedAt"`
	DeletedAt       *int64           `json:"deletedAt,omitempty"`
	ComponentGroups []ComponentGroup `json:"componentGroups"`
	Members         []Member         `json:"members"`
	LastSequence    *int64           `json:"lastSequence,omitempty"`
}

type ComponentGroup struct {
	ID            string      `json:"id"`
	ApplicationID string      `json:"applicationId"`
	Name          string      `json:"name"`
	Index         int         `json:"index"`
	Components    []Component `json:"components"`
}

type Component struct {
	ID               string                 `json:"id"`
	ComponentGroupID string                 `json:"componentGroupId"`
	ApplicationID    string                 `json:"applicationId"`
	Name             string                 `json:"name"`
	Data             map[string]interface{} `json:"data,omitempty"`
	Index            int                    `json:"index"`
}

type ApplicationState struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	UpdatedAt int64  `json:"updatedAt"`
}

type MemberRole string

const (
	MemberRoleOwner  MemberRole = "owner"
	MemberRoleAdmin  MemberRole = "admin"
	MemberRoleMember MemberRole = "member"
	MemberRoleViewer MemberRole = "viewer"
)

type Member struct {
	ID                  string     `json:"id,omitempty"`
	ApplicationID       string     `json:"applicationId"`
	Role                MemberRole `json:"role"`
	PublicKey           string     `json:"publicKey"`
	UserDisplayName     *string    `json:"userDisplayName,omitempty"`
	UserAvatarStorageID *string    `json:"userAvatarStorageId,omitempty"`
	// MembershipExpiresAt is the absolute per-joiner membership deadline
	// (#117); nil means the membership never expires. Enforcement is lazy -
	// see activeMemberPredicate in repository.go - this field is never read
	// by a scheduler, only filtered on at query time.
	MembershipExpiresAt *int64 `json:"membershipExpiresAt,omitempty"`
}

// AppVersionInfo holds version tracking data for an application.
// Used by the lightweight poll query to avoid N+1 full-app loads.
type AppVersionInfo struct {
	LastSequence *int64
}

func (a *Application) UpdateTimestamp() {
	a.UpdatedAt = time.Now().Unix()
}

func (a *Application) GetOwner() (*Member, error) {
	for i := range a.Members {
		if a.Members[i].Role == MemberRoleOwner {
			return &a.Members[i], nil
		}
	}
	return nil, fmt.Errorf("no owner found in members")
}

func (a *Application) GetOwnerPublicKey() (string, error) {
	owner, err := a.GetOwner()
	if err != nil {
		return "", err
	}
	return owner.PublicKey, nil
}
