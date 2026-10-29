// Package spaceprofile is the name and image a space's owner shows to every
// account on the space (#309). Accounts read it from GET /status.
package spaceprofile

type Profile struct {
	Name            string  `json:"name"`
	AvatarStorageID *string `json:"avatarStorageId"`
	UpdatedAt       int64   `json:"updatedAt"`
}
