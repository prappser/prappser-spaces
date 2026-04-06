package space

import "database/sql"

type Space struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	UserPublicKey *string `json:"userPublicKey,omitempty"`
	CreatedAt     int64   `json:"createdAt"`
	UpdatedAt     int64   `json:"updatedAt"`
}

type SpaceRepository interface {
	Create(space *Space) error
	GetByID(id string) (*Space, error)
	GetByUserPublicKey(publicKey string) (*Space, error)
	List() ([]*Space, error)
	Delete(id string) error
	Update(space *Space) error
}

func NewSpaceRepository(db *sql.DB) SpaceRepository {
	return &spaceRepository{db: db}
}
