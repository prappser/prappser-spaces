package spaceprofile

import (
	"database/sql"
	"fmt"
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// Get returns the zero Profile when the owner has never set one.
func (r *Repository) Get() (Profile, error) {
	var p Profile
	var avatar sql.NullString
	err := r.db.QueryRow(`SELECT name, avatar_storage_id, updated_at FROM space_profile WHERE id = 1`).
		Scan(&p.Name, &avatar, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return Profile{}, nil
	}
	if err != nil {
		return Profile{}, fmt.Errorf("failed to get space profile: %w", err)
	}
	if avatar.Valid {
		p.AvatarStorageID = &avatar.String
	}
	return p, nil
}

func (r *Repository) Save(p Profile) error {
	_, err := r.db.Exec(`INSERT INTO space_profile (id, name, avatar_storage_id, updated_at) VALUES (1, $1, $2, $3)
		ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, avatar_storage_id = EXCLUDED.avatar_storage_id, updated_at = EXCLUDED.updated_at`,
		p.Name, p.AvatarStorageID, p.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to save space profile: %w", err)
	}
	return nil
}

type liveApplication struct {
	ID      string
	SpaceID *string
}

func (r *Repository) listLiveApplications() ([]liveApplication, error) {
	rows, err := r.db.Query(`SELECT id, space_id FROM applications WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("failed to list applications: %w", err)
	}
	defer rows.Close()

	var apps []liveApplication
	for rows.Next() {
		var a liveApplication
		var spaceID sql.NullString
		if err := rows.Scan(&a.ID, &spaceID); err != nil {
			return nil, fmt.Errorf("failed to scan application: %w", err)
		}
		if spaceID.Valid {
			a.SpaceID = &spaceID.String
		}
		apps = append(apps, a)
	}
	return apps, rows.Err()
}
