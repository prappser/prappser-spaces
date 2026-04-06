package space

import (
	"database/sql"
	"fmt"
)

type spaceRepository struct {
	db *sql.DB
}

func (r *spaceRepository) Create(space *Space) error {
	_, err := r.db.Exec(
		"INSERT INTO spaces (id, name, user_public_key, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)",
		space.ID, space.Name, space.UserPublicKey, space.CreatedAt, space.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create space: %w", err)
	}
	return nil
}

func (r *spaceRepository) GetByID(id string) (*Space, error) {
	var s Space
	var userPublicKey sql.NullString
	err := r.db.QueryRow(
		"SELECT id, name, user_public_key, created_at, updated_at FROM spaces WHERE id = $1",
		id,
	).Scan(&s.ID, &s.Name, &userPublicKey, &s.CreatedAt, &s.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get space by id: %w", err)
	}
	if userPublicKey.Valid {
		s.UserPublicKey = &userPublicKey.String
	}
	return &s, nil
}

func (r *spaceRepository) GetByUserPublicKey(publicKey string) (*Space, error) {
	var s Space
	var userPublicKey sql.NullString
	err := r.db.QueryRow(
		"SELECT id, name, user_public_key, created_at, updated_at FROM spaces WHERE user_public_key = $1",
		publicKey,
	).Scan(&s.ID, &s.Name, &userPublicKey, &s.CreatedAt, &s.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get space by user public key: %w", err)
	}
	if userPublicKey.Valid {
		s.UserPublicKey = &userPublicKey.String
	}
	return &s, nil
}

func (r *spaceRepository) List() ([]*Space, error) {
	rows, err := r.db.Query(
		"SELECT id, name, user_public_key, created_at, updated_at FROM spaces ORDER BY created_at DESC",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list spaces: %w", err)
	}
	defer rows.Close()

	var spaces []*Space
	for rows.Next() {
		s := &Space{}
		var userPublicKey sql.NullString
		err := rows.Scan(&s.ID, &s.Name, &userPublicKey, &s.CreatedAt, &s.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan space: %w", err)
		}
		if userPublicKey.Valid {
			s.UserPublicKey = &userPublicKey.String
		}
		spaces = append(spaces, s)
	}

	return spaces, rows.Err()
}

func (r *spaceRepository) Delete(id string) error {
	result, err := r.db.Exec("DELETE FROM spaces WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete space: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("space not found")
	}
	return nil
}

func (r *spaceRepository) Update(space *Space) error {
	result, err := r.db.Exec(
		"UPDATE spaces SET name = $1, user_public_key = $2, updated_at = $3 WHERE id = $4",
		space.Name, space.UserPublicKey, space.UpdatedAt, space.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update space: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("space not found")
	}
	return nil
}
