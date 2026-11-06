package schemas

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Get() (*Stored, error) {
	var s Stored
	err := r.db.QueryRow(`SELECT bundle, container FROM schema_bundle WHERE id = 1`).Scan(&s.Bundle, &s.Container)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get schema bundle: %w", err)
	}
	return &s, nil
}

// Save never lowers the persisted bundle: a lower or equal number leaves the row as is and returns nil.
func (r *Repository) Save(bundle int, container []byte) error {
	_, err := r.db.Exec(`INSERT INTO schema_bundle (id, bundle, container, updated_at) VALUES (1, $1, $2, $3)
		ON CONFLICT (id) DO UPDATE SET bundle = EXCLUDED.bundle, container = EXCLUDED.container, updated_at = EXCLUDED.updated_at
		WHERE schema_bundle.bundle < EXCLUDED.bundle`,
		bundle, container, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("failed to save schema bundle: %w", err)
	}
	return nil
}
