package user

import (
	"database/sql"
	"fmt"
)

type userRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) CreateUser(user *User) error {
	_, err := r.db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1, $2, $3, $4)",
		user.PublicKey, user.Username, user.Role, user.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

func (r *userRepository) GetUserByPublicKey(publicKey string) (*User, error) {
	var user User
	var avatarStorageID sql.NullString
	err := r.db.QueryRow(
		"SELECT public_key, username, role, created_at, avatar_storage_id FROM users WHERE public_key = $1",
		publicKey,
	).Scan(&user.PublicKey, &user.Username, &user.Role, &user.CreatedAt, &avatarStorageID)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by public key: %w", err)
	}
	if avatarStorageID.Valid {
		user.AvatarStorageID = &avatarStorageID.String
	}
	return &user, nil
}

func (r *userRepository) GetUserByUsername(username string) (*User, error) {
	var user User
	var avatarStorageID sql.NullString
	err := r.db.QueryRow(
		"SELECT public_key, username, role, created_at, avatar_storage_id FROM users WHERE username = $1",
		username,
	).Scan(&user.PublicKey, &user.Username, &user.Role, &user.CreatedAt, &avatarStorageID)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}
	if avatarStorageID.Valid {
		user.AvatarStorageID = &avatarStorageID.String
	}
	return &user, nil
}

func (r *userRepository) UpdateUserRole(publicKey string, role string) error {
	_, err := r.db.Exec(
		"UPDATE users SET role = $1 WHERE public_key = $2",
		role, publicKey,
	)
	if err != nil {
		return fmt.Errorf("failed to update user role: %w", err)
	}
	return nil
}

func (r *userRepository) UpdateAvatarStorageID(publicKey string, avatarStorageID *string) error {
	result, err := r.db.Exec(
		"UPDATE users SET avatar_storage_id = $1 WHERE public_key = $2",
		avatarStorageID, publicKey,
	)
	if err != nil {
		return fmt.Errorf("failed to update avatar storage id: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("user with public key %s not found", publicKey)
	}
	return nil
}
