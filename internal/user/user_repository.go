package user

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"
)

// pqUniqueViolation is the PostgreSQL SQLSTATE code for a unique constraint
// violation (see internal/storage/service.go for the same constant, defined
// locally per package rather than shared to avoid a cross-package import for
// a single string literal).
const pqUniqueViolation = "23505"

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
	var identifier sql.NullString
	err := r.db.QueryRow(
		"SELECT public_key, username, role, created_at, avatar_storage_id, identifier FROM users WHERE public_key = $1",
		publicKey,
	).Scan(&user.PublicKey, &user.Username, &user.Role, &user.CreatedAt, &avatarStorageID, &identifier)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by public key: %w", err)
	}
	if avatarStorageID.Valid {
		user.AvatarStorageID = &avatarStorageID.String
	}
	if identifier.Valid {
		user.Identifier = &identifier.String
	}
	return &user, nil
}

func (r *userRepository) GetUserByUsername(username string) (*User, error) {
	var user User
	var avatarStorageID sql.NullString
	var identifier sql.NullString
	err := r.db.QueryRow(
		"SELECT public_key, username, role, created_at, avatar_storage_id, identifier FROM users WHERE username = $1",
		username,
	).Scan(&user.PublicKey, &user.Username, &user.Role, &user.CreatedAt, &avatarStorageID, &identifier)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}
	if avatarStorageID.Valid {
		user.AvatarStorageID = &avatarStorageID.String
	}
	if identifier.Valid {
		user.Identifier = &identifier.String
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

func (r *userRepository) UpdateUsername(publicKey, username string) error {
	result, err := r.db.Exec(
		"UPDATE users SET username = $1 WHERE public_key = $2",
		username, publicKey,
	)
	if err != nil {
		return fmt.Errorf("failed to update username: %w", err)
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

// SetPasswordCredentials sets the password-login identifier and verifier for
// an account. The unique index on lower(identifier) (migration 000019)
// enforces case-insensitive uniqueness at the database level.
func (r *userRepository) SetPasswordCredentials(publicKey, identifier, passwordVerifier string) error {
	_, err := r.db.Exec(
		"UPDATE users SET identifier = $1, password_verifier = $2 WHERE public_key = $3",
		identifier, passwordVerifier, publicKey,
	)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == pqUniqueViolation {
			return ErrIdentifierTaken
		}
		return fmt.Errorf("failed to set password credentials: %w", err)
	}
	return nil
}

// GetPasswordCredential returns "", "", nil when no account holds this
// identifier - absence is a valid state here, not an error (see
// UserRepository's doc comment). identifier must already be normalized by
// the caller; the lower() comparison is a defense-in-depth match for the
// case-insensitive unique index, not a substitute for normalization.
func (r *userRepository) GetPasswordCredential(identifier string) (userPublicKey, verifier string, err error) {
	err = r.db.QueryRow(
		"SELECT public_key, password_verifier FROM users WHERE lower(identifier) = $1",
		identifier,
	).Scan(&userPublicKey, &verifier)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", nil
		}
		return "", "", fmt.Errorf("failed to get password credential: %w", err)
	}
	return userPublicKey, verifier, nil
}
