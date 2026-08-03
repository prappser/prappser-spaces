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
		"INSERT INTO users (public_key, username, role, created_at, issuer) VALUES ($1, $2, $3, $4, COALESCE(NULLIF($5,''),$1))",
		user.PublicKey, user.Username, user.Role, user.CreatedAt, user.Issuer,
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
		"SELECT public_key, username, role, created_at, avatar_storage_id, issuer FROM users WHERE public_key = $1",
		publicKey,
	).Scan(&user.PublicKey, &user.Username, &user.Role, &user.CreatedAt, &avatarStorageID, &user.Issuer)

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
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == pqUniqueViolation {
			return ErrUsernameTaken
		}
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

// UpdateUserIssuer re-pins issuer from self to vouched. The WHERE clause is
// the entire guard: it only ever matches a row still self-pinned
// (issuer = public_key), so it is a no-op - not an error - for an unknown
// account or one already vouched by someone else. See UserRepository's doc
// comment for the full rationale.
func (r *userRepository) UpdateUserIssuer(publicKey, issuer string) error {
	_, err := r.db.Exec(
		"UPDATE users SET issuer=$2 WHERE public_key=$1 AND issuer=public_key",
		publicKey, issuer,
	)
	if err != nil {
		return fmt.Errorf("failed to update user issuer: %w", err)
	}
	return nil
}

// SetPasswordCredentials sets the password-login verifier, handle, and
// escrowed account-key/user-state blobs for an account in a single UPDATE.
// The partial unique index on lower(username) WHERE password_verifier IS NOT
// NULL (migration 000023) enforces case-insensitive uniqueness among
// password-enabled accounts only - a non-password account may freely share a
// username with anyone.
//
// The verifier and both escrow blobs are written together on purpose: an
// omitted (empty string) blob clears that column via NULLIF rather than
// leaving a stale value in place. A stale escrow blob under a wrapKey that no
// longer matches the current verifier is worse than a cleared one - it would
// look present to a client but fail to decrypt.
//
// handle is COALESCEd, not overwritten: LOAD-BEARING - once GetPasswordHandle
// has handed a stored handle out to a client (via GetSalt), a later password
// change (e.g. after a username rename) must not silently re-point it to the
// new username. The client's escrow blob is sealed under a wrapKey derived
// from the salt GetSalt computed from the ORIGINAL handle at set-password
// time; re-pointing the handle would change that derived salt and make the
// escrow permanently undecryptable.
func (r *userRepository) SetPasswordCredentials(publicKey, passwordVerifier, handle, accountKeyBlob, userState string) error {
	_, err := r.db.Exec(
		"UPDATE users SET password_verifier = $1, password_handle = COALESCE(password_handle, $2), account_key_blob = NULLIF($3, ''), user_state_blob = NULLIF($4, '') WHERE public_key = $5",
		passwordVerifier, handle, accountKeyBlob, userState, publicKey,
	)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == pqUniqueViolation {
			return ErrUsernameTaken
		}
		return fmt.Errorf("failed to set password credentials: %w", err)
	}
	return nil
}

// GetPasswordCredential returns "", "", nil when no PASSWORD-ENABLED account
// holds this username - absence is a valid state here, not an error (see
// UserRepository's doc comment). username must already be normalized by the
// caller; the lower() comparison is a defense-in-depth match for the
// case-insensitive partial unique index, not a substitute for normalization.
func (r *userRepository) GetPasswordCredential(username string) (userPublicKey, verifier string, err error) {
	err = r.db.QueryRow(
		"SELECT public_key, password_verifier FROM users WHERE lower(username) = lower($1) AND password_verifier IS NOT NULL",
		username,
	).Scan(&userPublicKey, &verifier)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", nil
		}
		return "", "", fmt.Errorf("failed to get password credential: %w", err)
	}
	return userPublicKey, verifier, nil
}

// GetPasswordHandle returns "" when no password-enabled account holds this
// username - absence is a valid state here, not an error (see
// GetPasswordCredential above for the same contract). The caller
// (password_endpoints.go's GetSalt) falls back to lower(username) itself as
// the HMAC input when this returns empty.
func (r *userRepository) GetPasswordHandle(username string) (handle string, err error) {
	var handleNull sql.NullString
	err = r.db.QueryRow(
		"SELECT password_handle FROM users WHERE lower(username) = lower($1) AND password_verifier IS NOT NULL",
		username,
	).Scan(&handleNull)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", fmt.Errorf("failed to get password handle: %w", err)
	}
	return handleNull.String, nil
}

// GetEscrow returns "", "", nil when the account has no row, or a row with
// unset escrow columns - absence is a valid state here, not an error (see
// GetPasswordCredential above for the same contract).
func (r *userRepository) GetEscrow(publicKey string) (accountKeyBlob, userState string, err error) {
	var accountKeyBlobNull, userStateNull sql.NullString
	err = r.db.QueryRow(
		"SELECT account_key_blob, user_state_blob FROM users WHERE public_key = $1",
		publicKey,
	).Scan(&accountKeyBlobNull, &userStateNull)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", nil
		}
		return "", "", fmt.Errorf("failed to get escrow: %w", err)
	}
	return accountKeyBlobNull.String, userStateNull.String, nil
}
