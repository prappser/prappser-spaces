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

// spaceOwnerClaimPkey and usersPasswordUsernameIdx name the two constraints
// (migrations 000024 and 000023 respectively) that ClaimOwner's transaction
// can collide with. A unique violation's pqErr.Constraint field is checked
// against these names, NOT the bare SQLSTATE code, because ClaimOwner's
// users INSERT can also collide on the public_key primary key - a violation
// the two 409 error kinds below must not be mislabeled as. spaceOwnerClaimPkey
// is Postgres's default "<table>_pkey" name for space_owner_claim's PRIMARY
// KEY column (id) - confirmed empirically against a real Postgres instance,
// not assumed from the table name.
const (
	spaceOwnerClaimPkey      = "space_owner_claim_pkey"
	usersPasswordUsernameIdx = "users_password_username_idx"
)

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

// SetUserIssuer unconditionally overwrites issuer for an account - used only
// by the account-key-signed rebind endpoint (#116 Phase 5, see
// AssertionEndpoints.RebindIssuer). Unlike UpdateUserIssuer above, there is
// no WHERE issuer=public_key guard: users.issuer is provenance-only (see
// UserRepository's doc comment), never an authorization input, so the
// account key is root authority and any transition it signs for is allowed
// in either direction, including vouched->self. Do NOT relax
// UpdateUserIssuer's guard instead of adding this method - it is
// load-bearing for the join flow's one-way self->vouched upgrade.
func (r *userRepository) SetUserIssuer(publicKey, issuer string) error {
	_, err := r.db.Exec(
		"UPDATE users SET issuer=$2 WHERE public_key=$1",
		publicKey, issuer,
	)
	if err != nil {
		return fmt.Errorf("failed to set user issuer: %w", err)
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

// UpdateUserState overwrites the account's escrowed user-state blob (#137,
// see PasswordEndpoints.UpdateUserState). NULLIF mirrors
// SetPasswordCredentials: an empty blob clears the column.
func (r *userRepository) UpdateUserState(publicKey, userState string) error {
	_, err := r.db.Exec(
		"UPDATE users SET user_state_blob = NULLIF($1, '') WHERE public_key = $2",
		userState, publicKey,
	)
	if err != nil {
		return fmt.Errorf("failed to update user state: %w", err)
	}
	return nil
}

// ClaimOwner creates the owner account, device #1 (whose key IS the account
// key, same as the pre-#114 owner flow), the password-login verifier,
// handle, and escrow blobs, and the space's claim record, all in a single
// transaction - the entire body of the one-shot, unauthenticated
// POST /users/owners/claim endpoint (see owner_claim_endpoints.go's Claim).
//
// space_owner_claim's primary key (migration 000024) is the AUTHORITATIVE
// concurrency guard: two requests can both reach this method at the same
// instant (the endpoint is unauthenticated, so nothing upstream serializes
// them), so the users INSERT below is deliberately unconditional - there is
// no WHERE NOT EXISTS guard on it, because that guard is what made the
// original implementation racy (under READ COMMITTED, two concurrent
// transactions with different public_key values can both observe "no owner
// exists" and both commit, since there's no primary-key conflict between
// them to catch it). The claim-row INSERT at the end is what actually
// serializes concurrent claims: Postgres blocks the second one until the
// first commits or rolls back, then fails it with a unique violation on
// space_owner_claim's primary key, which this method maps to
// ErrSpaceAlreadyClaimed below - and because everything runs in one
// transaction, that failure rolls back the users/user_devices rows this
// call already wrote, so a losing claimant never leaves a stray account
// behind.
//
// A prior HasClaim() call (as the endpoint makes, for a cheap pre-KDF
// reject) is an optimization on top of this guard, not a substitute for it -
// it is inherently racy between its own check and this transaction.
//
// NULLIF($6,'') / NULLIF($7,'') mirror SetPasswordCredentials: an empty
// accountKeyBlob or userState is stored as SQL NULL, not an empty string, so
// a not-yet-escrowed column reads the same way GetEscrow already expects.
func (r *userRepository) ClaimOwner(publicKey, username, passwordVerifier, handle, accountKeyBlob, userState string, deviceName *string, createdAt int64) error {
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		`INSERT INTO users (public_key, username, role, created_at, issuer, password_verifier, password_handle, account_key_blob, user_state_blob)
		 VALUES ($1, $2, 'owner', $3, $1, $4, $5, NULLIF($6, ''), NULLIF($7, ''))`,
		publicKey, username, createdAt, passwordVerifier, handle, accountKeyBlob, userState,
	); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == pqUniqueViolation {
			switch pqErr.Constraint {
			case usersPasswordUsernameIdx:
				return ErrUsernameTaken
			default:
				// Most likely the public_key primary key. Neither 409 kind
				// applies - surface it as a 500 rather than mislabeling it.
				return fmt.Errorf("failed to claim owner: unexpected unique violation on %q: %w", pqErr.Constraint, err)
			}
		}
		return fmt.Errorf("failed to claim owner: %w", err)
	}

	// Device #1's key equals the account key - same convention as the
	// pre-#114 OwnerRegister flow. Statement matches EnsureDevice exactly.
	if _, err := tx.Exec(
		`INSERT INTO user_devices (device_public_key, user_public_key, device_name, created_at)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (device_public_key) DO NOTHING`,
		publicKey, publicKey, deviceName, createdAt,
	); err != nil {
		return fmt.Errorf("failed to create owner device: %w", err)
	}

	if _, err := tx.Exec(
		`INSERT INTO space_owner_claim (id, owner_public_key, claimed_at) VALUES ('main', $1, $2)`,
		publicKey, createdAt,
	); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == pqUniqueViolation && pqErr.Constraint == spaceOwnerClaimPkey {
			return ErrSpaceAlreadyClaimed
		}
		return fmt.Errorf("failed to record owner claim: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit owner claim: %w", err)
	}
	return nil
}

// HasClaim reports whether this space has already been claimed. It is a
// cheap pre-check for the claim endpoint (see owner_claim_endpoints.go's
// Claim) to reject an already-claimed space at DB-lookup cost before doing
// any Argon2id work - it is a pre-KDF optimization only, not the concurrency
// guard against two simultaneous claims (see ClaimOwner's doc comment for
// that guard).
func (r *userRepository) HasClaim() (bool, error) {
	var exists bool
	if err := r.db.QueryRow("SELECT EXISTS (SELECT 1 FROM space_owner_claim WHERE id = 'main')").Scan(&exists); err != nil {
		return false, fmt.Errorf("failed to check for existing claim: %w", err)
	}
	return exists, nil
}
