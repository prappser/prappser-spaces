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

// spaceOwnerClaimPkey, usersPasswordUsernameIdx, and userDevicesPkey name the
// three constraints (migrations 000024, 000023, and 000018 respectively)
// that ClaimOwner's transaction can collide with. A unique violation's
// pqErr.Constraint field is checked against these names, NOT the bare
// SQLSTATE code, because ClaimOwner's users INSERT can also collide on the
// public_key primary key - a violation the three 409 error kinds below must
// not be mislabeled as. spaceOwnerClaimPkey and userDevicesPkey are
// Postgres's default "<table>_pkey" name for each table's PRIMARY KEY column
// (space_owner_claim.id, user_devices.device_public_key) - confirmed
// empirically against a real Postgres instance, not assumed from the table
// name.
const (
	spaceOwnerClaimPkey      = "space_owner_claim_pkey"
	usersPasswordUsernameIdx = "users_password_username_idx"
	userDevicesPkey          = "user_devices_pkey"
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
// handle is frozen while a verifier is live: LOAD-BEARING - once GetPasswordHandle
// has handed a stored handle out to a client (via GetSalt), a later password
// change (e.g. after a username rename) must not silently re-point it to the
// new username. The client's escrow blob is sealed under a wrapKey derived
// from the salt GetSalt computed from the ORIGINAL handle at set-password
// time; re-pointing the handle would change that derived salt and make the
// escrow permanently undecryptable.
//
// With a NULL verifier (never set, or ClearEscrow) no escrow is reachable -
// login, enroll and GetSalt all need a verifier, and GetSalt falls back to
// lower(username) - and this same UPDATE overwrites both blobs, so the handle
// is re-pointed to the submitted one. Otherwise a rename after ClearEscrow
// would leave the stored handle stale and every later GetSalt wrong.
func (r *userRepository) SetPasswordCredentials(publicKey, passwordVerifier, handle, accountKeyBlob, userState string) error {
	_, err := r.db.Exec(
		"UPDATE users SET password_verifier = $1, password_handle = CASE WHEN password_verifier IS NULL THEN $2 ELSE COALESCE(password_handle, $2) END, account_key_blob = NULLIF($3, ''), user_state_blob = NULLIF($4, '') WHERE public_key = $5",
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

// ClearEscrow nulls account_key_blob, user_state_blob, and password_verifier
// for an account on this space (DELETE /users/me/escrow, see
// PasswordEndpoints.ClearEscrow) - the user is moving their escrow to a
// different space, or reclaiming their key. Always succeeds on a matching
// row regardless of current state, so clearing an already-clear account is
// idempotent, not an error.
//
// password_handle is deliberately left untouched: clearing it here buys
// nothing, SetPasswordCredentials re-points it when the verifier is NULL, and
// the partial unique index on lower(username) (migration 000023) is gated on
// password_verifier IS NOT NULL, so nulling the verifier already releases
// the username slot.
//
// Nulling password_verifier is the point, not a side effect: it stops
// password login on this space cleanly with a 401, instead of letting it
// succeed and hand a new device an empty escrow it can silently do nothing
// with.
func (r *userRepository) ClearEscrow(publicKey string) error {
	_, err := r.db.Exec(
		"UPDATE users SET account_key_blob = NULL, user_state_blob = NULL, password_verifier = NULL WHERE public_key = $1",
		publicKey,
	)
	if err != nil {
		return fmt.Errorf("failed to clear escrow: %w", err)
	}
	return nil
}

// ClaimOwner creates the owner account, its first device, the password-login
// verifier, handle, and escrow blobs, and the space's claim record, all in a
// single transaction - the entire body of the one-shot, unauthenticated
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
// A prior HasClaim() call (as the endpoint makes, for a cheap early
// reject) is an optimization on top of this guard, not a substitute for it -
// it is inherently racy between its own check and this transaction.
//
// All four positional params $4 through $7 are NULLIF-wrapped now, not just
// the escrow blobs: an owner can claim without setting a password, leaving
// passwordVerifier and handle empty too. GetPasswordCredential and
// GetPasswordHandle above treat password_verifier IS NOT NULL as "this
// account has a password" - leaving $4/$5 bare would store an empty string
// as the verifier instead of SQL NULL, and every passwordless claim would
// report a phantom password. A caller (see owner_claim_endpoints.go's Claim)
// must pass an empty handle whenever passwordVerifier is empty - the reverse
// (a set verifier with an empty handle) is fine, since GetSalt already falls
// back to lower(username) when GetPasswordHandle returns "".
func (r *userRepository) ClaimOwner(publicKey, username, passwordVerifier, handle, accountKeyBlob, userState, devicePublicKey string, deviceName *string, createdAt int64) error {
	tx, err := r.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		`INSERT INTO users (public_key, username, role, created_at, issuer, password_verifier, password_handle, account_key_blob, user_state_blob)
		 VALUES ($1, $2, 'owner', $3, $1, NULLIF($4, ''), NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''))`,
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

	// devicePublicKey defaults to the account key when the claimer omits one
	// (see Claim), preserving old clients' behavior - it's no longer assumed
	// to equal the account key otherwise. Unlike EnsureDevice's identical
	// INSERT, this one has no ON CONFLICT DO NOTHING: EnsureDevice wants
	// idempotency because it runs on every enroll, but a claim is one-shot,
	// already guarded by space_owner_claim's primary key below, so a
	// collision here is a real conflict - the claimer sent a
	// devicePublicKey already registered on this space. No-oping it would
	// still commit the users/claim rows, leaving an owner with no device
	// rows (unable to ever authenticate) and the space permanently
	// unclaimable.
	if _, err := tx.Exec(
		`INSERT INTO user_devices (device_public_key, user_public_key, device_name, created_at)
		 VALUES ($1, $2, $3, $4)`,
		devicePublicKey, publicKey, deviceName, createdAt,
	); err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == pqUniqueViolation && pqErr.Constraint == userDevicesPkey {
			return ErrDeviceKeyTaken
		}
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
// Claim) so an already-claimed space answers 409 - it is not the concurrency
// guard against two simultaneous claims (see ClaimOwner's doc comment for
// that guard).
func (r *userRepository) HasClaim() (bool, error) {
	var exists bool
	if err := r.db.QueryRow("SELECT EXISTS (SELECT 1 FROM space_owner_claim WHERE id = 'main')").Scan(&exists); err != nil {
		return false, fmt.Errorf("failed to check for existing claim: %w", err)
	}
	return exists, nil
}
