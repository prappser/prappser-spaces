//go:build integration

package user

import (
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
)

func getTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://test:test@localhost:5433/prappser_test?sslmode=disable"
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}

	// user_devices and push_subscriptions are included here (not just users)
	// because RevokeDevice's push_subscriptions cleanup is a raw DELETE
	// against that table (see device_repository.go) - the device
	// repository integration tests below need it present.
	//
	// issuer has a test-only DEFAULT '' (the real migration 000021 adds it
	// NOT NULL with no default) so the raw INSERTs elsewhere in this file
	// that predate #112 keep compiling without listing every column;
	// CreateUser's COALESCE(NULLIF($5,''),$1) is what guarantees a non-empty
	// issuer in production.
	//
	// The unique index is now PARTIAL (migration 000023): case-insensitive
	// uniqueness on username applies only among password-enabled rows
	// (password_verifier IS NOT NULL) - non-password rows may freely share a
	// username.
	schema := `
		CREATE TABLE IF NOT EXISTS users (
			public_key        TEXT PRIMARY KEY,
			username          TEXT NOT NULL,
			role              TEXT NOT NULL,
			created_at        BIGINT NOT NULL,
			avatar_storage_id TEXT,
			password_verifier TEXT,
			password_handle   TEXT,
			account_key_blob  TEXT,
			user_state_blob   TEXT,
			issuer            TEXT NOT NULL DEFAULT ''
		);
		CREATE UNIQUE INDEX IF NOT EXISTS users_password_username_idx ON users (lower(username)) WHERE password_verifier IS NOT NULL;
		CREATE TABLE IF NOT EXISTS user_devices (
			device_public_key TEXT PRIMARY KEY,
			user_public_key   TEXT NOT NULL REFERENCES users(public_key) ON DELETE CASCADE,
			device_name       TEXT,
			created_at        BIGINT NOT NULL,
			last_seen_at      BIGINT,
			revoked_at        BIGINT
		);
		CREATE TABLE IF NOT EXISTS push_subscriptions (
			id                    TEXT PRIMARY KEY,
			device_public_key     TEXT NOT NULL REFERENCES user_devices(device_public_key) ON DELETE CASCADE,
			endpoint              TEXT NOT NULL UNIQUE,
			p256dh                TEXT NOT NULL,
			auth                  TEXT NOT NULL,
			categories            JSONB NOT NULL DEFAULT '{}'::jsonb,
			muted_application_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
			created_at            BIGINT NOT NULL,
			failure_count         INTEGER NOT NULL DEFAULT 0
		);
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("Failed to create test schema: %v", err)
	}

	// Clean slate before each test.
	if _, err := db.Exec("DELETE FROM push_subscriptions"); err != nil {
		t.Fatalf("Failed to clean push_subscriptions: %v", err)
	}
	if _, err := db.Exec("DELETE FROM user_devices WHERE device_public_key LIKE 'test-%'"); err != nil {
		t.Fatalf("Failed to clean user_devices: %v", err)
	}
	if _, err := db.Exec("DELETE FROM users WHERE public_key LIKE 'test-%'"); err != nil {
		t.Fatalf("Failed to clean users: %v", err)
	}

	return db
}

func TestUserRepository_UpdateUsername_ShouldUpdateRow_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4)",
		"test-user-1", "OldName", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}

	// when
	err := repo.UpdateUsername("test-user-1", "NewName")

	// then
	assert.NoError(t, err)

	got, err := repo.GetUserByPublicKey("test-user-1")
	assert.NoError(t, err)
	assert.NotNil(t, got)
	assert.Equal(t, "NewName", got.Username)
}

func TestUserRepository_UpdateUsername_ShouldErrorForUnknownPublicKey_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	// when
	err := repo.UpdateUsername("test-user-does-not-exist", "NewName")

	// then
	assert.Error(t, err)
}

func TestUserRepository_SetPasswordCredentials_ShouldRoundTripWithGetPasswordCredential_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4)",
		"test-user-1", "test-alice", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}

	// when
	err := repo.SetPasswordCredentials("test-user-1", "hmac-sha256$dGVzdC12ZXJpZmllcg==", "test-salt", "", "")

	// then
	assert.NoError(t, err)
	userPublicKey, verifier, err := repo.GetPasswordCredential("test-alice")
	assert.NoError(t, err)
	assert.Equal(t, "test-user-1", userPublicKey)
	assert.Equal(t, "hmac-sha256$dGVzdC12ZXJpZmllcg==", verifier)
}

// TestUserRepository_SetPasswordCredentials_ShouldRoundTripEscrowBlobsWithGetEscrow_Integration
// covers the escrow half of SetPasswordCredentials: both blobs persist
// together with the verifier, and GetEscrow reads them back.
func TestUserRepository_SetPasswordCredentials_ShouldRoundTripEscrowBlobsWithGetEscrow_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4)",
		"test-user-1", "test-alice", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}

	// when
	err := repo.SetPasswordCredentials("test-user-1", "hmac-sha256$dGVzdC12ZXJpZmllcg==", "test-salt", "sealed-account-key", "sealed-user-state")

	// then
	assert.NoError(t, err)
	accountKeyBlob, userState, err := repo.GetEscrow("test-user-1")
	assert.NoError(t, err)
	assert.Equal(t, "sealed-account-key", accountKeyBlob)
	assert.Equal(t, "sealed-user-state", userState)
}

// TestUserRepository_SetPasswordCredentials_ShouldClearEscrowBlobsWhenOmitted_Integration
// covers the NULLIF clear-on-omit contract: re-calling with empty blob
// arguments clears whatever escrow a previous call stored.
func TestUserRepository_SetPasswordCredentials_ShouldClearEscrowBlobsWhenOmitted_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4)",
		"test-user-1", "test-alice", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}
	assert.NoError(t, repo.SetPasswordCredentials("test-user-1", "hmac-sha256$AAAA", "test-salt", "sealed-account-key", "sealed-user-state"))

	// when - re-set with no escrow blobs
	err := repo.SetPasswordCredentials("test-user-1", "hmac-sha256$BBBB", "test-salt", "", "")

	// then
	assert.NoError(t, err)
	accountKeyBlob, userState, err := repo.GetEscrow("test-user-1")
	assert.NoError(t, err)
	assert.Empty(t, accountKeyBlob)
	assert.Empty(t, userState)
}

func TestUserRepository_GetEscrow_ShouldReturnEmptyForUnknownPublicKey_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	// when
	accountKeyBlob, userState, err := repo.GetEscrow("test-does-not-exist")

	// then
	assert.NoError(t, err)
	assert.Empty(t, accountKeyBlob)
	assert.Empty(t, userState)
}

func TestUserRepository_GetPasswordCredential_ShouldReturnEmptyForUnknownUsername_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	// when
	userPublicKey, verifier, err := repo.GetPasswordCredential("test-does-not-exist")

	// then
	assert.NoError(t, err)
	assert.Empty(t, userPublicKey)
	assert.Empty(t, verifier)
}

// TestUserRepository_GetPasswordCredential_ShouldMatchCaseInsensitively_Integration
// covers the lower(username) comparison directly against the DB.
func TestUserRepository_GetPasswordCredential_ShouldMatchCaseInsensitively_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4)",
		"test-user-1", "test-CaseMix", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}
	assert.NoError(t, repo.SetPasswordCredentials("test-user-1", "hmac-sha256$DDDD", "test-salt", "", ""))

	// when
	userPublicKey, verifier, err := repo.GetPasswordCredential("TEST-casemix")

	// then
	assert.NoError(t, err)
	assert.Equal(t, "test-user-1", userPublicKey)
	assert.Equal(t, "hmac-sha256$DDDD", verifier)
}

// TestUserRepository_GetPasswordCredential_ShouldPickPasswordEnabledRowWhenNonPasswordRowSharesName_Integration
// covers the "AND password_verifier IS NOT NULL" guard: two accounts may
// share a username as long as at most one is password-enabled, and the
// lookup must resolve to that one, not the plain namesake.
func TestUserRepository_GetPasswordCredential_ShouldPickPasswordEnabledRowWhenNonPasswordRowSharesName_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4), ($5,$6,$7,$8)",
		"test-user-1", "test-dupname", "user", time.Now().Unix(),
		"test-user-2", "test-dupname", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test users: %v", err)
	}
	assert.NoError(t, repo.SetPasswordCredentials("test-user-2", "hmac-sha256$CCCC", "test-salt", "", ""))

	// when
	userPublicKey, verifier, err := repo.GetPasswordCredential("test-dupname")

	// then
	assert.NoError(t, err)
	assert.Equal(t, "test-user-2", userPublicKey)
	assert.Equal(t, "hmac-sha256$CCCC", verifier)
}

// TestUserRepository_UsersTable_ShouldAllowSharedUsernameWhenNeitherHasPassword_Integration
// covers the partial index's scope directly: two plain (non-password) rows
// may share a username - the case that predates #126 would have forbidden
// via the old unconditional unique index.
func TestUserRepository_UsersTable_ShouldAllowSharedUsernameWhenNeitherHasPassword_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()

	// when
	_, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4), ($5,$6,$7,$8)",
		"test-user-1", "test-shared-name", "user", time.Now().Unix(),
		"test-user-2", "test-shared-name", "user", time.Now().Unix(),
	)

	// then
	assert.NoError(t, err)
}

func TestUserRepository_SetPasswordCredentials_ShouldReturnErrUsernameTakenForDuplicateCaseInsensitive_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4), ($5,$6,$7,$8)",
		"test-user-1", "test-shared", "user", time.Now().Unix(),
		"test-user-2", "TEST-SHARED", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test users: %v", err)
	}
	assert.NoError(t, repo.SetPasswordCredentials("test-user-1", "hmac-sha256$AAAA", "test-salt", "", ""))

	// when - a different account, whose username differs only by case, also sets a password
	err := repo.SetPasswordCredentials("test-user-2", "hmac-sha256$BBBB", "test-salt", "", "")

	// then
	assert.ErrorIs(t, err, ErrUsernameTaken)
}

// TestUserRepository_UpdateUsername_ShouldReturnErrUsernameTakenWhenRenamingIntoPasswordEnabledName_Integration
// covers UpdateUsername's OWN unique-violation mapping: the partial index
// only constrains rows that themselves have password_verifier set, so this
// collision only bites when the RENAMING account is ALSO password-enabled -
// renaming a plain (non-password) account into a password-enabled name is
// unconstrained (see the success test right below for that case).
func TestUserRepository_UpdateUsername_ShouldReturnErrUsernameTakenWhenRenamingIntoPasswordEnabledName_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4), ($5,$6,$7,$8)",
		"test-user-1", "test-passworded", "user", time.Now().Unix(),
		"test-user-2", "test-renaming", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test users: %v", err)
	}
	assert.NoError(t, repo.SetPasswordCredentials("test-user-1", "hmac-sha256$AAAA", "test-salt", "", ""))
	// test-user-2 must be password-enabled too, or the partial index simply
	// doesn't cover it and the rename below would succeed unconstrained.
	assert.NoError(t, repo.SetPasswordCredentials("test-user-2", "hmac-sha256$BBBB", "test-salt-2", "", ""))

	// when
	err := repo.UpdateUsername("test-user-2", "TEST-PASSWORDED")

	// then
	assert.ErrorIs(t, err, ErrUsernameTaken)
}

// TestUserRepository_UpdateUsername_ShouldSucceedWhenRenamingIntoPasswordEnabledNameWithoutOwnPassword_Integration
// covers the flip side: a PLAIN (non-password) account renaming into a name
// a password-enabled account already holds is unconstrained - the partial
// index only ever applies to rows that themselves have password_verifier
// set, so this rename raises no conflict at the DB level. GetPasswordCredential
// still resolves the username to the password-enabled account only (see the
// "picks password-enabled row" test above); only a LATER SetPasswordCredentials
// call from this now-doubly-named account would collide.
func TestUserRepository_UpdateUsername_ShouldSucceedWhenRenamingIntoPasswordEnabledNameWithoutOwnPassword_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4), ($5,$6,$7,$8)",
		"test-user-1", "test-passworded-2", "user", time.Now().Unix(),
		"test-user-2", "test-renaming-3", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test users: %v", err)
	}
	assert.NoError(t, repo.SetPasswordCredentials("test-user-1", "hmac-sha256$CCCC", "test-salt-3", "", ""))

	// when - test-user-2 has no password of its own
	err := repo.UpdateUsername("test-user-2", "test-passworded-2")

	// then
	assert.NoError(t, err)
}

// TestUserRepository_UpdateUsername_ShouldSucceedWhenTargetNameHasNoPassword_Integration
// covers renaming into a name held only by non-password accounts - never
// constrained, since neither side is ever in the partial index.
func TestUserRepository_UpdateUsername_ShouldSucceedWhenTargetNameHasNoPassword_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4), ($5,$6,$7,$8)",
		"test-user-1", "test-existing-name", "user", time.Now().Unix(),
		"test-user-2", "test-renaming-2", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test users: %v", err)
	}

	// when
	err := repo.UpdateUsername("test-user-2", "test-existing-name")

	// then
	assert.NoError(t, err)
}

// TestUserRepository_GetPasswordHandle_ShouldRoundTripAndCoalesceOnResubmit_Integration
// is the COALESCE proof at the SQL layer (see SetPasswordCredentials's doc
// comment): a second SetPasswordCredentials call with a different handle
// argument must not re-point the handle already on file.
func TestUserRepository_GetPasswordHandle_ShouldRoundTripAndCoalesceOnResubmit_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4)",
		"test-user-1", "test-handled", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}
	assert.NoError(t, repo.SetPasswordCredentials("test-user-1", "hmac-sha256$EEEE", "handle-first", "", ""))

	// when - re-set with a different handle argument
	assert.NoError(t, repo.SetPasswordCredentials("test-user-1", "hmac-sha256$FFFF", "handle-second", "", ""))

	// then - the FIRST handle sticks
	handle, err := repo.GetPasswordHandle("test-handled")
	assert.NoError(t, err)
	assert.Equal(t, "handle-first", handle)
}

func TestUserRepository_GetPasswordHandle_ShouldReturnEmptyForUnknownUsername_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	// when
	handle, err := repo.GetPasswordHandle("test-does-not-exist")

	// then
	assert.NoError(t, err)
	assert.Empty(t, handle)
}

// TestUserRepository_GetPasswordHandle_ShouldReturnHandleIndependentOfUsername_Integration
// covers the migration-safety property directly at the SQL layer: a row
// whose password_handle differs from its username (exactly what the
// backfill produces for every pre-#126 password-enabled account) still
// resolves lookups by username, but hands back the ORIGINAL handle, not the
// current username.
func TestUserRepository_GetPasswordHandle_ShouldReturnHandleIndependentOfUsername_Integration(t *testing.T) {
	// given - simulates a post-backfill row directly: password_handle is the
	// OLD identifier, username is an unrelated current display name.
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at, password_verifier, password_handle) VALUES ($1,$2,$3,$4,$5,$6)",
		"test-user-1", "test-displayname", "user", time.Now().Unix(), "hmac-sha256$GGGG", "test-old-identifier",
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}

	// when
	handle, err := repo.GetPasswordHandle("test-displayname")

	// then
	assert.NoError(t, err)
	assert.Equal(t, "test-old-identifier", handle)
}

// TestUserRepository_CreateUser_ShouldDefaultIssuerToPublicKeyWhenEmpty_Integration
// covers D1's self-registration default: an empty Issuer on the struct falls
// through CreateUser's COALESCE/NULLIF fallback to the account's own public
// key.
func TestUserRepository_CreateUser_ShouldDefaultIssuerToPublicKeyWhenEmpty_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	// when - Issuer left empty, as a plain (non-assertion) join would leave it
	err := repo.CreateUser(&User{
		PublicKey: "test-user-1",
		Username:  "Alice",
		Role:      "user",
		CreatedAt: time.Now().Unix(),
	})

	// then
	assert.NoError(t, err)
	got, err := repo.GetUserByPublicKey("test-user-1")
	assert.NoError(t, err)
	assert.NotNil(t, got)
	assert.Equal(t, "test-user-1", got.Issuer)
}

// TestUserRepository_CreateUser_ShouldPersistExplicitIssuer_Integration covers
// D1's vouched case: an assertion-derived Issuer survives CreateUser's
// COALESCE unchanged (NULLIF only substitutes on empty).
func TestUserRepository_CreateUser_ShouldPersistExplicitIssuer_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	// when - Issuer set to a vouching space's key, as first-contact-via-assertion would
	err := repo.CreateUser(&User{
		PublicKey: "test-user-1",
		Username:  "Alice",
		Role:      "user",
		CreatedAt: time.Now().Unix(),
		Issuer:    "test-space-key",
	})

	// then
	assert.NoError(t, err)
	got, err := repo.GetUserByPublicKey("test-user-1")
	assert.NoError(t, err)
	assert.NotNil(t, got)
	assert.Equal(t, "test-space-key", got.Issuer)
}

// TestUserRepository_GetUserByPublicKey_ShouldReturnIssuer_Integration checks
// the SELECT/Scan side directly (via a raw INSERT), independent of
// CreateUser's COALESCE logic covered above.
func TestUserRepository_GetUserByPublicKey_ShouldReturnIssuer_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at, issuer) VALUES ($1,$2,$3,$4,$5)",
		"test-user-1", "Alice", "user", time.Now().Unix(), "test-space-key",
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}

	// when
	got, err := repo.GetUserByPublicKey("test-user-1")

	// then
	assert.NoError(t, err)
	assert.NotNil(t, got)
	assert.Equal(t, "test-space-key", got.Issuer)
}

// TestUserRepository_UpdateUserIssuer_ShouldMoveSelfToVouched_Integration
// covers D5's one-way re-pin lever: a self-pinned account (issuer = own
// public key) upgrades to a vouching space's key.
func TestUserRepository_UpdateUserIssuer_ShouldMoveSelfToVouched_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at, issuer) VALUES ($1,$2,$3,$4,$1)",
		"test-user-1", "Alice", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}

	// when
	err := repo.UpdateUserIssuer("test-user-1", "test-space-key")

	// then
	assert.NoError(t, err)
	got, err := repo.GetUserByPublicKey("test-user-1")
	assert.NoError(t, err)
	assert.Equal(t, "test-space-key", got.Issuer)
}

// TestUserRepository_UpdateUserIssuer_ShouldBeNoOpWhenAlreadyVouched_Integration
// covers the SQL guard (WHERE issuer = public_key): a pin that has already
// moved away from self never moves again, and the call still returns nil
// rather than an error (see UserRepository's doc comment).
func TestUserRepository_UpdateUserIssuer_ShouldBeNoOpWhenAlreadyVouched_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at, issuer) VALUES ($1,$2,$3,$4,$5)",
		"test-user-1", "Alice", "user", time.Now().Unix(), "test-space-key-A",
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}

	// when - already vouched by space A; a different issuer must not move the pin
	err := repo.UpdateUserIssuer("test-user-1", "test-space-key-B")

	// then
	assert.NoError(t, err)
	got, err := repo.GetUserByPublicKey("test-user-1")
	assert.NoError(t, err)
	assert.Equal(t, "test-space-key-A", got.Issuer)
}
