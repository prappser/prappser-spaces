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
	schema := `
		CREATE TABLE IF NOT EXISTS users (
			public_key        TEXT PRIMARY KEY,
			username          TEXT NOT NULL,
			role              TEXT NOT NULL,
			created_at        BIGINT NOT NULL,
			avatar_storage_id TEXT,
			identifier        TEXT,
			password_verifier TEXT,
			account_key_blob  TEXT,
			user_state_blob   TEXT
		);
		CREATE UNIQUE INDEX IF NOT EXISTS users_identifier_lower_idx ON users (lower(identifier));
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
		"test-user-1", "Alice", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}

	// when
	err := repo.SetPasswordCredentials("test-user-1", "test-alice", "hmac-sha256$dGVzdC12ZXJpZmllcg==", "", "")

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
		"test-user-1", "Alice", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}

	// when
	err := repo.SetPasswordCredentials("test-user-1", "test-alice", "hmac-sha256$dGVzdC12ZXJpZmllcg==", "sealed-account-key", "sealed-user-state")

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
		"test-user-1", "Alice", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}
	assert.NoError(t, repo.SetPasswordCredentials("test-user-1", "test-alice", "hmac-sha256$AAAA", "sealed-account-key", "sealed-user-state"))

	// when - re-set with no escrow blobs
	err := repo.SetPasswordCredentials("test-user-1", "test-alice", "hmac-sha256$BBBB", "", "")

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

func TestUserRepository_GetPasswordCredential_ShouldReturnEmptyForUnknownIdentifier_Integration(t *testing.T) {
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

func TestUserRepository_SetPasswordCredentials_ShouldReturnErrIdentifierTakenForDuplicateCaseInsensitive_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4), ($5,$6,$7,$8)",
		"test-user-1", "Alice", "user", time.Now().Unix(),
		"test-user-2", "Bob", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test users: %v", err)
	}
	assert.NoError(t, repo.SetPasswordCredentials("test-user-1", "test-shared", "hmac-sha256$AAAA", "", ""))

	// when - a different account claims the same identifier, differing only by case
	err := repo.SetPasswordCredentials("test-user-2", "TEST-SHARED", "hmac-sha256$BBBB", "", "")

	// then
	assert.ErrorIs(t, err, ErrIdentifierTaken)
}
