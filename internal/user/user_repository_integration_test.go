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

	schema := `
		CREATE TABLE IF NOT EXISTS users (
			public_key        TEXT PRIMARY KEY,
			username          TEXT NOT NULL,
			role              TEXT NOT NULL,
			created_at        BIGINT NOT NULL,
			avatar_storage_id TEXT
		);
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("Failed to create test schema: %v", err)
	}

	// Clean slate before each test.
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
