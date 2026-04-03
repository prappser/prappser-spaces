//go:build integration

package keys

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

const createTableSQL = `
CREATE TABLE IF NOT EXISTS space_keys (
    id TEXT PRIMARY KEY DEFAULT 'main',
    public_key BYTEA NOT NULL,
    encrypted_private_key BYTEA NOT NULL,
    salt BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    created_at BIGINT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'ed25519'
);
`

func getTestDB(t *testing.T) *sql.DB {
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

	// Create table
	if _, err := db.Exec(createTableSQL); err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	// Clean up before test
	if _, err := db.Exec("DELETE FROM space_keys"); err != nil {
		t.Fatalf("Failed to clean table: %v", err)
	}

	return db
}

func TestKeyRepository_SaveAndGetSpaceKey_Integration(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewKeyRepository(db)
	ctx := context.Background()

	// Generate a test key
	priv, pub, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate keypair: %v", err)
	}

	// Encrypt the key
	enc, err := EncryptPrivateKey(priv, "test-password")
	if err != nil {
		t.Fatalf("Failed to encrypt key: %v", err)
	}

	// Save to database
	err = repo.SaveSpaceKey(ctx, enc)
	if err != nil {
		t.Fatalf("Failed to save server key: %v", err)
	}

	// Retrieve from database
	retrieved, err := repo.GetSpaceKey(ctx)
	if err != nil {
		t.Fatalf("Failed to get server key: %v", err)
	}

	if retrieved == nil {
		t.Fatal("Expected to retrieve key, got nil")
	}

	// Verify public key matches
	if string(retrieved.PublicKey) != string(pub) {
		t.Errorf("Public key mismatch")
	}

	// Verify we can decrypt
	decrypted, err := DecryptPrivateKey(retrieved, "test-password")
	if err != nil {
		t.Fatalf("Failed to decrypt retrieved key: %v", err)
	}

	if string(decrypted.Seed()) != string(priv.Seed()) {
		t.Errorf("Decrypted key seed mismatch")
	}
}

func TestKeyRepository_GetSpaceKey_ReturnsNilWhenNotExists_Integration(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewKeyRepository(db)
	ctx := context.Background()

	// Should return nil, not error
	retrieved, err := repo.GetSpaceKey(ctx)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if retrieved != nil {
		t.Errorf("Expected nil when no key exists, got: %+v", retrieved)
	}
}
