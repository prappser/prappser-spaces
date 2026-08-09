//go:build integration

package keys

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/prappser/prappser-spaces/internal/testdb"
)

// getTestDB returns a *sql.DB scoped to this package's own Postgres schema,
// built from the real files/migrations (see internal/testdb) rather than a
// hand-written copy - so this file can't drift from production schema.
// space_keys comes from migrations 000001 and 000011.
func getTestDB(t *testing.T) *sql.DB {
	t.Helper()
	return testdb.Connect(t, "keys")
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
