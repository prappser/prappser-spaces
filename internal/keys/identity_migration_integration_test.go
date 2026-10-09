//go:build integration

package keys

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"

	"github.com/prappser/prappser-spaces/internal/testdb"
)

// testClaims is a minimal JWT claims shape standing in for a live session,
// used only to prove a pre-migration token still validates after a hosting
// move. Deliberately NOT internal/user.JWTClaims: user imports keys, so
// importing user from here would be a cycle.
type testClaims struct {
	UserPublicKey string `json:"userPublicKey"`
	jwt.RegisteredClaims
}

type userSnapshot struct {
	publicKey string
	username  string
	role      string
	createdAt int64
}

type deviceSnapshot struct {
	devicePublicKey string
	userPublicKey   string
	createdAt       int64
}

func snapshotUsers(t *testing.T, db *sql.DB) []userSnapshot {
	t.Helper()
	rows, err := db.Query(`SELECT public_key, username, role, created_at FROM users ORDER BY public_key`)
	assert.NoError(t, err)
	defer rows.Close()
	var out []userSnapshot
	for rows.Next() {
		var u userSnapshot
		assert.NoError(t, rows.Scan(&u.publicKey, &u.username, &u.role, &u.createdAt))
		out = append(out, u)
	}
	assert.NoError(t, rows.Err())
	return out
}

func snapshotDevices(t *testing.T, db *sql.DB) []deviceSnapshot {
	t.Helper()
	rows, err := db.Query(`SELECT device_public_key, user_public_key, created_at FROM user_devices ORDER BY device_public_key`)
	assert.NoError(t, err)
	defer rows.Close()
	var out []deviceSnapshot
	for rows.Next() {
		var d deviceSnapshot
		assert.NoError(t, rows.Scan(&d.devicePublicKey, &d.userPublicKey, &d.createdAt))
		out = append(out, d)
	}
	assert.NoError(t, rows.Err())
	return out
}

// insertTestUserAndDevice writes a minimal users + user_devices row (device
// #1's key equals the account key, same convention as ClaimOwner) - enough
// to prove the migration leaves unrelated app data untouched. role is
// 'user' - see users_role_check (migration 000012), which allows only
// 'owner', 'user', 'guest'.
func insertTestUserAndDevice(t *testing.T, db *sql.DB, publicKey, username string) {
	t.Helper()
	now := time.Now().Unix()
	_, err := db.Exec(`INSERT INTO users (public_key, username, role, issuer, created_at) VALUES ($1, $2, 'user', $1, $3)`, publicKey, username, now)
	assert.NoError(t, err)
	_, err = db.Exec(`INSERT INTO user_devices (device_public_key, user_public_key, device_name, created_at) VALUES ($1, $1, NULL, $2)`, publicKey, now)
	assert.NoError(t, err)
}

type spaceKeyRow struct {
	pub, ct, salt, nonce []byte
}

func readSpaceKeyRow(t *testing.T, db *sql.DB) spaceKeyRow {
	t.Helper()
	var r spaceKeyRow
	assert.NoError(t, db.QueryRow(
		`SELECT public_key, encrypted_private_key, salt, nonce FROM space_keys WHERE id = 'main'`,
	).Scan(&r.pub, &r.ct, &r.salt, &r.nonce))
	return r
}

func signTestJWT(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	claims := testClaims{
		UserPublicKey: "user-pk-1",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(priv)
	assert.NoError(t, err)
	return token
}

// TestIdentityMigration_LegacyRowToKeyFile_Integration: migrating leaves the
// space_keys row byte-identical (so rollback still works) and a JWT signed
// before the migration validates against the migrated key.
func TestIdentityMigration_LegacyRowToKeyFile_Integration(t *testing.T) {
	db := testdb.Connect(t, "keys")
	defer db.Close()
	ctx := context.Background()

	// given - a legacy row, accounts, and a JWT signed by the legacy key
	legacyPriv, _, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	legacyEnc, err := EncryptPrivateKey(legacyPriv, "pw-old")
	assert.NoError(t, err)
	seedSpaceKey(t, db, legacyEnc)
	insertTestUserAndDevice(t, db, "user-pk-1", "alice")
	insertTestUserAndDevice(t, db, "user-pk-2", "bob")
	usersBefore := snapshotUsers(t, db)
	devicesBefore := snapshotDevices(t, db)
	rowBefore := readSpaceKeyRow(t, db)
	tokenString := signTestJWT(t, legacyPriv)

	keyFile := filepath.Join(t.TempDir(), ".space", "identity.key")
	service := NewKeyService(NewKeyRepository(db), "pw-old", "", "", keyFile, false)

	// when
	err = service.Initialize(ctx)

	// then
	assert.NoError(t, err)
	assert.Equal(t, legacyPriv.Seed(), service.PrivateKey().Seed())

	parsed, err := jwt.ParseWithClaims(tokenString, &testClaims{}, func(token *jwt.Token) (interface{}, error) {
		return service.PublicKey(), nil
	})
	assert.NoError(t, err)
	assert.True(t, parsed.Valid, "a pre-migration JWT must still validate after migration")

	assert.Equal(t, rowBefore, readSpaceKeyRow(t, db), "space_keys row must stay byte-identical")
	rowEnc, err := NewKeyRepository(db).GetSpaceKey(ctx)
	assert.NoError(t, err)
	rowPriv, err := DecryptPrivateKey(rowEnc, "pw-old")
	assert.NoError(t, err)
	assert.Equal(t, legacyPriv.Seed(), rowPriv.Seed(), "legacy DecryptPrivateKey must still work on the row")

	assert.Equal(t, usersBefore, snapshotUsers(t, db))
	assert.Equal(t, devicesBefore, snapshotDevices(t, db))
}

// TestIdentityMigration_HostingMoveWithRow_Integration: the blob restores the
// key file with MASTER_PASSWORD unset, and the row is left untouched.
func TestIdentityMigration_HostingMoveWithRow_Integration(t *testing.T) {
	db := testdb.Connect(t, "keysmove")
	defer db.Close()
	ctx := context.Background()

	// given
	priv, _, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	enc, err := EncryptPrivateKey(priv, "pw-old")
	assert.NoError(t, err)
	seedSpaceKey(t, db, enc)
	rowBefore := readSpaceKeyRow(t, db)
	blobEnc, err := EncryptPrivateKey(priv, "export-passphrase-1234")
	assert.NoError(t, err)
	blob, err := EncodeIdentityBlob(blobEnc)
	assert.NoError(t, err)
	tokenString := signTestJWT(t, priv)

	service := NewKeyService(NewKeyRepository(db), "", blob, "export-passphrase-1234",
		filepath.Join(t.TempDir(), ".space", "identity.key"), false)

	// when
	err = service.Initialize(ctx)

	// then
	assert.NoError(t, err)
	assert.Equal(t, priv.Seed(), service.PrivateKey().Seed())
	parsed, err := jwt.ParseWithClaims(tokenString, &testClaims{}, func(token *jwt.Token) (interface{}, error) {
		return service.PublicKey(), nil
	})
	assert.NoError(t, err)
	assert.True(t, parsed.Valid)
	assert.Equal(t, rowBefore, readSpaceKeyRow(t, db), "import must not rewrite the row")
}

// TestIdentityMigration_FreshSchemaImport_Integration: import into an empty
// database writes the key file and no space_keys row.
func TestIdentityMigration_FreshSchemaImport_Integration(t *testing.T) {
	db := testdb.Connect(t, "keysimport")
	defer db.Close()
	ctx := context.Background()

	// given
	priv, pub, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	enc, err := EncryptPrivateKey(priv, "export-passphrase-1234")
	assert.NoError(t, err)
	blob, err := EncodeIdentityBlob(enc)
	assert.NoError(t, err)

	repo := NewKeyRepository(db)
	keyFile := filepath.Join(t.TempDir(), ".space", "identity.key")
	service := NewKeyService(repo, "", blob, "export-passphrase-1234", keyFile, false)

	// when
	err = service.Initialize(ctx)

	// then
	assert.NoError(t, err)
	assert.Equal(t, pub, service.PublicKey())
	stored, err := repo.GetSpaceKey(ctx)
	assert.NoError(t, err)
	assert.Nil(t, stored, "no space_keys row is written")
}

// TestIdentityMigration_MismatchGuard_Integration: an import blob for a
// different keypair than the row's must fail startup and write nothing.
func TestIdentityMigration_MismatchGuard_Integration(t *testing.T) {
	db := testdb.Connect(t, "keysmismatch")
	defer db.Close()
	ctx := context.Background()

	// given
	existingPriv, _, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	existingEnc, err := EncryptPrivateKey(existingPriv, "pw-existing")
	assert.NoError(t, err)
	seedSpaceKey(t, db, existingEnc)
	rowBefore := readSpaceKeyRow(t, db)

	otherPriv, _, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	otherEnc, err := EncryptPrivateKey(otherPriv, "other-passphrase-1234")
	assert.NoError(t, err)
	otherBlob, err := EncodeIdentityBlob(otherEnc)
	assert.NoError(t, err)

	keyFile := filepath.Join(t.TempDir(), ".space", "identity.key")
	service := NewKeyService(NewKeyRepository(db), "", otherBlob, "other-passphrase-1234", keyFile, false)

	// when
	err = service.Initialize(ctx)

	// then
	assert.Error(t, err)
	_, statErr := os.Stat(keyFile)
	assert.True(t, os.IsNotExist(statErr))
	assert.Equal(t, rowBefore, readSpaceKeyRow(t, db))
}

// TestIdentityMigration_UsersWithoutKeyOrRow_Integration: accounts exist but
// neither key file nor row does, so a fresh key must not be minted.
func TestIdentityMigration_UsersWithoutKeyOrRow_Integration(t *testing.T) {
	db := testdb.Connect(t, "keysnokey")
	defer db.Close()

	// given
	insertTestUserAndDevice(t, db, "user-pk-1", "alice")
	keyFile := filepath.Join(t.TempDir(), ".space", "identity.key")
	service := NewKeyService(NewKeyRepository(db), "", "", "", keyFile, false)

	// when
	err := service.Initialize(context.Background())

	// then
	assert.Error(t, err)
	_, statErr := os.Stat(keyFile)
	assert.True(t, os.IsNotExist(statErr))
}
