//go:build integration

package keys

import (
	"context"
	"database/sql"
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

// TestIdentityMigration_HostingMove_Integration covers acceptance criterion
// 1 end to end: export under the old MASTER_PASSWORD, import under a new
// one against the SAME database, and confirm the space's identity, a
// pre-migration JWT, and unrelated app data (users/devices) all survive the
// move untouched, while the encrypted key material itself is re-wrapped.
func TestIdentityMigration_HostingMove_Integration(t *testing.T) {
	db := testdb.Connect(t, "keys")
	defer db.Close()
	ctx := context.Background()

	// given - the "old host": a space identity plus some unrelated data
	repo := NewKeyRepository(db)
	oldService := NewKeyService(repo, "pw-old", "", "")
	assert.NoError(t, oldService.Initialize(ctx))
	pub0 := oldService.PublicKey()

	insertTestUserAndDevice(t, db, "user-pk-1", "alice")
	insertTestUserAndDevice(t, db, "user-pk-2", "bob")
	usersBefore := snapshotUsers(t, db)
	devicesBefore := snapshotDevices(t, db)

	var pubKeyColBefore, privKeyColBefore, saltColBefore, nonceColBefore []byte
	assert.NoError(t, db.QueryRow(
		`SELECT public_key, encrypted_private_key, salt, nonce FROM space_keys WHERE id = 'main'`,
	).Scan(&pubKeyColBefore, &privKeyColBefore, &saltColBefore, &nonceColBefore))

	// a pre-migration JWT, standing in for a live session minted by the old host
	claims := testClaims{
		UserPublicKey: "user-pk-1",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}
	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(oldService.PrivateKey())
	assert.NoError(t, err)

	// when - export under the old master password, then simulate the move:
	// a fresh KeyService against the SAME db, but a new MASTER_PASSWORD and
	// the export blob configured for import.
	blob, err := oldService.ExportIdentity("export-passphrase-1234")
	assert.NoError(t, err)

	newService := NewKeyService(repo, "pw-new", blob, "export-passphrase-1234")
	err = newService.Initialize(ctx)

	// then
	assert.NoError(t, err)
	assert.Equal(t, pub0, newService.PublicKey())

	parsed, err := jwt.ParseWithClaims(tokenString, &testClaims{}, func(token *jwt.Token) (interface{}, error) {
		return newService.PublicKey(), nil
	})
	assert.NoError(t, err)
	assert.True(t, parsed.Valid, "a pre-migration JWT must still validate against the new host's public key")

	assert.Equal(t, usersBefore, snapshotUsers(t, db))
	assert.Equal(t, devicesBefore, snapshotDevices(t, db))

	var pubKeyColAfter, privKeyColAfter, saltColAfter, nonceColAfter []byte
	assert.NoError(t, db.QueryRow(
		`SELECT public_key, encrypted_private_key, salt, nonce FROM space_keys WHERE id = 'main'`,
	).Scan(&pubKeyColAfter, &privKeyColAfter, &saltColAfter, &nonceColAfter))
	assert.Equal(t, pubKeyColBefore, pubKeyColAfter, "public_key must be unchanged across a re-wrap")
	assert.NotEqual(t, privKeyColBefore, privKeyColAfter, "encrypted_private_key must change - re-wrapped under the new master password")
	assert.NotEqual(t, saltColBefore, saltColAfter, "salt must change - EncryptPrivateKey always generates a fresh one")
	assert.NotEqual(t, nonceColBefore, nonceColAfter, "nonce must change - EncryptPrivateKey always generates a fresh one")
}

// TestIdentityMigration_FreshSchemaImport_Integration covers importing into
// an empty database (no prior space_keys row) - the other supported path
// alongside the hosting-move re-wrap above.
func TestIdentityMigration_FreshSchemaImport_Integration(t *testing.T) {
	db := testdb.Connect(t, "keysimport")
	defer db.Close()
	ctx := context.Background()

	// given - a blob exported from a keypair that has never touched this DB
	priv, pub, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	enc, err := EncryptPrivateKey(priv, "export-passphrase-1234")
	assert.NoError(t, err)
	blob, err := EncodeIdentityBlob(enc)
	assert.NoError(t, err)

	repo := NewKeyRepository(db)
	service := NewKeyService(repo, "pw-new", blob, "export-passphrase-1234")

	// when
	err = service.Initialize(ctx)

	// then
	assert.NoError(t, err)
	assert.Equal(t, pub, service.PublicKey())

	stored, err := repo.GetSpaceKey(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []byte(pub), []byte(stored.PublicKey))
}

// TestIdentityMigration_MismatchGuard_Integration covers the safety check
// that stops Initialize from silently swapping a space's identity: an
// import blob for a DIFFERENT keypair than the one already stored must fail
// startup rather than overwrite it.
func TestIdentityMigration_MismatchGuard_Integration(t *testing.T) {
	db := testdb.Connect(t, "keysmismatch")
	defer db.Close()
	ctx := context.Background()

	// given - an existing space identity ...
	repo := NewKeyRepository(db)
	existingService := NewKeyService(repo, "pw-existing", "", "")
	assert.NoError(t, existingService.Initialize(ctx))

	// ... and an import blob for a completely different keypair
	otherPriv, _, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	otherEnc, err := EncryptPrivateKey(otherPriv, "other-passphrase-1234")
	assert.NoError(t, err)
	otherBlob, err := EncodeIdentityBlob(otherEnc)
	assert.NoError(t, err)

	// when
	mismatchedService := NewKeyService(repo, "pw-new", otherBlob, "other-passphrase-1234")
	err = mismatchedService.Initialize(ctx)

	// then
	assert.Error(t, err)

	// and the original identity must be left untouched
	stored, getErr := repo.GetSpaceKey(ctx)
	assert.NoError(t, getErr)
	assert.Equal(t, []byte(existingService.PublicKey()), []byte(stored.PublicKey))
}
