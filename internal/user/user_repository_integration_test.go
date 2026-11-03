//go:build integration

package user

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goccy/go-json"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"

	"github.com/prappser/prappser-spaces/internal/testdb"
)

const ownKeyForTest = "own"

// getTestDB returns a *sql.DB scoped to this package's own Postgres schema,
// built from the real files/migrations (see internal/testdb) rather than a
// hand-written copy - so this file can't drift from production schema.
func getTestDB(t *testing.T) *sql.DB {
	t.Helper()
	return testdb.Connect(t, "user")
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
	err := repo.SetPasswordCredentials("test-user-1", "hmac-sha256$dGVzdC12ZXJpZmllcg==", "test-salt", "", "", ownKeyForTest)

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
	err := repo.SetPasswordCredentials("test-user-1", "hmac-sha256$dGVzdC12ZXJpZmllcg==", "test-salt", "sealed-account-key", "sealed-user-state", ownKeyForTest)

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
	assert.NoError(t, repo.SetPasswordCredentials("test-user-1", "hmac-sha256$AAAA", "test-salt", "sealed-account-key", "sealed-user-state", ownKeyForTest))

	// when - re-set with no escrow blobs
	err := repo.SetPasswordCredentials("test-user-1", "hmac-sha256$BBBB", "test-salt", "", "", ownKeyForTest)

	// then
	assert.NoError(t, err)
	accountKeyBlob, userState, err := repo.GetEscrow("test-user-1")
	assert.NoError(t, err)
	assert.Empty(t, accountKeyBlob)
	assert.Empty(t, userState)
}

// TestUserRepository_ClearEscrow_ShouldNullVerifierAndBlobsButKeepHandle_Integration
// pins ClearEscrow's exact column list against the real schema: verifier and
// both escrow blobs go to SQL NULL, password_handle survives untouched (see
// ClearEscrow's doc comment for why).
func TestUserRepository_ClearEscrow_ShouldNullVerifierAndBlobsButKeepHandle_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4)",
		"test-clear-escrow-user", "test-clear-escrow-alice", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}
	assert.NoError(t, repo.SetPasswordCredentials("test-clear-escrow-user", "hmac-sha256$AAAA", "test-clear-escrow-handle", "sealed-account-key", "sealed-user-state", ownKeyForTest))

	// when
	err := repo.ClearEscrow("test-clear-escrow-user", ownKeyForTest)

	// then
	assert.NoError(t, err)
	accountKeyBlob, userState, err := repo.GetEscrow("test-clear-escrow-user")
	assert.NoError(t, err)
	assert.Empty(t, accountKeyBlob)
	assert.Empty(t, userState)

	var verifier sql.NullString
	var handle sql.NullString
	assert.NoError(t, db.QueryRow(
		"SELECT password_verifier, password_handle FROM users WHERE public_key = $1",
		"test-clear-escrow-user",
	).Scan(&verifier, &handle))
	assert.False(t, verifier.Valid, "password_verifier must be SQL NULL after ClearEscrow")
	assert.True(t, handle.Valid, "password_handle must survive ClearEscrow")
	assert.Equal(t, "test-clear-escrow-handle", handle.String)
}

// TestUserRepository_ClearEscrow_ShouldBeIdempotent_Integration covers the
// no-error-on-already-clear contract: an account with nothing escrowed still
// succeeds.
func TestUserRepository_ClearEscrow_ShouldBeIdempotent_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4)",
		"test-clear-escrow-idempotent-user", "test-clear-escrow-idempotent-alice", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}

	// when - cleared twice in a row, neither call has anything to clear
	assert.NoError(t, repo.ClearEscrow("test-clear-escrow-idempotent-user", ownKeyForTest))
	err := repo.ClearEscrow("test-clear-escrow-idempotent-user", ownKeyForTest)

	// then
	assert.NoError(t, err)
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
	assert.NoError(t, repo.SetPasswordCredentials("test-user-1", "hmac-sha256$DDDD", "test-salt", "", "", ownKeyForTest))

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
	assert.NoError(t, repo.SetPasswordCredentials("test-user-2", "hmac-sha256$CCCC", "test-salt", "", "", ownKeyForTest))

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
	assert.NoError(t, repo.SetPasswordCredentials("test-user-1", "hmac-sha256$AAAA", "test-salt", "", "", ownKeyForTest))

	// when - a different account, whose username differs only by case, also sets a password
	err := repo.SetPasswordCredentials("test-user-2", "hmac-sha256$BBBB", "test-salt", "", "", ownKeyForTest)

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
	assert.NoError(t, repo.SetPasswordCredentials("test-user-1", "hmac-sha256$AAAA", "test-salt", "", "", ownKeyForTest))
	// test-user-2 must be password-enabled too, or the partial index simply
	// doesn't cover it and the rename below would succeed unconstrained.
	assert.NoError(t, repo.SetPasswordCredentials("test-user-2", "hmac-sha256$BBBB", "test-salt-2", "", "", ownKeyForTest))

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
	assert.NoError(t, repo.SetPasswordCredentials("test-user-1", "hmac-sha256$CCCC", "test-salt-3", "", "", ownKeyForTest))

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
	assert.NoError(t, repo.SetPasswordCredentials("test-user-1", "hmac-sha256$EEEE", "handle-first", "", "", ownKeyForTest))

	// when - re-set with a different handle argument
	assert.NoError(t, repo.SetPasswordCredentials("test-user-1", "hmac-sha256$FFFF", "handle-second", "", "", ownKeyForTest))

	// then - the FIRST handle sticks
	handle, err := repo.GetPasswordHandle("test-handled")
	assert.NoError(t, err)
	assert.Equal(t, "handle-first", handle)
}

func TestUserRepository_SetPasswordCredentials_ShouldRepointHandleAfterClearEscrowAndRename_Integration(t *testing.T) {
	// given - a cleared account (NULL verifier, stale handle) that was renamed
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4)",
		"test-user-1", "Alice", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}
	assert.NoError(t, repo.SetPasswordCredentials("test-user-1", "hmac-sha256$AAAA", "alice", "", "", ownKeyForTest))
	assert.NoError(t, repo.ClearEscrow("test-user-1", ownKeyForTest))
	assert.NoError(t, repo.UpdateUsername("test-user-1", "Bob"))

	// when
	assert.NoError(t, repo.SetPasswordCredentials("test-user-1", "hmac-sha256$BBBB", "bob", "", "", ownKeyForTest))

	// then - the stale handle is replaced, not COALESCEd
	handle, err := repo.GetPasswordHandle("Bob")
	assert.NoError(t, err)
	assert.Equal(t, "bob", handle)
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

func seedEscrowUser(t *testing.T, db *sql.DB, key string) {
	t.Helper()
	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at, password_verifier, account_key_blob, user_state_blob) VALUES ($1,$2,$3,$4,'v','acct','state')",
		key, "alice", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}
}

func escrowPresent(t *testing.T, db *sql.DB, key string) (blob, state, verifier bool) {
	t.Helper()
	var b, s, v sql.NullString
	if err := db.QueryRow("SELECT account_key_blob, user_state_blob, password_verifier FROM users WHERE public_key = $1", key).Scan(&b, &s, &v); err != nil {
		t.Fatalf("Failed to read escrow: %v", err)
	}
	return b.Valid, s.Valid, v.Valid
}

func TestUserRepository_AcceptBinding_ShouldStoreFirstBindingAndLoadItBack_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)
	seedEscrowUser(t, db, "acct-1")

	// when
	stored, sub, updated, err := repo.AcceptBinding("acct-1", "jws-1", 100, "sub-b", "own")

	// then
	assert.NoError(t, err)
	assert.True(t, updated)
	assert.Equal(t, "jws-1", stored)
	assert.Equal(t, "sub-b", sub)
	got, err := repo.GetUserByPublicKey("acct-1")
	assert.NoError(t, err)
	assert.Equal(t, "jws-1", got.StoredBinding)
	assert.Equal(t, int64(100), got.BindingIat)
	assert.Equal(t, "sub-b", got.BindingSub)
}

func TestUserRepository_AcceptBinding_ShouldIgnoreLowerAndEqualPairs_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)
	seedEscrowUser(t, db, "acct-1")
	_, _, _, err := repo.AcceptBinding("acct-1", "jws-high", 200, "sub-b", "own")
	assert.NoError(t, err)

	// when
	_, _, lowerUpdated, err1 := repo.AcceptBinding("acct-1", "jws-low", 100, "sub-z", "own")
	_, _, lowerSubUpdated, err2 := repo.AcceptBinding("acct-1", "jws-lowsub", 200, "sub-a", "own")
	stored, sub, equalUpdated, err3 := repo.AcceptBinding("acct-1", "jws-equal", 200, "sub-b", "own")

	// then
	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.NoError(t, err3)
	assert.False(t, lowerUpdated)
	assert.False(t, lowerSubUpdated)
	assert.False(t, equalUpdated)
	assert.Equal(t, "jws-high", stored)
	assert.Equal(t, "sub-b", sub)
}

func TestUserRepository_AcceptBinding_ShouldBreakEqualIatTieWithHigherSub_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)
	seedEscrowUser(t, db, "acct-1")
	_, _, _, err := repo.AcceptBinding("acct-1", "jws-b", 200, "sub-b", "own")
	assert.NoError(t, err)

	// when
	stored, sub, updated, err := repo.AcceptBinding("acct-1", "jws-c", 200, "sub-c", "own")

	// then
	assert.NoError(t, err)
	assert.True(t, updated)
	assert.Equal(t, "jws-c", stored)
	assert.Equal(t, "sub-c", sub)
}

func TestUserRepository_AcceptBinding_ShouldOrderSubsByBytesAtEqualIat_Integration(t *testing.T) {
	// given: byte order puts "B-sub" below "a-sub"; a locale collation would not
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)
	seedEscrowUser(t, db, "acct-1")
	_, _, _, err := repo.AcceptBinding("acct-1", "jws-upper", 200, "B-sub", "own")
	assert.NoError(t, err)

	// when
	stored, sub, updated, err := repo.AcceptBinding("acct-1", "jws-lower", 200, "a-sub", "own")

	// then
	assert.NoError(t, err)
	assert.True(t, updated)
	assert.Equal(t, "jws-lower", stored)
	assert.Equal(t, "a-sub", sub)
}

func TestUserRepository_AcceptBinding_ShouldClearEscrowForForeignSub_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)
	seedEscrowUser(t, db, "acct-1")

	// when
	_, _, updated, err := repo.AcceptBinding("acct-1", "jws-1", 100, "foreign", "own")

	// then
	assert.NoError(t, err)
	assert.True(t, updated)
	blob, state, verifier := escrowPresent(t, db, "acct-1")
	assert.False(t, blob)
	assert.False(t, state)
	assert.False(t, verifier)
}

func TestUserRepository_AcceptBinding_ShouldKeepEscrowForOwnSub_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)
	seedEscrowUser(t, db, "acct-1")

	// when
	_, _, updated, err := repo.AcceptBinding("acct-1", "jws-1", 100, "own", "own")

	// then
	assert.NoError(t, err)
	assert.True(t, updated)
	blob, state, verifier := escrowPresent(t, db, "acct-1")
	assert.True(t, blob)
	assert.True(t, state)
	assert.True(t, verifier)
}

func TestUserRepository_AcceptBinding_ShouldNotStoreOwnSubWithoutEscrow_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)
	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4)",
		"acct-1", "alice", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}

	// when
	stored, sub, updated, err := repo.AcceptBinding("acct-1", "jws-1", 100, "own", "own")

	// then
	assert.NoError(t, err)
	assert.False(t, updated)
	assert.Empty(t, stored)
	assert.Empty(t, sub)
}

// ---- #114: ClaimOwner ----

// TestUserRepository_ClaimOwner_ShouldWriteUserAndDeviceAtomically_Integration
// covers ClaimOwner's whole transaction against a real Postgres: the owner
// row (role, verifier, handle) and its device #1 row
// (keyed by the same public key) both land in a single call.
func TestUserRepository_ClaimOwner_ShouldWriteUserAndDeviceAtomically_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)
	createdAt := time.Now().Unix()

	// when
	err := repo.ClaimOwner("test-claim-user-1", "test-claim-alice", "hmac-sha256$AAAA", "test-claim-alice", "sealed-account-key", "sealed-user-state", "test-claim-user-1", nil, createdAt)

	// then - the owner row
	assert.NoError(t, err)
	got, err := repo.GetUserByPublicKey("test-claim-user-1")
	assert.NoError(t, err)
	if assert.NotNil(t, got) {
		assert.Equal(t, RoleOwner, got.Role)
		assert.Equal(t, "test-claim-alice", got.Username)
	}

	// then - device #1, keyed by the account key
	device, err := repo.GetDevice("test-claim-user-1")
	assert.NoError(t, err)
	if assert.NotNil(t, device) {
		assert.Equal(t, "test-claim-user-1", device.UserPublicKey)
		assert.Equal(t, createdAt, device.CreatedAt)
	}

	// then - password credential and handle
	userPublicKey, verifier, err := repo.GetPasswordCredential("test-claim-alice")
	assert.NoError(t, err)
	assert.Equal(t, "test-claim-user-1", userPublicKey)
	assert.Equal(t, "hmac-sha256$AAAA", verifier)
	handle, err := repo.GetPasswordHandle("test-claim-alice")
	assert.NoError(t, err)
	assert.Equal(t, "test-claim-alice", handle)
}

// TestUserRepository_ClaimOwner_ShouldStorePasswordVerifierAndHandleAsSQLNullWhenEmpty_Integration
// is the real-Postgres guard for the ClaimOwner NULLIF wrapping (see
// ClaimOwner's doc comment): a passwordless claim must store SQL NULL, not
// an empty string, in password_verifier and password_handle. A unit test
// against a fake repo can't tell the two apart (see
// TestClaim_ShouldSucceedWithoutAuthSecretAndReportNoPasswordViaGetProfile in
// owner_claim_endpoints_test.go, which still covers the endpoint wiring) -
// only a real column read distinguishes them, and the difference matters
// because GetPasswordCredential's query below is IS NOT NULL, not != ”.
func TestUserRepository_ClaimOwner_ShouldStorePasswordVerifierAndHandleAsSQLNullWhenEmpty_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)

	// when - claim without a password: empty verifier and handle
	err := repo.ClaimOwner("test-claim-no-password-user", "test-claim-no-password-alice", "", "", "", "", "test-claim-no-password-user", nil, time.Now().Unix())

	// then
	assert.NoError(t, err)
	var verifier, handle sql.NullString
	assert.NoError(t, db.QueryRow(
		"SELECT password_verifier, password_handle FROM users WHERE public_key = $1",
		"test-claim-no-password-user",
	).Scan(&verifier, &handle))
	assert.False(t, verifier.Valid, "password_verifier must be SQL NULL, not '', for a passwordless claim")
	assert.False(t, handle.Valid, "password_handle must be SQL NULL, not '', for a passwordless claim")
}

// TestUserRepository_ClaimOwner_ShouldRejectConcurrentClaimsExceptOne_Integration
// is the real-Postgres proof for ClaimOwner's doc comment: space_owner_claim's
// primary key (migration 000024), not any check on users, is what actually
// serializes concurrent claims. N goroutines race ClaimOwner at once, each
// with a DISTINCT public_key and username, so every users/user_devices
// INSERT succeeds unconditionally for all of them - the only thing that can
// catch a loser is the claim table's primary key. That precondition is
// exactly why this can assert the mapping is exact rather than "some error":
// every loser must be ErrSpaceAlreadyClaimed specifically, and the losers'
// users/user_devices rows must be rolled back with it (see the owner-count
// assertion below). The strictness is a property of this test's
// distinct-username setup, not a general guarantee of ClaimOwner - a
// same-username race (see
// TestUserRepository_ClaimOwner_ShouldRejectConcurrentSameUsernameClaimsExceptOne_Integration
// below) hits a DIFFERENT unique index first (usersPasswordUsernameIdx),
// before any of them ever reach the claim table.
func TestUserRepository_ClaimOwner_ShouldRejectConcurrentClaimsExceptOne_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)
	const n = 10
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)

	// when
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			pk := fmt.Sprintf("test-claim-concurrent-user-%d", i)
			username := fmt.Sprintf("test-claim-concurrent-name-%d", i)
			errs[i] = repo.ClaimOwner(pk, username, "hmac-sha256$AAAA", strings.ToLower(username), "", "", pk, nil, time.Now().Unix())
		}(i)
	}
	wg.Wait()

	// then - exactly one nil, the rest ErrSpaceAlreadyClaimed and nothing else
	nilCount, alreadyClaimedCount := 0, 0
	for i, err := range errs {
		switch {
		case err == nil:
			nilCount++
		case errors.Is(err, ErrSpaceAlreadyClaimed):
			alreadyClaimedCount++
		default:
			t.Errorf("errs[%d]: expected nil or ErrSpaceAlreadyClaimed, got %v", i, err)
		}
	}
	assert.Equal(t, 1, nilCount)
	assert.Equal(t, n-1, alreadyClaimedCount)

	// then - exactly one owner row exists
	var ownerCount int
	assert.NoError(t, db.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'owner'").Scan(&ownerCount))
	assert.Equal(t, 1, ownerCount)
}

// TestUserRepository_ClaimOwner_ShouldRejectConcurrentSameUsernameClaimsExceptOne_Integration
// pins the contract the distinct-username test above cannot: when every
// goroutine also races on the SAME username, usersPasswordUsernameIdx (not
// the claim table) is what a loser's users INSERT trips FIRST - ClaimOwner
// writes password_verifier unconditionally, so every attempt here is
// password-enabled and collides on username before any of them reach the
// claim-row INSERT at all. Only the single winner's transaction ever gets
// that far, so unlike the distinct-username test, every loser here must be
// ErrUsernameTaken specifically, never ErrSpaceAlreadyClaimed.
func TestUserRepository_ClaimOwner_ShouldRejectConcurrentSameUsernameClaimsExceptOne_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)
	const n = 10
	const username = "test-claim-concurrent-shared-name"
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)

	// when
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			pk := fmt.Sprintf("test-claim-concurrent-shared-user-%d", i)
			errs[i] = repo.ClaimOwner(pk, username, "hmac-sha256$AAAA", strings.ToLower(username), "", "", pk, nil, time.Now().Unix())
		}(i)
	}
	wg.Wait()

	// then - exactly one nil, the rest ErrUsernameTaken and nothing else
	nilCount, rejectedCount := 0, 0
	for i, err := range errs {
		switch {
		case err == nil:
			nilCount++
		case errors.Is(err, ErrUsernameTaken):
			rejectedCount++
		default:
			t.Errorf("errs[%d]: expected nil or ErrUsernameTaken, got %v", i, err)
		}
	}
	assert.Equal(t, 1, nilCount)
	assert.Equal(t, n-1, rejectedCount)

	// then - exactly one owner row exists
	var sharedOwnerCount int
	assert.NoError(t, db.QueryRow("SELECT COUNT(*) FROM users WHERE role = 'owner'").Scan(&sharedOwnerCount))
	assert.Equal(t, 1, sharedOwnerCount)
}

// TestUserRepository_ClaimOwner_ShouldRoundTripEscrowWithGetEscrow_Integration
// is the real end-to-end contract with #113: the account-key/user-state
// blobs handed to ClaimOwner come back byte-identical from GetEscrow, the
// same call the password-login device-enroll path (#113) uses to hand them
// back to a client.
func TestUserRepository_ClaimOwner_ShouldRoundTripEscrowWithGetEscrow_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)
	assert.NoError(t, repo.ClaimOwner("test-claim-escrow-user", "test-claim-escrow-name", "hmac-sha256$AAAA", "test-claim-escrow-name", "sealed-account-key", "sealed-user-state", "test-claim-escrow-user", nil, time.Now().Unix()))

	// when
	accountKeyBlob, userState, err := repo.GetEscrow("test-claim-escrow-user")

	// then
	assert.NoError(t, err)
	assert.Equal(t, "sealed-account-key", accountKeyBlob)
	assert.Equal(t, "sealed-user-state", userState)
}

// TestUserRepository_ClaimOwner_ShouldKeepSaltIdenticalAcrossClaim_Integration
// is why ClaimOwner's caller (owner_claim_endpoints.go's Claim) always passes
// handle = lower(username): GetSalt's anti-enumeration fallback (computed
// from lower(username) alone, with no DB lookup, before any account exists)
// must derive to the SAME salt GetSalt returns once the account is claimed
// and GetPasswordHandle starts resolving a stored handle - otherwise a
// client that fetched its salt before claiming would find its escrow
// unwrapped under the wrong key afterwards.
func TestUserRepository_ClaimOwner_ShouldKeepSaltIdenticalAcrossClaim_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)
	saltSecret := []byte("salt-secret")
	pe := NewPasswordEndpoints(repo, saltSecret, []byte("verifier-key"), "")
	username := "test-claim-salt-name"

	beforeCtx := newSaltRequestCtx(username)
	pe.GetSalt(beforeCtx)
	var before saltResponse
	assert.NoError(t, json.Unmarshal(beforeCtx.Response.Body(), &before))

	// when - claim the space under this same username, handle = lower(username)
	assert.NoError(t, repo.ClaimOwner("test-claim-salt-user", username, "hmac-sha256$AAAA", strings.ToLower(username), "", "", "test-claim-salt-user", nil, time.Now().Unix()))

	afterCtx := newSaltRequestCtx(username)
	pe.GetSalt(afterCtx)
	var after saltResponse
	assert.NoError(t, json.Unmarshal(afterCtx.Response.Body(), &after))

	// then
	assert.Equal(t, before.Salt, after.Salt)
}

// TestMigration_SpaceOwnerClaim_ShouldBackfillClaimFromLegacyMultiOwnerSpace_Integration
// is the whole point of this rework (see
// files/migrations/000024_space_owner_claim.up.sql's doc comment): a real
// deployed space that predates #114's one-owner rule can hold several
// role='owner' rows (the old POST /users/owners/register had no such guard),
// and the migration must succeed against that data AND leave it alone -
// nothing demoted - while still producing exactly one claim row, so a
// subsequent ClaimOwner correctly refuses a second claim.
//
// This reads and executes the ACTUAL migration file from disk, not a
// hand-copied inline SQL string, so a future edit to the migration is what
// this test exercises, not a frozen snapshot of it that could silently drift
// from the real file. It stops short of going through golang-migrate's own
// version-tracking machinery, though: getTestDB already runs the real
// migrations (including 000024 itself) via internal/testdb, providing the
// migrations 000001-000023 baseline this test needs; dropping
// space_owner_claim below re-creates the pre-000024 starting point so this
// test can prove out 000024 itself against that baseline.
func TestMigration_SpaceOwnerClaim_ShouldBackfillClaimFromLegacyMultiOwnerSpace_Integration(t *testing.T) {
	// given - drop the space_owner_claim table getTestDB's schema creates, so
	// this test starts exactly like a legacy pre-000024 database: nothing
	// has created that table yet.
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)
	if _, err := db.Exec("DROP TABLE IF EXISTS space_owner_claim"); err != nil {
		t.Fatalf("Failed to drop space_owner_claim: %v", err)
	}

	now := time.Now().Unix()
	owners := []struct {
		pk, username string
		createdAt    int64
	}{
		{"test-legacy-owner-1", "test-legacy-alice", now},
		{"test-legacy-owner-2", "test-legacy-bob", now + 1},
		{"test-legacy-owner-3", "test-legacy-carol", now + 2},
	}
	for _, o := range owners {
		if _, err := db.Exec(
			"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,'owner',$3)",
			o.pk, o.username, o.createdAt,
		); err != nil {
			t.Fatalf("Failed to seed legacy owner %s: %v", o.pk, err)
		}
	}

	migrationSQL, err := os.ReadFile("../../files/migrations/000024_space_owner_claim.up.sql")
	if err != nil {
		t.Fatalf("Failed to read migration 000024: %v", err)
	}

	// when
	_, err = db.Exec(string(migrationSQL))

	// then (a) - the migration succeeds
	assert.NoError(t, err)

	// then (b) - nothing was demoted, all three legacy owners are untouched
	var ownerCount int
	assert.NoError(t, db.QueryRow(
		"SELECT COUNT(*) FROM users WHERE role = 'owner' AND public_key LIKE 'test-legacy-%'",
	).Scan(&ownerCount))
	assert.Equal(t, 3, ownerCount)

	// then (c) - exactly one claim row exists, crediting the OLDEST owner
	var claimCount int
	assert.NoError(t, db.QueryRow("SELECT COUNT(*) FROM space_owner_claim").Scan(&claimCount))
	assert.Equal(t, 1, claimCount)
	var claimedOwner string
	assert.NoError(t, db.QueryRow("SELECT owner_public_key FROM space_owner_claim WHERE id = 'main'").Scan(&claimedOwner))
	assert.Equal(t, "test-legacy-owner-1", claimedOwner, "the oldest owner (by created_at) is recorded as the historical claimant")

	// then (d) - a fresh claim attempt against this now-claimed legacy space is refused
	err = repo.ClaimOwner("test-legacy-new-claimant", "test-legacy-newname", "hmac-sha256$AAAA", "test-legacy-newname", "", "", "test-legacy-new-claimant", nil, time.Now().Unix())
	assert.ErrorIs(t, err, ErrSpaceAlreadyClaimed)
}

func TestUserRepository_ClearEscrow_ShouldRefuseWhenBindingNamesOwnKey_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)
	seedEscrowUser(t, db, "acct-1")
	_, _, _, err := repo.AcceptBinding("acct-1", "jws-1", 100, ownKeyForTest, ownKeyForTest)
	assert.NoError(t, err)

	// when
	err = repo.ClearEscrow("acct-1", ownKeyForTest)

	// then
	assert.ErrorIs(t, err, ErrIdentitySpaceEscrow)
	blob, state, verifier := escrowPresent(t, db, "acct-1")
	assert.True(t, blob)
	assert.True(t, state)
	assert.True(t, verifier)
}

func TestUserRepository_ClearEscrow_ShouldClearWhenBindingNamesForeignKey_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)
	seedEscrowUser(t, db, "acct-1")
	_, err := db.Exec("UPDATE users SET binding_sub = 'foreign' WHERE public_key = 'acct-1'")
	assert.NoError(t, err)

	// when
	err = repo.ClearEscrow("acct-1", ownKeyForTest)

	// then
	assert.NoError(t, err)
	blob, state, verifier := escrowPresent(t, db, "acct-1")
	assert.False(t, blob)
	assert.False(t, state)
	assert.False(t, verifier)
}

func TestUserRepository_SetPasswordCredentials_ShouldRefuseEmptyBlobWhenBindingNamesOwnKey_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)
	seedEscrowUser(t, db, "acct-1")
	_, err := db.Exec("UPDATE users SET binding_sub = $1 WHERE public_key = 'acct-1'", ownKeyForTest)
	assert.NoError(t, err)

	// when
	refused := repo.SetPasswordCredentials("acct-1", "hmac-sha256$ZZZZ", "h", "", "", ownKeyForTest)
	allowed := repo.SetPasswordCredentials("acct-1", "hmac-sha256$ZZZZ", "h", "new-blob", "", ownKeyForTest)

	// then
	assert.ErrorIs(t, refused, ErrIdentitySpaceEscrow)
	assert.NoError(t, allowed)
	blob, _, _ := escrowPresent(t, db, "acct-1")
	assert.True(t, blob)
}
