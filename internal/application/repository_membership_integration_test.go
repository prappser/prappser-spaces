//go:build integration

package application

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/prappser/prappser-spaces/internal/testdb"
)

// getTestDB returns a *sql.DB scoped to this package's own Postgres schema,
// built from the real files/migrations (see internal/testdb) rather than a
// hand-written copy - so this file can't drift from production schema.
func getTestDB(t *testing.T) *sql.DB {
	t.Helper()
	return testdb.Connect(t, "application")
}

// insertTestUser inserts a bare-minimum users row. The users schema is
// strict: issuer is NOT NULL with no default, and role is CHECK'd to
// owner/user/guest - self-pinning issuer to publicKey (as every real
// self-registered account does) satisfies both.
func insertTestUser(t *testing.T, db *sql.DB, publicKey string) {
	t.Helper()
	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at, issuer) VALUES ($1,$2,$3,$4,$1)",
		publicKey, "test-user-"+publicKey, "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user %s: %v", publicKey, err)
	}
}

// TestRepository_ExpiredMembership_InvisibleToAllFilteredQueries_Integration
// exercises #117's lazy filter (activeMemberPredicate) against the REAL
// repository/DB across all six queries it was applied to. The row itself is
// never deleted - member.MembershipExpiresAt is set to the past and a direct
// SQL SELECT below still finds it.
func TestRepository_ExpiredMembership_InvisibleToAllFilteredQueries_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewRepository(db)

	appID := "test-expiry-app-1"
	publicKey := "test-expiry-pk-1"
	insertTestUser(t, db, publicKey)
	if err := repo.CreateApplication(&Application{ID: appID, Name: "Expiry Integration App", CreatedAt: time.Now().Unix(), UpdatedAt: time.Now().Unix()}); err != nil {
		t.Fatalf("Failed to create application: %v", err)
	}

	past := time.Now().Add(-1 * time.Hour).Unix()
	if err := repo.CreateMember(&Member{ID: "test-expiry-member-1", ApplicationID: appID, Role: MemberRoleMember, PublicKey: publicKey, MembershipExpiresAt: &past}); err != nil {
		t.Fatalf("Failed to create member: %v", err)
	}

	// when / then: all six filtered queries treat the expired member as gone
	members, err := repo.GetMembersByApplicationID(appID)
	if err != nil {
		t.Fatalf("GetMembersByApplicationID: unexpected error: %v", err)
	}
	if len(members) != 0 {
		t.Errorf("GetMembersByApplicationID: expected 0 members, got %d", len(members))
	}

	if _, err := repo.GetMemberByPublicKey(appID, publicKey); err == nil {
		t.Error("GetMemberByPublicKey: expected error for expired member, got nil")
	}

	apps, err := repo.GetApplicationsByMemberPublicKey(publicKey)
	if err != nil {
		t.Fatalf("GetApplicationsByMemberPublicKey: unexpected error: %v", err)
	}
	if len(apps) != 0 {
		t.Errorf("GetApplicationsByMemberPublicKey: expected 0 applications, got %d", len(apps))
	}

	versions, err := repo.GetAppVersionsByMemberPublicKey(publicKey)
	if err != nil {
		t.Fatalf("GetAppVersionsByMemberPublicKey: unexpected error: %v", err)
	}
	if len(versions) != 0 {
		t.Errorf("GetAppVersionsByMemberPublicKey: expected 0 entries, got %d", len(versions))
	}

	isMember, err := repo.IsMember(appID, publicKey)
	if err != nil {
		t.Fatalf("IsMember: unexpected error: %v", err)
	}
	if isMember {
		t.Error("IsMember: expected false for expired member")
	}

	count, err := repo.GetMemberCount(appID)
	if err != nil {
		t.Fatalf("GetMemberCount: unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("GetMemberCount: expected 0, got %d", count)
	}

	// and: the row itself was never deleted - only filtered out at read time
	var rawCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM members WHERE application_id = $1 AND public_key = $2", appID, publicKey).Scan(&rawCount); err != nil {
		t.Fatalf("Failed to query raw member count: %v", err)
	}
	if rawCount != 1 {
		t.Errorf("Expected the expired member row to still exist (rawCount=1), got %d", rawCount)
	}
}

// TestRepository_ReJoin_UpsertsSameRow_NoDuplicate_Integration exercises
// CreateMember's ON CONFLICT (application_id, public_key) target (#117): a
// second "join" for the same (application_id, public_key) pair - a
// different member.ID, as a fresh member_added event would carry - updates
// the existing row in place instead of inserting a duplicate.
func TestRepository_ReJoin_UpsertsSameRow_NoDuplicate_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewRepository(db)

	appID := "test-expiry-app-2"
	publicKey := "test-expiry-pk-2"
	insertTestUser(t, db, publicKey)
	if err := repo.CreateApplication(&Application{ID: appID, Name: "Rejoin Integration App", CreatedAt: time.Now().Unix(), UpdatedAt: time.Now().Unix()}); err != nil {
		t.Fatalf("Failed to create application: %v", err)
	}

	if err := repo.CreateMember(&Member{ID: "test-rejoin-member-first", ApplicationID: appID, Role: MemberRoleMember, PublicKey: publicKey}); err != nil {
		t.Fatalf("Failed to create first member row: %v", err)
	}

	// when: a second join for the same pair, under a different member.ID and
	// a fresh expiry, as a re-join's event execution would produce
	future := time.Now().Add(2 * time.Hour).Unix()
	if err := repo.CreateMember(&Member{ID: "test-rejoin-member-second", ApplicationID: appID, Role: MemberRoleAdmin, PublicKey: publicKey, MembershipExpiresAt: &future}); err != nil {
		t.Fatalf("Failed to upsert on re-join: %v", err)
	}

	// then: exactly one row, keyed by the ORIGINAL member.ID, with the
	// re-join's role and expiry
	var rawCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM members WHERE application_id = $1 AND public_key = $2", appID, publicKey).Scan(&rawCount); err != nil {
		t.Fatalf("Failed to query raw member count: %v", err)
	}
	if rawCount != 1 {
		t.Fatalf("Expected exactly 1 member row after re-join, got %d", rawCount)
	}

	member, err := repo.GetMemberByPublicKey(appID, publicKey)
	if err != nil {
		t.Fatalf("GetMemberByPublicKey: unexpected error: %v", err)
	}
	if member.ID != "test-rejoin-member-first" {
		t.Errorf("Expected the original member.ID to be preserved across re-join, got %q", member.ID)
	}
	if member.Role != MemberRoleAdmin {
		t.Errorf("Expected role to be updated to %q, got %q", MemberRoleAdmin, member.Role)
	}
}
