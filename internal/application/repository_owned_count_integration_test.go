//go:build integration

package application

import (
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/prappser/prappser-spaces/internal/testdb"
)

func TestRepository_CountOwnedApplications_CountsOnlyLiveOwnedApps_Integration(t *testing.T) {
	// given
	db := testdb.Connect(t, "application")
	defer db.Close()
	repo := NewRepository(db)
	now := time.Now().Unix()
	pk := "test-count-pk"
	testdb.InsertTestUser(t, db, pk)

	for _, a := range []struct {
		id   string
		role MemberRole
	}{
		{"test-count-live", MemberRoleOwner},
		{"test-count-deleted", MemberRoleOwner},
		{"test-count-admin", MemberRoleAdmin},
	} {
		if err := repo.CreateApplication(&Application{ID: a.id, Name: a.id, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatalf("Failed to create application: %v", err)
		}
		if err := repo.CreateMember(&Member{ID: a.id + "-m", ApplicationID: a.id, Role: a.role, PublicKey: pk}); err != nil {
			t.Fatalf("Failed to create member: %v", err)
		}
	}
	if err := repo.DeleteApplication("test-count-deleted"); err != nil {
		t.Fatalf("Failed to delete application: %v", err)
	}

	// when
	count, err := repo.CountOwnedApplications(pk)

	// then
	if err != nil {
		t.Fatalf("CountOwnedApplications: unexpected error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 (live owned only), got %d", count)
	}
}

func TestRepository_IsApplicationLive_ShouldReportLiveOnly_Integration(t *testing.T) {
	// given
	db := testdb.Connect(t, "application")
	defer db.Close()
	repo := NewRepository(db)
	now := time.Now().Unix()
	for _, id := range []string{"test-live-app", "test-live-deleted"} {
		if err := repo.CreateApplication(&Application{ID: id, Name: id, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatalf("Failed to create application: %v", err)
		}
	}
	if err := repo.DeleteApplication("test-live-deleted"); err != nil {
		t.Fatalf("Failed to delete application: %v", err)
	}

	// when / then
	for id, want := range map[string]bool{"test-live-app": true, "test-live-deleted": false, "test-live-missing": false} {
		live, err := repo.IsApplicationLive(id)
		if err != nil {
			t.Fatalf("IsApplicationLive(%s): unexpected error: %v", id, err)
		}
		if live != want {
			t.Errorf("IsApplicationLive(%s) = %v, want %v", id, live, want)
		}
	}
}
