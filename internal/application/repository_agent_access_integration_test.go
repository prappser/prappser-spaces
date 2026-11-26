//go:build integration

package application

import (
	"errors"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/prappser/prappser-spaces/internal/testdb"
)

func TestRepository_GetAgentAccess_ShouldReturnFlagAndOwner_Integration(t *testing.T) {
	// given
	db := testdb.Connect(t, "application")
	defer db.Close()
	repo := NewRepository(db)
	now := time.Now().Unix()
	pk := "test-agent-access-pk"
	testdb.InsertTestUser(t, db, pk)
	if err := repo.RegisterApplication(&Application{ID: "test-agent-access", Name: "a", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("Failed to create application: %v", err)
	}
	if err := repo.CreateMember(&Member{ID: "test-agent-access-m", ApplicationID: "test-agent-access", Role: MemberRoleOwner, PublicKey: pk}); err != nil {
		t.Fatalf("Failed to create member: %v", err)
	}
	if err := repo.SetAgentReadEnabled("test-agent-access", false); err != nil {
		t.Fatalf("SetAgentReadEnabled: %v", err)
	}

	// when
	enabled, owner, err := repo.GetAgentAccess("test-agent-access")
	_, _, missingErr := repo.GetAgentAccess("test-agent-access-missing")

	// then
	if err != nil || enabled || owner != pk {
		t.Errorf("got enabled=%v owner=%q err=%v, want false %q nil", enabled, owner, err, pk)
	}
	if !errors.Is(missingErr, ErrNotFound) {
		t.Errorf("missing app: got %v, want ErrNotFound", missingErr)
	}
}
