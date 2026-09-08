//go:build integration

package application

import (
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/prappser/prappser-spaces/internal/testdb"
)

// TestUpdateLastSequence_LowerValue_NeverLowersStoredMax pins the GREATEST
// floor: a write with a lower sequence than what's already stored (an
// out-of-order update, or a retry racing a newer one) must leave the
// high-water mark alone.
func TestUpdateLastSequence_LowerValue_NeverLowersStoredMax(t *testing.T) {
	db := testdb.Connect(t, "application")
	defer db.Close()
	repo := NewRepository(db)

	appID := "test-lastseq-app-1"
	if err := repo.CreateApplication(&Application{ID: appID, Name: "LastSeq App", CreatedAt: time.Now().Unix(), UpdatedAt: time.Now().Unix()}); err != nil {
		t.Fatalf("Failed to create application: %v", err)
	}

	if err := repo.UpdateLastSequence(appID, 45); err != nil {
		t.Fatalf("Failed to set last_sequence to 45: %v", err)
	}
	if err := repo.UpdateLastSequence(appID, 1); err != nil {
		t.Fatalf("Failed to call UpdateLastSequence(1): %v", err)
	}

	app, err := repo.GetApplicationByID(appID)
	if err != nil {
		t.Fatalf("GetApplicationByID: unexpected error: %v", err)
	}
	if app.LastSequence == nil || *app.LastSequence != 45 {
		t.Fatalf("expected last_sequence to remain 45, got %v", app.LastSequence)
	}
}
