//go:build integration

package push

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"

	"github.com/prappser/prappser-spaces/internal/testdb"
)

// getTestDB returns a *sql.DB scoped to this package's own Postgres schema,
// built from the real files/migrations (see internal/testdb) rather than a
// hand-written copy - so this file can't drift from production schema.
func getTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db := testdb.Connect(t, "push")

	// Insert a test user and its device #1 (same key, mirroring the free
	// migration in 000018) so FK constraints pass. Schema isolation means no
	// other package's tests share this schema, so plain sequential inserts
	// are enough - no need to guard against a concurrent cross-package DELETE.
	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at, issuer) VALUES ($1,$2,$3,$4,$1) ON CONFLICT DO NOTHING",
		"test-user-1", "testuser", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}
	if _, err := db.Exec(
		"INSERT INTO user_devices (device_public_key, user_public_key, created_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
		"test-user-1", "test-user-1", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test device: %v", err)
	}

	return db
}

func TestPushRepository_UpsertAndGetSpaceVapid_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewPushRepository(db)

	now := time.Now().Unix()
	v := &SpaceVapid{
		VapidPublicKey:  "vapid-pub-key",
		VapidPrivateKey: "vapid-priv-key",
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	// when: upsert
	err := repo.UpsertSpaceVapid(v)

	// then
	assert.NoError(t, err)

	got, err := repo.GetSpaceVapid()
	assert.NoError(t, err)
	assert.NotNil(t, got)
	assert.Equal(t, "vapid-pub-key", got.VapidPublicKey)
	assert.Equal(t, "vapid-priv-key", got.VapidPrivateKey)
	assert.Equal(t, now, got.CreatedAt)
}

func TestPushRepository_UpsertSpaceVapid_ShouldUpdateOnConflict_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewPushRepository(db)

	now := time.Now().Unix()
	first := &SpaceVapid{VapidPublicKey: "pub-v1", VapidPrivateKey: "priv-v1", CreatedAt: now, UpdatedAt: now}
	second := &SpaceVapid{VapidPublicKey: "pub-v2", VapidPrivateKey: "priv-v2", CreatedAt: now, UpdatedAt: now + 1}

	// when: upsert twice
	assert.NoError(t, repo.UpsertSpaceVapid(first))
	assert.NoError(t, repo.UpsertSpaceVapid(second))

	// then: second values win
	got, err := repo.GetSpaceVapid()
	assert.NoError(t, err)
	assert.Equal(t, "pub-v2", got.VapidPublicKey)
	assert.Equal(t, now+1, got.UpdatedAt)
}

func TestPushRepository_GetSpaceVapid_ShouldReturnNilWhenNotFound_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewPushRepository(db)

	// when
	got, err := repo.GetSpaceVapid()

	// then
	assert.NoError(t, err)
	assert.Nil(t, got)
}

func TestPushRepository_UpsertSpaceVapid_ShouldRejectIdNotOne_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()

	now := time.Now().Unix()

	// when: attempt to insert with id = 2 directly (bypasses repository to test DB constraint)
	_, err := db.Exec(
		`INSERT INTO space_vapid (id, vapid_public_key, vapid_private_key, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)`,
		2, "pub", "priv", now, now,
	)

	// then: CHECK (id = 1) violation
	assert.Error(t, err)
}

func TestPushRepository_CreateAndGetSubscription_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewPushRepository(db)

	label := "My Device"
	sub := &Subscription{
		ID:                  "sub-integration-1",
		DevicePublicKey:     "test-user-1",
		Endpoint:            "https://push.example.com/integration-1",
		P256dh:              "p256dh-value",
		Auth:                "auth-value",
		DeviceLabel:         &label,
		Categories:          Categories{Member: true, Edit: false},
		MutedApplicationIDs: []string{"muted-app-1"},
		CreatedAt:           time.Now().Unix(),
	}

	// when
	err := repo.CreateSubscription(sub)
	assert.NoError(t, err)

	subs, err := repo.GetSubscriptionsForUsers([]string{"test-user-1"})

	// then
	assert.NoError(t, err)
	assert.Len(t, subs, 1)
	assert.Equal(t, "sub-integration-1", subs[0].ID)
	assert.True(t, subs[0].Categories.Member)
	assert.False(t, subs[0].Categories.Edit)
	assert.NotNil(t, subs[0].DeviceLabel)
	assert.Equal(t, "My Device", *subs[0].DeviceLabel)
	assert.Equal(t, []string{"muted-app-1"}, subs[0].MutedApplicationIDs)
}

func TestPushRepository_UpdateSubscription_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewPushRepository(db)

	sub := &Subscription{
		ID:                  "sub-integration-2",
		DevicePublicKey:     "test-user-1",
		Endpoint:            "https://push.example.com/integration-2",
		P256dh:              "p256dh-old",
		Auth:                "auth-old",
		Categories:          Categories{Member: false, Edit: false},
		MutedApplicationIDs: []string{},
		CreatedAt:           time.Now().Unix(),
	}
	assert.NoError(t, repo.CreateSubscription(sub))

	// when: update
	sub.P256dh = "p256dh-new"
	sub.Categories = Categories{Member: true, Edit: true}
	sub.MutedApplicationIDs = []string{"muted-app-2"}
	err := repo.UpdateSubscription(sub)

	// then
	assert.NoError(t, err)
	subs, err := repo.GetSubscriptionsForUsers([]string{"test-user-1"})
	assert.NoError(t, err)
	assert.Len(t, subs, 1)
	assert.Equal(t, "p256dh-new", subs[0].P256dh)
	assert.True(t, subs[0].Categories.Member)
	assert.True(t, subs[0].Categories.Edit)
	assert.Equal(t, []string{"muted-app-2"}, subs[0].MutedApplicationIDs)
}

func TestPushRepository_DeleteSubscription_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewPushRepository(db)

	sub := &Subscription{
		ID:                  "sub-integration-3",
		DevicePublicKey:     "test-user-1",
		Endpoint:            "https://push.example.com/integration-3",
		P256dh:              "p256dh",
		Auth:                "auth",
		Categories:          Categories{},
		MutedApplicationIDs: []string{},
		CreatedAt:           time.Now().Unix(),
	}
	assert.NoError(t, repo.CreateSubscription(sub))

	// when
	err := repo.DeleteSubscription("sub-integration-3", "test-user-1")

	// then
	assert.NoError(t, err)
	subs, err := repo.GetSubscriptionsForUsers([]string{"test-user-1"})
	assert.NoError(t, err)
	assert.Empty(t, subs)
}

func TestPushRepository_MarkSuccessAndIncrementFailure_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewPushRepository(db)

	sub := &Subscription{
		ID:                  "sub-integration-4",
		DevicePublicKey:     "test-user-1",
		Endpoint:            "https://push.example.com/integration-4",
		P256dh:              "p256dh",
		Auth:                "auth",
		Categories:          Categories{},
		MutedApplicationIDs: []string{},
		CreatedAt:           time.Now().Unix(),
	}
	assert.NoError(t, repo.CreateSubscription(sub))

	// when: increment failure twice then mark success
	assert.NoError(t, repo.IncrementFailure(sub.ID))
	assert.NoError(t, repo.IncrementFailure(sub.ID))

	ts := time.Now().Unix()
	assert.NoError(t, repo.MarkSuccess(sub.ID, ts))

	// then: failure_count reset to 0 and last_success_at set
	subs, err := repo.GetSubscriptionsForUsers([]string{"test-user-1"})
	assert.NoError(t, err)
	assert.Len(t, subs, 1)
	assert.Equal(t, 0, subs[0].FailureCount)
	assert.NotNil(t, subs[0].LastSuccessAt)
	assert.Equal(t, ts, *subs[0].LastSuccessAt)
}

func TestPushRepository_GetSubscriptionsForUsers_ShouldJoinAcrossDevicesAndDropRevoked_Integration(t *testing.T) {
	// given: one account with two devices, each with its own subscription
	db := getTestDB(t)
	defer db.Close()
	repo := NewPushRepository(db)

	if _, err := db.Exec(
		"INSERT INTO user_devices (device_public_key, user_public_key, created_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
		"test-device-2", "test-user-1", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert second test device: %v", err)
	}

	sub1 := &Subscription{
		ID:              "sub-device-1",
		DevicePublicKey: "test-user-1", // device #1, inserted by getTestDB
		Endpoint:        "https://push.example.com/device-1",
		P256dh:          "p256dh-1",
		Auth:            "auth-1",
		CreatedAt:       time.Now().Unix(),
	}
	sub2 := &Subscription{
		ID:              "sub-device-2",
		DevicePublicKey: "test-device-2",
		Endpoint:        "https://push.example.com/device-2",
		P256dh:          "p256dh-2",
		Auth:            "auth-2",
		CreatedAt:       time.Now().Unix(),
	}
	assert.NoError(t, repo.CreateSubscription(sub1))
	assert.NoError(t, repo.CreateSubscription(sub2))

	// when: both devices live
	subs, err := repo.GetSubscriptionsForUsers([]string{"test-user-1"})

	// then: subscriptions from both devices come back
	assert.NoError(t, err)
	assert.Len(t, subs, 2)

	// when: device 2 is revoked (raw UPDATE - push package has no RevokeDevice)
	if _, err := db.Exec(`UPDATE user_devices SET revoked_at = $1 WHERE device_public_key = $2`, time.Now().Unix(), "test-device-2"); err != nil {
		t.Fatalf("Failed to revoke test device 2: %v", err)
	}
	subs, err = repo.GetSubscriptionsForUsers([]string{"test-user-1"})

	// then: only device 1's subscription remains
	assert.NoError(t, err)
	assert.Len(t, subs, 1)
	assert.Equal(t, "sub-device-1", subs[0].ID)
}
