//go:build integration

package user

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUserRepository_EnsureDevice_ShouldBeIdempotent_Integration(t *testing.T) {
	// given: fixture keys are unique to this test so concurrently-run
	// packages' integration tests (also hitting this shared DB) can't collide.
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)
	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
		"test-devrepo-ensure-user", "alice", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}

	// when: EnsureDevice called twice for the same device
	name := "Laptop"
	err1 := repo.EnsureDevice("test-devrepo-ensure-device", "test-devrepo-ensure-user", &name, time.Now().Unix())
	err2 := repo.EnsureDevice("test-devrepo-ensure-device", "test-devrepo-ensure-user", &name, time.Now().Unix())

	// then: no error either time, exactly one row
	assert.NoError(t, err1)
	assert.NoError(t, err2)
	devices, err := repo.ListDevices("test-devrepo-ensure-user")
	assert.NoError(t, err)
	assert.Len(t, devices, 1)
	assert.Equal(t, "test-devrepo-ensure-device", devices[0].DevicePublicKey)
}

func TestUserRepository_RevokeDevice_ShouldDeleteOnlyThatDevicesSubscriptions_Integration(t *testing.T) {
	// given: fixture keys are unique to this test so concurrently-run
	// packages' integration tests (also hitting this shared DB) can't collide.
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)
	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
		"test-devrepo-revoke-user", "alice", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}
	assert.NoError(t, repo.EnsureDevice("test-devrepo-revoke-device-1", "test-devrepo-revoke-user", nil, time.Now().Unix()))
	assert.NoError(t, repo.EnsureDevice("test-devrepo-revoke-device-2", "test-devrepo-revoke-user", nil, time.Now().Unix()))

	if _, err := db.Exec(
		`INSERT INTO push_subscriptions (id, device_public_key, endpoint, p256dh, auth, created_at) VALUES ($1,$2,$3,$4,$5,$6)`,
		"test-devrepo-sub-1", "test-devrepo-revoke-device-1", "https://push.example.com/devrepo-1", "p256dh", "auth", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert subscription for device 1: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO push_subscriptions (id, device_public_key, endpoint, p256dh, auth, created_at) VALUES ($1,$2,$3,$4,$5,$6)`,
		"test-devrepo-sub-2", "test-devrepo-revoke-device-2", "https://push.example.com/devrepo-2", "p256dh", "auth", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert subscription for device 2: %v", err)
	}

	// when
	err := repo.RevokeDevice("test-devrepo-revoke-device-1", time.Now().Unix())

	// then: device 1 revoked, its subscription gone; device 2 untouched
	assert.NoError(t, err)

	device1, err := repo.GetDevice("test-devrepo-revoke-device-1")
	assert.NoError(t, err)
	assert.NotNil(t, device1.RevokedAt)

	var count int
	assert.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM push_subscriptions WHERE id = $1`, "test-devrepo-sub-1").Scan(&count))
	assert.Equal(t, 0, count)
	assert.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM push_subscriptions WHERE id = $1`, "test-devrepo-sub-2").Scan(&count))
	assert.Equal(t, 1, count)
}

func TestUserRepository_ListDevices_ShouldHideRevoked_Integration(t *testing.T) {
	// given: fixture keys are unique to this test so concurrently-run
	// packages' integration tests (also hitting this shared DB) can't collide.
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)
	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
		"test-devrepo-list-user", "alice", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}
	assert.NoError(t, repo.EnsureDevice("test-devrepo-list-device-1", "test-devrepo-list-user", nil, time.Now().Unix()))
	assert.NoError(t, repo.EnsureDevice("test-devrepo-list-device-2", "test-devrepo-list-user", nil, time.Now().Unix()))
	assert.NoError(t, repo.RevokeDevice("test-devrepo-list-device-1", time.Now().Unix()))

	// when
	devices, err := repo.ListDevices("test-devrepo-list-user")

	// then: only the non-revoked device is returned
	assert.NoError(t, err)
	assert.Len(t, devices, 1)
	assert.Equal(t, "test-devrepo-list-device-2", devices[0].DevicePublicKey)
}
