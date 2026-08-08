//go:build integration

package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

func TestUserRepository_RenameDevice_ShouldPersistNewName_Integration(t *testing.T) {
	// given: fixture keys are unique to this test so concurrently-run
	// packages' integration tests (also hitting this shared DB) can't collide.
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)
	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
		"test-devrepo-rename-user", "alice", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}
	name := "Old Name"
	assert.NoError(t, repo.EnsureDevice("test-devrepo-rename-device", "test-devrepo-rename-user", &name, time.Now().Unix()))

	// when
	err := repo.RenameDevice("test-devrepo-rename-device", "New Name")

	// then
	assert.NoError(t, err)
	device, err := repo.GetDevice("test-devrepo-rename-device")
	assert.NoError(t, err)
	if assert.NotNil(t, device.DeviceName) {
		assert.Equal(t, "New Name", *device.DeviceName)
	}
}

// TestVerifyDelegation_AccountKeySelfDelegation_Integration exercises
// verifyDelegation's account-key fallback (issue #116 phase 2) against the
// REAL repository/DB, not the in-memory mock used by device_endpoints_test.go
// - the mock's GetDevice/GetUserByPublicKey behavior on a miss could silently
// drift from what the real SQL returns.
func TestVerifyDelegation_AccountKeySelfDelegation_Integration(t *testing.T) {
	// given: fixture keys are unique to this test so concurrently-run
	// packages' integration tests (also hitting this shared DB) can't collide.
	db := getTestDB(t)
	defer db.Close()
	repo := NewUserRepository(db)
	de := NewDeviceEndpoints(repo, nil, "test-devrepo-selfdeleg-space")

	accountPub, accountPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	accountKeyB64 := base64.StdEncoding.EncodeToString(accountPub)
	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
		accountKeyB64, "test-devrepo-selfdeleg-alice", "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}

	now := time.Now().Unix()
	buildJWS := func(jti string) string {
		claims := jwt.MapClaims{
			"iss": accountKeyB64, "jti": jti, "iat": now, "exp": now + 300,
			"dpk": "test-devrepo-selfdeleg-enrolling-device", "aud": "test-devrepo-selfdeleg-space",
		}
		signed, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(accountPriv)
		assert.NoError(t, err)
		return signed
	}

	// when: the account key vouches for itself, with no device row yet.
	signer, err := de.verifyDelegation(buildJWS("test-devrepo-selfdeleg-jti-1"), "test-devrepo-selfdeleg-enrolling-device")

	// then: accepted, synthesized as the account key's own device.
	assert.NoError(t, err)
	if assert.NotNil(t, signer) {
		assert.Equal(t, accountKeyB64, signer.UserPublicKey)
	}

	// given: device #1 (the account key's own row) gets enrolled, then revoked.
	assert.NoError(t, repo.EnsureDevice(accountKeyB64, accountKeyB64, nil, now))
	assert.NoError(t, repo.RevokeDevice(accountKeyB64, now))

	// when/then: the same self-delegation is now rejected - revoking device #1
	// stays a permanent kill switch even though the issuer is still the
	// account key.
	_, err = de.verifyDelegation(buildJWS("test-devrepo-selfdeleg-jti-2"), "test-devrepo-selfdeleg-enrolling-device")
	assert.Error(t, err)
}
