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
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
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
		MutedApplicationIDs: []string{},
		CreatedAt:           time.Now().Unix(),
	}
	assert.NoError(t, repo.CreateSubscription(sub))

	// when: update
	sub.P256dh = "p256dh-new"
	sub.MutedApplicationIDs = []string{"muted-app-2"}
	err := repo.UpdateSubscription(sub)

	// then
	assert.NoError(t, err)
	subs, err := repo.GetSubscriptionsForUsers([]string{"test-user-1"})
	assert.NoError(t, err)
	assert.Len(t, subs, 1)
	assert.Equal(t, "p256dh-new", subs[0].P256dh)
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

func TestPushRepository_GetSubscriptionsForUsers_ShouldIncludeAccountLocale_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewPushRepository(db)
	if _, err := db.Exec("UPDATE users SET locale = 'pl' WHERE public_key = $1", "test-user-1"); err != nil {
		t.Fatalf("Failed to set locale: %v", err)
	}
	sub := &Subscription{
		ID:                  "sub-locale",
		DevicePublicKey:     "test-user-1",
		Endpoint:            "https://push.example.com/locale",
		P256dh:              "p",
		Auth:                "a",
		MutedApplicationIDs: []string{},
		CreatedAt:           time.Now().Unix(),
	}
	if err := repo.CreateSubscription(sub); err != nil {
		t.Fatalf("Failed to create subscription: %v", err)
	}

	// when
	subs, err := repo.GetSubscriptionsForUsers([]string{"test-user-1"})

	// then
	assert.NoError(t, err)
	var got *Subscription
	for _, s := range subs {
		if s.ID == "sub-locale" {
			got = s
		}
	}
	if assert.NotNil(t, got) {
		assert.Equal(t, "pl", got.Locale)
	}
}

func TestPushRepository_GetSubscriptionsForUsers_ShouldIncludeAccountNotifyMode_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewPushRepository(db)
	if _, err := db.Exec("UPDATE users SET notify_mode = 'all' WHERE public_key = $1", "test-user-1"); err != nil {
		t.Fatalf("Failed to reset notify_mode: %v", err)
	}
	sub := &Subscription{
		ID:                  "sub-notify-mode",
		DevicePublicKey:     "test-user-1",
		Endpoint:            "https://push.example.com/notify-mode",
		P256dh:              "p",
		Auth:                "a",
		MutedApplicationIDs: []string{},
		CreatedAt:           time.Now().Unix(),
	}
	if err := repo.CreateSubscription(sub); err != nil {
		t.Fatalf("Failed to create subscription: %v", err)
	}
	find := func() *Subscription {
		subs, err := repo.GetSubscriptionsForUsers([]string{"test-user-1"})
		assert.NoError(t, err)
		for _, s := range subs {
			if s.ID == "sub-notify-mode" {
				return s
			}
		}
		return nil
	}

	// when
	before := find()
	if _, err := db.Exec("UPDATE users SET notify_mode = 'chat' WHERE public_key = $1", "test-user-1"); err != nil {
		t.Fatalf("Failed to set notify_mode: %v", err)
	}
	after := find()

	// then
	if assert.NotNil(t, before) {
		assert.Equal(t, "all", before.NotifyMode)
	}
	if assert.NotNil(t, after) {
		assert.Equal(t, "chat", after.NotifyMode)
	}
}

func TestMigration_ShouldDropCategoriesAndDefaultNotifyModeToAll_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	if _, err := db.Exec("INSERT INTO users (public_key, username, role, created_at) VALUES ('migration-user', 'migration-user', 'user', 1) ON CONFLICT DO NOTHING"); err != nil {
		t.Fatalf("Failed to insert user: %v", err)
	}

	// when
	var columns int
	err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'push_subscriptions' AND column_name = 'categories'`).Scan(&columns)
	var mode string
	modeErr := db.QueryRow("SELECT notify_mode FROM users WHERE public_key = 'migration-user'").Scan(&mode)

	// then
	assert.NoError(t, err)
	assert.Equal(t, 0, columns)
	assert.NoError(t, modeErr)
	assert.Equal(t, "all", mode)
}

func insertDevice(t *testing.T, db *sql.DB, device string) {
	t.Helper()
	if _, err := db.Exec(
		"INSERT INTO user_devices (device_public_key, user_public_key, created_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
		device, "test-user-1", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert device %s: %v", device, err)
	}
}

func TestPushRepository_WSSubscriptions_ShouldCoexistAcrossDevicesWithEmptyEndpoint_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewPushRepository(db)
	insertDevice(t, db, "ws-device-2")
	now := time.Now().Unix()

	// when
	_, err1 := repo.UpsertWSSubscription(&Subscription{ID: "ws-a", DevicePublicKey: "test-user-1", MutedApplicationIDs: []string{}, CreatedAt: now})
	_, err2 := repo.UpsertWSSubscription(&Subscription{ID: "ws-b", DevicePublicKey: "ws-device-2", MutedApplicationIDs: []string{}, CreatedAt: now})

	// then
	assert.NoError(t, err1)
	assert.NoError(t, err2)
	subs, err := repo.GetSubscriptionsForUsers([]string{"test-user-1"})
	assert.NoError(t, err)
	assert.Len(t, subs, 2)
	for _, s := range subs {
		assert.Equal(t, TransportWS, s.Transport)
		assert.Equal(t, "test-user-1", s.UserPublicKey)
		assert.Empty(t, s.Endpoint)
	}
}

func TestPushRepository_UpsertWSSubscription_ShouldKeepOneRowAndID_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewPushRepository(db)
	now := time.Now().Unix()
	first, err := repo.UpsertWSSubscription(&Subscription{ID: "ws-first", DevicePublicKey: "test-user-1", MutedApplicationIDs: []string{}, CreatedAt: now})
	assert.NoError(t, err)

	// when
	second, err := repo.UpsertWSSubscription(&Subscription{ID: "ws-second", DevicePublicKey: "test-user-1", MutedApplicationIDs: []string{"app-1"}, CreatedAt: now})

	// then
	assert.NoError(t, err)
	assert.Equal(t, first, second)
	var count int
	assert.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM push_subscriptions WHERE transport = 'ws'`).Scan(&count))
	assert.Equal(t, 1, count)
	got, err := repo.GetSubscriptionByID(first, "test-user-1")
	assert.NoError(t, err)
	assert.Equal(t, []string{"app-1"}, got.MutedApplicationIDs)
}

func TestPushRepository_WebpushAndWS_ShouldCoexistForOneDeviceAndKeepEndpointUnique_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewPushRepository(db)
	now := time.Now().Unix()
	_, err := repo.UpsertWSSubscription(&Subscription{ID: "ws-x", DevicePublicKey: "test-user-1", MutedApplicationIDs: []string{}, CreatedAt: now})
	assert.NoError(t, err)

	// when
	err = repo.CreateSubscription(&Subscription{ID: "wp-x", DevicePublicKey: "test-user-1", Endpoint: "https://push.example.com/dup", P256dh: "p", Auth: "a", CreatedAt: now})
	dup := repo.CreateSubscription(&Subscription{ID: "wp-y", DevicePublicKey: "test-user-1", Endpoint: "https://push.example.com/dup", P256dh: "p", Auth: "a", CreatedAt: now})

	// then
	assert.NoError(t, err)
	assert.Error(t, dup)
	subs, err := repo.GetSubscriptionsForUsers([]string{"test-user-1"})
	assert.NoError(t, err)
	assert.Len(t, subs, 2)
}

func TestPushRepository_GetSubscriptionsForUsers_ShouldDropRevokedWSDevice_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	repo := NewPushRepository(db)
	insertDevice(t, db, "ws-revoked")
	_, err := repo.UpsertWSSubscription(&Subscription{ID: "ws-r", DevicePublicKey: "ws-revoked", MutedApplicationIDs: []string{}, CreatedAt: time.Now().Unix()})
	assert.NoError(t, err)

	// when
	_, err = db.Exec(`UPDATE user_devices SET revoked_at = $1 WHERE device_public_key = $2`, time.Now().Unix(), "ws-revoked")
	assert.NoError(t, err)
	subs, err := repo.GetSubscriptionsForUsers([]string{"test-user-1"})

	// then
	assert.NoError(t, err)
	assert.Empty(t, subs)
}

type digestFixture struct {
	db   *sql.DB
	repo PushRepository
	user string
	sub  string
}

func newDigestFixture(t *testing.T, name string, seenAt int64) *digestFixture {
	t.Helper()
	db := getTestDB(t)
	t.Cleanup(func() { db.Close() })
	user, sub := "dg-user-"+name, "dg-sub-"+name
	now := time.Now().Unix()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO users (public_key, username, role, created_at, notify_mode, notifications_seen_at) VALUES ($1,$1,'user',$2,'daily',$3) ON CONFLICT DO NOTHING", []any{user, now, seenAt}},
		{"INSERT INTO user_devices (device_public_key, user_public_key, created_at) VALUES ($1,$1,$2) ON CONFLICT DO NOTHING", []any{user, now}},
		{"INSERT INTO push_subscriptions (id, device_public_key, endpoint, p256dh, auth, created_at) VALUES ($1,$2,'https://push.example.com/'||$1,'p','a',$3) ON CONFLICT DO NOTHING", []any{sub, user, now}},
	} {
		if _, err := db.Exec(q.sql, q.args...); err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}
	return &digestFixture{db: db, repo: NewPushRepository(db), user: user, sub: sub}
}

func (f *digestFixture) app(t *testing.T, id, name string, member, deleted bool) {
	t.Helper()
	var deletedAt any
	if deleted {
		deletedAt = int64(1)
	}
	if _, err := f.db.Exec("INSERT INTO applications (id, name, created_at, updated_at, deleted_at) VALUES ($1,$2,1,1,$3) ON CONFLICT DO NOTHING", id, name, deletedAt); err != nil {
		t.Fatalf("app: %v", err)
	}
	if member {
		if _, err := f.db.Exec("INSERT INTO members (id, application_id, role, public_key) VALUES ($1,$2,'member',$3) ON CONFLICT DO NOTHING", id+"-"+f.user, id, f.user); err != nil {
			t.Fatalf("member: %v", err)
		}
	}
}

func (f *digestFixture) pending(t *testing.T, app string, count int, lastAt int64) {
	t.Helper()
	if _, err := f.db.Exec("INSERT INTO push_digest_pending (subscription_id, application_id, component_key, kind, title, count, last_at) VALUES ($1,$2,'list-1','item','Groceries',$3,$4)", f.sub, app, count, lastAt); err != nil {
		t.Fatalf("pending: %v", err)
	}
}

func (f *digestFixture) pendingRows(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow("SELECT COUNT(*) FROM push_digest_pending WHERE subscription_id = $1", f.sub).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func TestPushRepository_CountDigest_ShouldIncrementAndResetOnceRead_Integration(t *testing.T) {
	// given
	f := newDigestFixture(t, "count", 0)
	f.app(t, "dg-app-count", "A", true, false)
	bucket := DigestBucket{Key: "list-1", Kind: KindItem, Title: "Groceries"}
	read := func() (n int, last int64) {
		if err := f.db.QueryRow("SELECT count, last_at FROM push_digest_pending WHERE subscription_id=$1 AND application_id='dg-app-count' AND component_key='list-1'", f.sub).Scan(&n, &last); err != nil {
			t.Fatalf("read: %v", err)
		}
		return
	}

	// when
	assert.NoError(t, f.repo.CountDigest(f.sub, "dg-app-count", bucket, 100, 0))
	assert.NoError(t, f.repo.CountDigest(f.sub, "dg-app-count", bucket, 110, 0))
	assert.NoError(t, f.repo.CountDigest(f.sub, "dg-app-count", bucket, 120, 0))
	n, last := read()

	// then
	assert.Equal(t, 3, n)
	assert.Equal(t, int64(120), last)

	// when: the account read everything up to 130, the next event starts over
	assert.NoError(t, f.repo.CountDigest(f.sub, "dg-app-count", bucket, 140, 130))
	n, last = read()

	// then
	assert.Equal(t, 1, n)
	assert.Equal(t, int64(140), last)
}

func TestPushRepository_CountDigest_ShouldKeepSeparateRowPerComponent_Integration(t *testing.T) {
	// given
	f := newDigestFixture(t, "bucket", 0)
	f.app(t, "dg-app-bucket", "A", true, false)

	// when
	assert.NoError(t, f.repo.CountDigest(f.sub, "dg-app-bucket", DigestBucket{Key: "list-1", Kind: KindItem, Title: "Old"}, 100, 0))
	assert.NoError(t, f.repo.CountDigest(f.sub, "dg-app-bucket", DigestBucket{Key: "list-1", Kind: KindItem, Title: "New"}, 110, 0))
	assert.NoError(t, f.repo.CountDigest(f.sub, "dg-app-bucket", DigestBucket{Key: "chat", Kind: KindChat}, 120, 0))
	rows, claimed, err := f.repo.ClaimDigest(f.user, 1000, 2000)

	// then
	assert.NoError(t, err)
	assert.True(t, claimed)
	assert.ElementsMatch(t, []DigestRow{
		{SubscriptionID: f.sub, ApplicationID: "dg-app-bucket", AppName: "A", Kind: KindItem, Title: "New", Count: 2},
		{SubscriptionID: f.sub, ApplicationID: "dg-app-bucket", AppName: "A", Kind: KindChat, Count: 1},
	}, rows)
}

func TestPushRepository_ClaimDigest_ShouldReturnLiveUnreadRowsDeleteAllAndClaimOncePerDue_Integration(t *testing.T) {
	// given
	f := newDigestFixture(t, "claim", 100)
	f.app(t, "dg-live", "Live", true, false)
	f.app(t, "dg-read", "Read", true, false)
	f.app(t, "dg-gone", "Gone", true, true)
	f.app(t, "dg-left", "Left", false, false)
	f.pending(t, "dg-live", 3, 200)
	f.pending(t, "dg-read", 5, 50)
	f.pending(t, "dg-gone", 4, 200)
	f.pending(t, "dg-left", 2, 200)

	// when
	rows, claimed, err := f.repo.ClaimDigest(f.user, 1000, 2000)
	again, claimedAgain, errAgain := f.repo.ClaimDigest(f.user, 1000, 2001)

	// then
	assert.NoError(t, err)
	assert.True(t, claimed)
	assert.Equal(t, []DigestRow{{SubscriptionID: f.sub, ApplicationID: "dg-live", AppName: "Live", Kind: KindItem, Title: "Groceries", Count: 3}}, rows)
	assert.Equal(t, 0, f.pendingRows(t))
	assert.NoError(t, errAgain)
	assert.False(t, claimedAgain)
	assert.Empty(t, again)
	var sentAt int64
	assert.NoError(t, f.db.QueryRow("SELECT digest_sent_at FROM users WHERE public_key=$1", f.user).Scan(&sentAt))
	assert.Equal(t, int64(2000), sentAt)
}

func TestPushRepository_ClaimDigest_ShouldNotClaimOutsideDailyMode_Integration(t *testing.T) {
	// given
	f := newDigestFixture(t, "mode", 0)
	f.app(t, "dg-mode", "A", true, false)
	f.pending(t, "dg-mode", 1, 10)
	if _, err := f.db.Exec("UPDATE users SET notify_mode='all' WHERE public_key=$1", f.user); err != nil {
		t.Fatal(err)
	}

	// when
	rows, claimed, err := f.repo.ClaimDigest(f.user, 1000, 2000)

	// then
	assert.NoError(t, err)
	assert.False(t, claimed)
	assert.Empty(t, rows)
	assert.Equal(t, 1, f.pendingRows(t))
}

func TestPushRepository_GetDailyUsers_ShouldReturnOnlyDailyAccountsWithTimezoneAndStamp_Integration(t *testing.T) {
	// given
	f := newDigestFixture(t, "daily", 0)
	if _, err := f.db.Exec("UPDATE users SET timezone='Europe/Warsaw', digest_sent_at=77 WHERE public_key=$1", f.user); err != nil {
		t.Fatal(err)
	}

	// when
	users, err := f.repo.GetDailyUsers()

	// then
	assert.NoError(t, err)
	assert.Contains(t, users, DigestUser{PublicKey: f.user, Timezone: "Europe/Warsaw", SentAt: 77})
	assert.NotContains(t, users, DigestUser{PublicKey: "test-user-1", Timezone: "", SentAt: 0})
}

func TestPushRepository_DeleteSubscription_ShouldCascadePendingDigestRows_Integration(t *testing.T) {
	// given
	f := newDigestFixture(t, "cascade", 0)
	f.app(t, "dg-cascade", "A", true, false)
	f.pending(t, "dg-cascade", 1, 10)

	// when
	err := f.repo.DeleteSubscription(f.sub, f.user)

	// then
	assert.NoError(t, err)
	assert.Equal(t, 0, f.pendingRows(t))
}

func TestPushRepository_GetSubscriptionsForUsers_ShouldIncludeNotificationsSeenAt_Integration(t *testing.T) {
	// given
	f := newDigestFixture(t, "seen", 321)

	// when
	subs, err := f.repo.GetSubscriptionsForUsers([]string{f.user})

	// then
	assert.NoError(t, err)
	if assert.Len(t, subs, 1) {
		assert.Equal(t, int64(321), subs[0].NotificationsSeenAt)
	}
}
