//go:build integration

package storage

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/testdb"
)

func seedPurgeApp(t *testing.T, db *sql.DB, svc *Service, id string, deletedAt *int64) string {
	t.Helper()
	ctx := context.Background()
	now := time.Now().Unix()

	_, err := db.Exec(`INSERT INTO applications (id, name, created_at, updated_at, deleted_at) VALUES ($1, $1, $2, $2, $3)`, id, now, deletedAt)
	require.NoError(t, err)

	path := id + "/blob.bin"
	require.NoError(t, svc.backend.Store(ctx, path, bytes.NewReader([]byte("data"))))
	_, err = db.Exec(`INSERT INTO storage (id, application_id, uploader_public_key, filename, content_type, size_bytes, storage_path, checksum, created_at)
		VALUES ($1, $2, 'purge-pk', 'blob.bin', 'application/octet-stream', 4, $3, 'x', $4)`, id+"-storage", id, path, now)
	require.NoError(t, err)
	return path
}

func countRows(t *testing.T, db *sql.DB, table, appID string) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE application_id = $1`, appID).Scan(&n))
	return n
}

func TestPurgeDeletedApps_ShouldHardDeleteOnlyAppsDeletedBeyondRetention_Integration(t *testing.T) {
	// given
	db := testdb.Connect(t, "storage")
	defer db.Close()

	root := t.TempDir()
	backend, err := NewLocalStorage(&BackendConfig{LocalPath: root})
	require.NoError(t, err)
	svc := NewService(NewRepository(db), backend, 0, 0)

	now := time.Now()
	old := now.Add(-31 * 24 * time.Hour).Unix()
	recent := now.Add(-24 * time.Hour).Unix()

	_, err = db.Exec(`INSERT INTO users (public_key, username, role, created_at, issuer) VALUES ('purge-pk', 'purge', 'user', $1, 'purge-pk') ON CONFLICT DO NOTHING`, now.Unix())
	require.NoError(t, err)

	pathA := seedPurgeApp(t, db, svc, "purge-app-a", &old)
	pathB := seedPurgeApp(t, db, svc, "purge-app-b", &recent)
	pathC := seedPurgeApp(t, db, svc, "purge-app-c", nil)

	_, err = db.Exec(`INSERT INTO component_groups (id, application_id, name, index_order) VALUES ('purge-group-a', 'purge-app-a', 'g', 0)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO components (id, component_group_id, application_id, name, index_order) VALUES ('purge-comp-a', 'purge-group-a', 'purge-app-a', 'c', 0)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO members (id, application_id, role, public_key) VALUES ('purge-member-a', 'purge-app-a', 'member', 'purge-pk')`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO invitations (id, application_id, created_by_public_key, created_at) VALUES ('purge-invite-a', 'purge-app-a', 'purge-pk', $1)`, now.Unix())
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO events (id, created_at, application_id, type) VALUES ('purge-event-a', $1, 'purge-app-a', 'test')`, now.Unix())
	require.NoError(t, err)

	sched := NewStoragePurgeScheduler(application.NewRepository(db), svc)

	// when
	sched.PurgeDeletedApps(context.Background())

	// then
	for _, table := range []string{"applications", "component_groups", "components", "members", "invitations", "events", "storage"} {
		col := "application_id"
		if table == "applications" {
			col = "id"
		}
		var n int
		require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE `+col+` = 'purge-app-a'`).Scan(&n))
		assert.Zero(t, n, table)
	}
	_, err = os.Stat(filepath.Join(root, pathA))
	assert.True(t, os.IsNotExist(err))

	for id, path := range map[string]string{"purge-app-b": pathB, "purge-app-c": pathC} {
		var n int
		require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM applications WHERE id = $1`, id).Scan(&n))
		assert.Equal(t, 1, n, id)
		assert.Equal(t, 1, countRows(t, db, "storage", id), id)
		_, err = os.Stat(filepath.Join(root, path))
		assert.NoError(t, err, id)
	}
}

type failingDeleteBackend struct {
	StorageBackend
}

func (failingDeleteBackend) Delete(_ context.Context, _ string) error {
	return errors.New("delete failed")
}

func TestCleanupApplicationStorage_ShouldKeepRowsWhenBlobDeleteFails_Integration(t *testing.T) {
	// given
	db := testdb.Connect(t, "storage")
	defer db.Close()

	backend, err := NewLocalStorage(&BackendConfig{LocalPath: t.TempDir()})
	require.NoError(t, err)
	svc := NewService(NewRepository(db), failingDeleteBackend{backend}, 0, 0)

	_, err = db.Exec(`INSERT INTO users (public_key, username, role, created_at, issuer) VALUES ('purge-pk', 'purge', 'user', $1, 'purge-pk') ON CONFLICT DO NOTHING`, time.Now().Unix())
	require.NoError(t, err)
	seedPurgeApp(t, db, svc, "purge-app-fail", nil)

	// when
	err = svc.CleanupApplicationStorage(context.Background(), "purge-app-fail")

	// then
	assert.Error(t, err)
	assert.Equal(t, 1, countRows(t, db, "storage", "purge-app-fail"))
}

func TestPurgeUnreferenced_ShouldDeleteOnlyOldUnreferencedBlobs_Integration(t *testing.T) {
	// given
	db := testdb.Connect(t, "storage")
	defer db.Close()

	root := t.TempDir()
	backend, err := NewLocalStorage(&BackendConfig{LocalPath: root})
	require.NoError(t, err)
	svc := NewService(NewRepository(db), backend, 0, 0)
	ctx := context.Background()

	now := time.Now()
	old := now.Add(-100 * 24 * time.Hour).Unix()
	recentRef := now.Add(-10 * 24 * time.Hour).Unix()

	const appID, userKey = "unref-app", "unref-pk"
	_, err = db.Exec(`UPDATE users SET avatar_storage_id = NULL WHERE public_key = $1`, userKey)
	require.NoError(t, err)
	_, err = db.Exec(`DELETE FROM storage WHERE id LIKE 'unref-%'`)
	require.NoError(t, err)
	_, err = db.Exec(`DELETE FROM events WHERE application_id = $1`, appID)
	require.NoError(t, err)
	_, err = db.Exec(`DELETE FROM applications WHERE id = $1`, appID)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO users (public_key, username, role, created_at, issuer) VALUES ($1, 'unref', 'user', $2, $1) ON CONFLICT DO NOTHING`, userKey, now.Unix())
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO applications (id, name, created_at, updated_at) VALUES ($1, $1, $2, $2)`, appID, now.Unix())
	require.NoError(t, err)

	seed := func(id, status string, lastReferenced *int64, createdAt int64, thumb bool) {
		path := appID + "/" + id + ".bin"
		require.NoError(t, backend.Store(ctx, path, bytes.NewReader([]byte("data"))))
		var thumbPath *string
		if thumb {
			p := appID + "/" + id + ".thumb"
			require.NoError(t, backend.Store(ctx, p, bytes.NewReader([]byte("t"))))
			thumbPath = &p
		}
		_, err := db.Exec(`INSERT INTO storage (id, application_id, uploader_public_key, filename, content_type, size_bytes, storage_path, thumbnail_path, checksum, created_at, status, last_referenced_at)
			VALUES ($1, $2, $3, 'f.bin', 'application/octet-stream', 4, $4, $5, 'x', $6, $7, $8)`, id, appID, userKey, path, thumbPath, createdAt, status, lastReferenced)
		require.NoError(t, err)
	}

	survivors := []string{"unref-files", "unref-quill", "unref-event", "unref-icon", "unref-avatar", "unref-recent", "unref-pending", "unref-thumb", "unref-new"}
	for _, id := range survivors {
		status := "ready"
		if id == "unref-pending" {
			status = "pending"
		}
		last, created := &old, old
		switch id {
		case "unref-recent":
			last = &recentRef
		case "unref-new":
			last, created = nil, now.Unix()
		}
		seed(id, status, last, created, false)
	}
	seed("unref-gone", "ready", &old, old, true)

	_, err = db.Exec(`INSERT INTO component_groups (id, application_id, name, index_order) VALUES ('unref-group', $1, 'g', 0)`, appID)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO components (id, component_group_id, application_id, name, index_order, data) VALUES
		('unref-comp-files', 'unref-group', $1, 'c', 0, '{"items":[{"id":"x","storageId":"unref-files"}]}'),
		('unref-comp-quill', 'unref-group', $1, 'c', 1, '{"doc":[{"insert":{"image":"https://host/storage/unref-quill"}}]}'),
		('unref-comp-thumb', 'unref-group', $1, 'c', 2, '{"img":"https://host/storage/unref-thumb/thumb"}')`, appID)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO events (id, created_at, application_id, type, data) VALUES ('unref-event-1', $1, $2, 'test', '{"fileId":"unref-event"}')`, now.Unix(), appID)
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE applications SET icon = 'storage:unref-icon' WHERE id = $1`, appID)
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE users SET avatar_storage_id = 'unref-avatar' WHERE public_key = $1`, userKey)
	require.NoError(t, err)

	// when
	require.NoError(t, svc.PurgeUnreferenced(ctx, now.Add(-90*24*time.Hour).Unix(), 100))

	// then
	for _, id := range survivors {
		var n int
		require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM storage WHERE id = $1`, id).Scan(&n))
		assert.Equal(t, 1, n, id)
		_, err = os.Stat(filepath.Join(root, appID, id+".bin"))
		assert.NoError(t, err, id)
	}

	var bumped int64
	require.NoError(t, db.QueryRow(`SELECT last_referenced_at FROM storage WHERE id = 'unref-files'`).Scan(&bumped))
	assert.InDelta(t, now.Unix(), bumped, 60)

	var n int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM storage WHERE id = 'unref-gone'`).Scan(&n))
	assert.Zero(t, n)
	for _, f := range []string{"unref-gone.bin", "unref-gone.thumb"} {
		_, err = os.Stat(filepath.Join(root, appID, f))
		assert.True(t, os.IsNotExist(err), f)
	}
}
