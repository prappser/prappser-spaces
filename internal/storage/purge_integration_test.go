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
	svc := NewService(NewRepository(db), backend, 0)

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

	sched := NewDeletedAppPurgeScheduler(application.NewRepository(db), svc)

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
	svc := NewService(NewRepository(db), failingDeleteBackend{backend}, 0)

	_, err = db.Exec(`INSERT INTO users (public_key, username, role, created_at, issuer) VALUES ('purge-pk', 'purge', 'user', $1, 'purge-pk') ON CONFLICT DO NOTHING`, time.Now().Unix())
	require.NoError(t, err)
	seedPurgeApp(t, db, svc, "purge-app-fail", nil)

	// when
	err = svc.CleanupApplicationStorage(context.Background(), "purge-app-fail")

	// then
	assert.Error(t, err)
	assert.Equal(t, 1, countRows(t, db, "storage", "purge-app-fail"))
}
