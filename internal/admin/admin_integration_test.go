//go:build integration

package admin

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/testdb"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

func newAdminDB(t *testing.T) *sql.DB {
	t.Helper()
	db := testdb.Connect(t, "admin")
	t.Cleanup(func() { db.Close() })
	return db
}

func exec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	_, err := db.Exec(query, args...)
	require.NoError(t, err)
}

func seedUser(t *testing.T, db *sql.DB, pk, role string, createdAt int64) {
	t.Helper()
	testdb.InsertTestUser(t, db, pk)
	exec(t, db, `UPDATE users SET role = $2, created_at = $3 WHERE public_key = $1`, pk, role, createdAt)
	exec(t, db, `INSERT INTO user_devices (device_public_key, user_public_key, created_at) VALUES ($1, $1, $2)`, pk, createdAt)
}

func seedApp(t *testing.T, db *sql.DB, id string, deletedAt *int64) {
	t.Helper()
	exec(t, db, `INSERT INTO applications (id, name, created_at, updated_at, deleted_at) VALUES ($1, $1, 1, 1, $2)`, id, deletedAt)
}

func seedMember(t *testing.T, db *sql.DB, appID, pk, role string, expiresAt *int64) {
	t.Helper()
	exec(t, db, `INSERT INTO members (id, application_id, role, public_key, membership_expires_at) VALUES ($1, $2, $3, $4, $5)`, appID+"-"+pk, appID, role, pk, expiresAt)
}

func seedFile(t *testing.T, db *sql.DB, id, uploader, status string, size int64) {
	t.Helper()
	exec(t, db, `INSERT INTO storage (id, uploader_public_key, filename, content_type, size_bytes, storage_path, checksum, created_at, status)
		VALUES ($1, $2, 'f', 'application/octet-stream', $3, 'p', 'c', 1, $4)`, id, uploader, size, status)
}

func ptr(v int64) *int64 { return &v }

func TestListAccounts_ShouldAggregatePerAccount(t *testing.T) {
	// given
	db := newAdminDB(t)
	seedUser(t, db, "alice", "user", 10)
	seedUser(t, db, "bob", "user", 20)
	seedApp(t, db, "live", nil)
	seedApp(t, db, "co-owned", nil)
	seedApp(t, db, "expired-membership", nil)
	seedApp(t, db, "soft-deleted", ptr(5))
	seedMember(t, db, "live", "alice", "owner", nil)
	seedMember(t, db, "co-owned", "alice", "owner", nil)
	seedMember(t, db, "co-owned", "bob", "owner", nil)
	seedMember(t, db, "expired-membership", "alice", "owner", ptr(1))
	seedMember(t, db, "soft-deleted", "alice", "owner", nil)
	seedFile(t, db, "f-live", "alice", "ready", 100)
	seedFile(t, db, "f-pending", "alice", "pending", 25)
	exec(t, db, `INSERT INTO storage (id, application_id, uploader_public_key, filename, content_type, size_bytes, storage_path, checksum, created_at)
		VALUES ('f-deleted-app', 'soft-deleted', 'alice', 'f', 'x', 50, 'p', 'c', 1)`)
	seedFile(t, db, "f-orphan", "ghost", "ready", 999)
	exec(t, db, `INSERT INTO user_devices (device_public_key, user_public_key, created_at, last_seen_at, revoked_at) VALUES ('alice-old', 'alice', 1, 500, 600)`)
	exec(t, db, `UPDATE user_devices SET last_seen_at = 100 WHERE device_public_key = 'alice'`)

	// when
	accounts, err := NewRepository(db).ListAccounts()

	// then
	require.NoError(t, err)
	require.Len(t, accounts, 2)
	assert.Equal(t, "alice", accounts[0].PublicKey)
	assert.Equal(t, "bob", accounts[1].PublicKey)
	assert.Equal(t, AccountOverview{PublicKey: "alice", Username: "test-user-alice", Role: "user", CreatedAt: 10, LastActiveAt: ptr(500), StorageBytes: 175, FileCount: 3, OwnedApps: 2}, accounts[0])
	assert.Equal(t, AccountOverview{PublicKey: "bob", Username: "test-user-bob", Role: "user", CreatedAt: 20, StorageBytes: 0, FileCount: 0, OwnedApps: 1}, accounts[1])
}

func TestListAccounts_ShouldReturnZerosAndNullLastActiveForIdleAccount(t *testing.T) {
	// given
	db := newAdminDB(t)
	seedUser(t, db, "idle", "guest", 1)

	// when
	accounts, err := NewRepository(db).ListAccounts()

	// then
	require.NoError(t, err)
	assert.Equal(t, []AccountOverview{{PublicKey: "idle", Username: "test-user-idle", Role: "guest", CreatedAt: 1}}, accounts)
}

func ctxWithRole(role string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue("user", &user.User{PublicKey: "caller", Role: role})
	return ctx
}

func TestListAccounts_ShouldReturn401WithoutUser(t *testing.T) {
	// given
	e := NewAdminEndpoints(nil, Limits{})
	ctx := &fasthttp.RequestCtx{}

	// when
	e.ListAccounts(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}

func TestListAccounts_ShouldReturn403ForNonOwner(t *testing.T) {
	// given
	e := NewAdminEndpoints(nil, Limits{})
	ctx := ctxWithRole(user.RoleUser)

	// when
	e.ListAccounts(ctx)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
}

func TestListAccounts_ShouldEchoLimitsAndEncodeEmptyListAsArray(t *testing.T) {
	// given
	e := NewAdminEndpoints(NewRepository(newAdminDB(t)), Limits{AccountQuotaBytes: 262144000, MaxAppsPerAccount: 20})
	ctx := ctxWithRole(user.RoleOwner)

	// when
	e.ListAccounts(ctx)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	assert.JSONEq(t, `{"limits":{"accountQuotaBytes":262144000,"maxAppsPerAccount":20},"accounts":[]}`, string(ctx.Response.Body()))
}

func TestListAccounts_ShouldNeverExposeContent(t *testing.T) {
	// given
	db := newAdminDB(t)
	seedUser(t, db, "owner-pk", "owner", 1)
	exec(t, db, `UPDATE users SET password_verifier = 'SENT-pwv', password_handle = 'SENT-pwh', account_key_blob = 'SENT-akb', user_state_blob = 'SENT-usb', issuer = 'SENT-issuer' WHERE public_key = 'owner-pk'`)
	exec(t, db, `UPDATE user_devices SET device_name = 'SENT-device', last_seen_at = 42 WHERE device_public_key = 'owner-pk'`)
	exec(t, db, `INSERT INTO applications (id, name, icon, created_at, updated_at) VALUES ('app', 'SENT-appname', 'SENT-appicon', 1, 1)`)
	seedMember(t, db, "app", "owner-pk", "owner", nil)
	exec(t, db, `INSERT INTO component_groups (id, application_id, name, index_order) VALUES ('g', 'app', 'SENT-groupname', 0)`)
	exec(t, db, `INSERT INTO components (id, component_group_id, application_id, name, data, index_order) VALUES ('c', 'g', 'app', 'SENT-compname', 'SENT-compdata', 0)`)
	exec(t, db, `INSERT INTO storage (id, application_id, uploader_public_key, filename, content_type, size_bytes, storage_path, thumbnail_path, checksum, created_at)
		VALUES ('SENT-fileid', 'app', 'owner-pk', 'SENT-filename', 'SENT-ctype', 7, 'SENT-path', 'SENT-thumb', 'SENT-checksum', 1)`)
	exec(t, db, `INSERT INTO events (id, created_at, application_id, type, data) VALUES ('e', 1, 'app', 't', 'SENT-eventdata')`)
	e := NewAdminEndpoints(NewRepository(db), Limits{AccountQuotaBytes: 1, MaxAppsPerAccount: 1})
	ctx := ctxWithRole(user.RoleOwner)

	// when
	e.ListAccounts(ctx)

	// then
	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	body := string(ctx.Response.Body())
	assert.False(t, strings.Contains(body, "SENT-"), body)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &decoded))
	assert.ElementsMatch(t, []string{"limits", "accounts"}, keys(decoded))
	assert.ElementsMatch(t, []string{"accountQuotaBytes", "maxAppsPerAccount"}, keys(decoded["limits"].(map[string]any)))
	accounts := decoded["accounts"].([]any)
	require.Len(t, accounts, 1)
	assert.ElementsMatch(t, []string{"publicKey", "username", "role", "createdAt", "lastActiveAt", "storageBytes", "fileCount", "ownedApps"}, keys(accounts[0].(map[string]any)))
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
