//go:build integration

package profile

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/testdb"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

func count(t *testing.T, db *sql.DB, query string, args ...interface{}) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(query, args...).Scan(&n))
	return n
}

func eventData(t *testing.T, db *sql.DB, appID, eventType string) map[string]interface{} {
	t.Helper()
	var raw string
	require.NoError(t, db.QueryRow(`SELECT data FROM events WHERE application_id = $1 AND type = $2`, appID, eventType).Scan(&raw))
	var data map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(raw), &data))
	return data
}

func TestDeleteAccount_ShouldLeaveSharedAppsDeleteSoleOwnedAndEraseRows_Integration(t *testing.T) {
	// given
	db := testdb.Connect(t, "profile")
	defer db.Close()
	repo := application.NewRepository(db)
	events := event.NewEventService(event.NewEventRepository(db), repo, nil, nil)
	blobs := &mockBlobDeleter{}
	ep := NewAccountEndpoints(db, repo, events, blobs)

	const pk, other = "acct-pk-0123456789abcdefghij", "acct-other-pk-0123456789abcdef"
	now := time.Now().Unix()
	exec := func(q string, args ...interface{}) {
		t.Helper()
		_, err := db.Exec(q, args...)
		require.NoError(t, err)
	}
	testdb.InsertTestUser(t, db, pk)
	testdb.InsertTestUser(t, db, other)
	for _, id := range []string{"acct-a", "acct-b", "acct-c", "acct-d"} {
		require.NoError(t, repo.CreateApplication(&application.Application{ID: id, Name: id, CreatedAt: now, UpdatedAt: now}))
	}
	member := func(id, appID, role, key string, expires interface{}) {
		exec(`INSERT INTO members (id, application_id, role, public_key, membership_expires_at) VALUES ($1,$2,$3,$4,$5)`, id, appID, role, key, expires)
	}
	member("m-a1", "acct-a", "owner", pk, nil)
	member("m-a2", "acct-a", "member", other, nil)
	member("m-b1", "acct-b", "owner", pk, nil)
	member("m-b2", "acct-b", "owner", other, nil)
	member("m-c1", "acct-c", "owner", other, nil)
	member("m-c2", "acct-c", "member", pk, nil)
	member("m-d1", "acct-d", "owner", other, nil)
	member("m-d2", "acct-d", "member", pk, now-3600)

	exec(`INSERT INTO storage (id, application_id, uploader_public_key, filename, content_type, size_bytes, storage_path, checksum, created_at)
		VALUES ('acct-avatar', NULL, $1, 'a.png', 'image/png', 1, 'acct/a.png', 'x', $2)`, pk, now)
	exec(`UPDATE users SET avatar_storage_id = 'acct-avatar' WHERE public_key = $1`, pk)
	exec(`INSERT INTO invitations (id, application_id, created_by_public_key, created_at) VALUES ('acct-invite', 'acct-a', $1, $2)`, pk, now)
	exec(`INSERT INTO spaces (id, name, user_public_key) VALUES ('acct-space', 's', $1)`, pk)
	exec(`INSERT INTO events (id, created_at, application_id, type, creator_public_key) VALUES ('acct-user-event', $1, NULL, 'user_profile_updated', $2)`, now, pk)
	exec(`INSERT INTO events (id, created_at, application_id, type, creator_public_key) VALUES ('acct-other-event', $1, NULL, 'user_profile_updated', $2)`, now, other)

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("DELETE")
	ctx.SetUserValue("user", &user.User{PublicKey: pk, Role: user.RoleUser})

	// when
	ep.DeleteAccount(ctx)

	// then
	assert.Equal(t, fasthttp.StatusNoContent, ctx.Response.StatusCode())
	assert.Equal(t, []string{pk}, blobs.calls)
	assert.Zero(t, count(t, db, `SELECT COUNT(*) FROM users WHERE public_key = $1`, pk))
	assert.Zero(t, count(t, db, `SELECT COUNT(*) FROM members WHERE public_key = $1`, pk))
	assert.Zero(t, count(t, db, `SELECT COUNT(*) FROM storage WHERE uploader_public_key = $1 AND application_id IS NULL`, pk))
	assert.Zero(t, count(t, db, `SELECT COUNT(*) FROM events WHERE application_id IS NULL AND creator_public_key = $1`, pk))
	assert.Zero(t, count(t, db, `SELECT COUNT(*) FROM invitations WHERE created_by_public_key = $1`, pk))
	assert.Equal(t, 1, count(t, db, `SELECT COUNT(*) FROM spaces WHERE id = 'acct-space' AND user_public_key IS NULL`))

	assert.Equal(t, 1, count(t, db, `SELECT COUNT(*) FROM applications WHERE id = 'acct-a' AND deleted_at IS NOT NULL`))
	assert.Zero(t, count(t, db, `SELECT COUNT(*) FROM applications WHERE id IN ('acct-b','acct-c','acct-d') AND deleted_at IS NOT NULL`))
	deleted := eventData(t, db, "acct-a", string(event.EventTypeApplicationDeleted))
	assert.Equal(t, "acct-a", deleted["applicationId"])
	assert.Contains(t, deleted, "version")
	assert.Contains(t, deleted, "deletedAt")
	for _, appID := range []string{"acct-b", "acct-c"} {
		removed := eventData(t, db, appID, string(event.EventTypeMemberRemoved))
		assert.Equal(t, pk, removed["memberPublicKey"], appID)
		assert.Equal(t, "account_deleted", removed["reason"], appID)
	}

	assert.Zero(t, count(t, db, `SELECT COUNT(*) FROM members WHERE id = 'm-d2'`))
	assert.Equal(t, 3, count(t, db, `SELECT COUNT(*) FROM events WHERE creator_public_key = $1 AND application_id IN ('acct-a','acct-b','acct-c')`, pk))
	assert.Zero(t, count(t, db, `SELECT COUNT(*) FROM events WHERE application_id IN ('acct-a','acct-b','acct-c') AND creator_public_key IS DISTINCT FROM $1`, pk))

	assert.Equal(t, 1, count(t, db, `SELECT COUNT(*) FROM users WHERE public_key = $1`, other))
	assert.Equal(t, 1, count(t, db, `SELECT COUNT(*) FROM members WHERE public_key = $1 AND application_id = 'acct-c'`, other))
	assert.Equal(t, 1, count(t, db, `SELECT COUNT(*) FROM events WHERE id = 'acct-other-event'`))
}

func TestDeleteAccount_ShouldReturn500AndKeepUserWhenBlobDeleteFails_Integration(t *testing.T) {
	// given
	db := testdb.Connect(t, "profile")
	defer db.Close()
	repo := application.NewRepository(db)
	events := &mockEventService{}
	ep := NewAccountEndpoints(db, repo, events, &mockBlobDeleter{err: errors.New("boom")})
	const pk = "fail-pk-0123456789abcdefghij"
	testdb.InsertTestUser(t, db, pk)
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue("user", &user.User{PublicKey: pk, Role: user.RoleUser})

	// when
	ep.DeleteAccount(ctx)

	// then
	assert.Equal(t, fasthttp.StatusInternalServerError, ctx.Response.StatusCode())
	assert.Empty(t, events.produced)
	assert.Equal(t, 1, count(t, db, `SELECT COUNT(*) FROM users WHERE public_key = $1`, pk))
}

func TestDeleteAccount_ShouldReturn500AndKeepUserWhenProduceEventFails_Integration(t *testing.T) {
	// given
	db := testdb.Connect(t, "profile")
	defer db.Close()
	repo := application.NewRepository(db)
	const pk, other = "fail-pk-0123456789abcdefghij", "fail-other-pk-0123456789abcdef"
	testdb.InsertTestUser(t, db, pk)
	testdb.InsertTestUser(t, db, other)
	now := time.Now().Unix()
	require.NoError(t, repo.CreateApplication(&application.Application{ID: "fail-a", Name: "fail-a", CreatedAt: now, UpdatedAt: now}))
	require.NoError(t, repo.CreateMember(&application.Member{ID: "fail-m1", ApplicationID: "fail-a", Role: application.MemberRoleMember, PublicKey: pk}))
	ep := NewAccountEndpoints(db, repo, &mockEventService{err: errors.New("boom")}, &mockBlobDeleter{})
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue("user", &user.User{PublicKey: pk, Role: user.RoleUser})

	// when
	ep.DeleteAccount(ctx)

	// then
	assert.Equal(t, fasthttp.StatusInternalServerError, ctx.Response.StatusCode())
	assert.Equal(t, 1, count(t, db, `SELECT COUNT(*) FROM users WHERE public_key = $1`, pk))
	assert.Equal(t, 1, count(t, db, `SELECT COUNT(*) FROM members WHERE id = 'fail-m1'`))
}
