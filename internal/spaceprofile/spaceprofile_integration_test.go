//go:build integration

package spaceprofile

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/storage"
	"github.com/prappser/prappser-spaces/internal/testdb"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

const ownerKey = "owner-pk"

func newProfileDB(t *testing.T) *sql.DB {
	t.Helper()
	db := testdb.Connect(t, "spaceprofile")
	t.Cleanup(func() { db.Close() })
	exec(t, db, `DELETE FROM space_profile`)
	exec(t, db, `DELETE FROM storage`)
	exec(t, db, `DELETE FROM applications`)
	return db
}

type recordedEvents struct{ produced []*event.Event }

func (r *recordedEvents) ProduceEvent(_ context.Context, e *event.Event) (*event.Event, error) {
	r.produced = append(r.produced, e)
	return e, nil
}

func exec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	_, err := db.Exec(query, args...)
	require.NoError(t, err)
}

func seedFile(t *testing.T, db *sql.DB, id, uploader, contentType, status string, appID *string) {
	t.Helper()
	if appID != nil {
		exec(t, db, `INSERT INTO applications (id, name, created_at, updated_at) VALUES ($1, $1, 1, 1) ON CONFLICT DO NOTHING`, *appID)
	}
	exec(t, db, `INSERT INTO storage (id, application_id, uploader_public_key, filename, content_type, size_bytes, storage_path, checksum, created_at, status)
		VALUES ($1, $2, $3, 'f', $4, 1, 'p', 'c', 1, $5)`, id, appID, uploader, contentType, status)
}

func putProfile(t *testing.T, db *sql.DB, role, body string) *fasthttp.RequestCtx {
	t.Helper()
	return putProfileRecording(t, db, role, body, &recordedEvents{})
}

func putProfileRecording(t *testing.T, db *sql.DB, role, body string, events *recordedEvents) *fasthttp.RequestCtx {
	t.Helper()
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod("PUT")
	ctx.Request.SetBodyString(body)
	ctx.SetUserValue("user", &user.User{PublicKey: ownerKey, Role: role})
	NewSpaceProfileEndpoints(NewRepository(db), storage.NewRepository(db), events).UpdateProfile(ctx)
	return ctx
}

func TestGet_ShouldReturnEmptyProfileWhenNeverSet(t *testing.T) {
	// given
	db := newProfileDB(t)

	// when
	p, err := NewRepository(db).Get()

	// then
	require.NoError(t, err)
	assert.Equal(t, Profile{}, p)
}

func TestUpdateProfile_ShouldSaveTrimmedNameAndOwnImage(t *testing.T) {
	// given
	db := newProfileDB(t)
	seedFile(t, db, "img", ownerKey, "image/png", "ready", nil)

	// when
	ctx := putProfile(t, db, user.RoleOwner, `{"name":"  Family  ","avatarStorageId":"img"}`)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	var resp Profile
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	assert.Equal(t, "Family", resp.Name)
	saved, err := NewRepository(db).Get()
	require.NoError(t, err)
	assert.Equal(t, "Family", saved.Name)
	assert.Equal(t, "img", *saved.AvatarStorageID)
	assert.NotZero(t, saved.UpdatedAt)
}

func TestUpdateProfile_ShouldClearNameAndImage(t *testing.T) {
	// given
	db := newProfileDB(t)
	seedFile(t, db, "img", ownerKey, "image/png", "ready", nil)
	putProfile(t, db, user.RoleOwner, `{"name":"Family","avatarStorageId":"img"}`)

	// when
	ctx := putProfile(t, db, user.RoleOwner, `{"name":"","avatarStorageId":null}`)

	// then
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	saved, err := NewRepository(db).Get()
	require.NoError(t, err)
	assert.Equal(t, "", saved.Name)
	assert.Nil(t, saved.AvatarStorageID)
}

func TestUpdateProfile_ShouldRejectNonOwner(t *testing.T) {
	// given
	db := newProfileDB(t)

	// when
	ctx := putProfile(t, db, user.RoleUser, `{"name":"Mine now"}`)

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	saved, err := NewRepository(db).Get()
	require.NoError(t, err)
	assert.Equal(t, "", saved.Name)
}

func TestUpdateProfile_ShouldRejectTooLongName(t *testing.T) {
	// given
	db := newProfileDB(t)

	// when
	ctx := putProfile(t, db, user.RoleOwner, `{"name":"`+strings.Repeat("x", 65)+`"}`)

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode())
}

func TestUpdateProfile_ShouldRejectUnusableImages(t *testing.T) {
	// given
	db := newProfileDB(t)
	app := "app-1"
	seedFile(t, db, "someone-elses", "other-pk", "image/png", "ready", nil)
	seedFile(t, db, "app-file", ownerKey, "image/png", "ready", &app)
	seedFile(t, db, "not-image", ownerKey, "application/pdf", "ready", nil)
	seedFile(t, db, "pending", ownerKey, "image/png", "pending", nil)

	for _, id := range []string{"someone-elses", "app-file", "not-image", "pending", "missing"} {
		// when
		ctx := putProfile(t, db, user.RoleOwner, `{"name":"Family","avatarStorageId":"`+id+`"}`)

		// then
		assert.Equal(t, fasthttp.StatusBadRequest, ctx.Response.StatusCode(), id)
	}
	saved, err := NewRepository(db).Get()
	require.NoError(t, err)
	assert.Nil(t, saved.AvatarStorageID)
}

func TestUpdateProfile_ShouldAnnounceTheChangeToEveryLiveApp(t *testing.T) {
	// given
	db := newProfileDB(t)
	exec(t, db, `INSERT INTO applications (id, name, created_at, updated_at) VALUES ('trip', 'trip', 1, 1), ('chores', 'chores', 1, 1)`)
	exec(t, db, `INSERT INTO applications (id, name, created_at, updated_at, deleted_at) VALUES ('gone', 'gone', 1, 1, 5)`)
	events := &recordedEvents{}

	// when
	putProfileRecording(t, db, user.RoleOwner, `{"name":"Family"}`, events)

	// then
	var apps []string
	for _, e := range events.produced {
		assert.Equal(t, event.EventTypeSpaceProfileChanged, e.Type)
		assert.Equal(t, e.ApplicationID, e.Data["applicationId"])
		apps = append(apps, e.ApplicationID)
	}
	assert.ElementsMatch(t, []string{"trip", "chores"}, apps)
}

func TestUpdateProfile_ShouldNotAnnounceARejectedChange(t *testing.T) {
	// given
	db := newProfileDB(t)
	exec(t, db, `INSERT INTO applications (id, name, created_at, updated_at) VALUES ('trip', 'trip', 1, 1)`)
	events := &recordedEvents{}

	// when
	putProfileRecording(t, db, user.RoleUser, `{"name":"Mine now"}`, events)

	// then
	assert.Empty(t, events.produced)
}
