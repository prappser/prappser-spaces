//go:build integration

package internal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"mime/multipart"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/invitation"
	"github.com/prappser/prappser-spaces/internal/storage"
	"github.com/prappser/prappser-spaces/internal/testdb"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

const (
	moveAppID     = "move-app"
	moveOwnerPK   = "move-owner-pk"
	moveMemberPK  = "move-member-pk"
	moveOutsidePK = "move-outside-pk"
	moveTargetURL = "https://b.example"
	moveToken     = "invite-token-on-b"
)

type spyBroadcaster struct {
	mu        sync.Mutex
	appEvents []*event.Event
	userCasts map[string][]*event.Event
}

func (s *spyBroadcaster) BroadcastToApplication(_ string, e *event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appEvents = append(s.appEvents, e)
}

func (s *spyBroadcaster) BroadcastToUser(pk string, e *event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.userCasts[pk] = append(s.userCasts[pk], e)
}

type moveFixture struct {
	t          *testing.T
	db         *sql.DB
	handler    fasthttp.RequestHandler
	tokens     map[string]string
	spy        *spyBroadcaster
	storageDir string
	purger     *storage.StoragePurgeScheduler
}

func newMoveFixture(t *testing.T) *moveFixture {
	t.Helper()
	db := testdb.Connect(t, "move")
	t.Cleanup(func() { db.Close() })

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	spacePK := base64.StdEncoding.EncodeToString(pub)

	userRepo := user.NewUserRepository(db)
	userService := user.NewUserService(userRepo, nil, user.Config{JWTExpirationHours: 24}, priv, pub)
	appRepo := application.NewRepository(db)
	spy := &spyBroadcaster{userCasts: map[string][]*event.Event{}}
	eventService := event.NewEventService(event.NewEventRepository(db), appRepo, spy, nil)

	storageDir := t.TempDir()
	backend, err := storage.NewBackend(&storage.BackendConfig{Type: storage.StorageTypeLocal, LocalPath: storageDir, MaxFileSize: 1 << 20, ChunkSize: 1 << 16})
	require.NoError(t, err)
	storageService := storage.NewService(storage.NewRepository(db), backend, 1<<20, 0)

	invitationService := invitation.NewInvitationService(invitation.NewInvitationRepository(db), priv, pub, appRepo, db, userRepo, eventService, spacePK)

	invitationService.ExternalURL = "http://a.example"

	handler := NewRequestHandler(&Config{TrustProxyHeaders: true}, nil, nil, nil, userService,
		application.NewApplicationEndpoints(application.NewApplicationService(appRepo, 0, spacePK)),
		invitation.NewInvitationEndpoints(invitationService, storageService),
		event.NewEventEndpoints(eventService), nil,
		storage.NewEndpoints(storageService, appRepo, eventService, userRepo, "http://a.example"),
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		application.NewMoveEndpoints(application.NewMoveService(appRepo, eventService, storageService)))

	f := &moveFixture{t: t, db: db, handler: handler, tokens: map[string]string{}, spy: spy, storageDir: storageDir,
		purger: storage.NewStoragePurgeScheduler(appRepo, storageService)}
	for _, pk := range []string{moveOwnerPK, moveMemberPK, moveOutsidePK} {
		testdb.InsertTestUser(t, db, pk)
		require.NoError(t, userRepo.EnsureDevice(pk, pk, nil, time.Now().Unix()))
		u, err := userRepo.GetUserByPublicKey(pk)
		require.NoError(t, err)
		token, _, err := userService.GenerateJWT(u, pk)
		require.NoError(t, err)
		f.tokens[pk] = token
	}
	return f
}

func (f *moveFixture) do(method, path, pk string, body []byte, contentType string) *fasthttp.RequestCtx {
	f.t.Helper()
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(method)
	ctx.Request.SetRequestURI(path)
	ctx.Request.Header.Set("Authorization", "Bearer "+f.tokens[pk])
	if body != nil {
		ctx.Request.SetBody(body)
		ctx.Request.Header.SetContentType(contentType)
	}
	f.handler(ctx)
	return ctx
}

func (f *moveFixture) doJSON(method, path, pk string, body any) *fasthttp.RequestCtx {
	f.t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		require.NoError(f.t, err)
	}
	return f.do(method, path, pk, raw, "application/json")
}

func (f *moveFixture) registerApp(pk string) *fasthttp.RequestCtx {
	f.t.Helper()
	return f.doJSON("POST", "/applications/register", pk, map[string]any{
		"id":   moveAppID,
		"name": "Move me",
		"members": []map[string]any{
			{"id": "m-owner", "role": "owner", "publicKey": moveOwnerPK},
			{"id": "m-member", "role": "member", "publicKey": moveMemberPK},
		},
		"componentGroups": []map[string]any{{
			"id": "group-1", "name": "Group", "index": 0,
			"components": []map[string]any{{"id": "comp-1", "name": "Note", "index": 0, "data": map[string]any{"text": "hi"}}},
		}},
	})
}

func (f *moveFixture) setUp() {
	f.t.Helper()
	require.Equal(f.t, fasthttp.StatusCreated, f.registerApp(moveOwnerPK).Response.StatusCode())
}

func (f *moveFixture) setMemberRole(pk, role string) {
	f.t.Helper()
	_, err := f.db.Exec(`UPDATE members SET role=$1 WHERE public_key=$2 AND application_id=$3`, role, pk, moveAppID)
	require.NoError(f.t, err)
}

func (f *moveFixture) assertMoveForbidden(pk string) {
	f.t.Helper()
	start := f.startMove(pk)
	abort := f.doJSON("DELETE", "/applications/"+moveAppID+"/move", pk, nil)
	complete := f.completeMove(pk)
	assert.Equal(f.t, fasthttp.StatusForbidden, start.Response.StatusCode())
	assert.Equal(f.t, fasthttp.StatusForbidden, abort.Response.StatusCode())
	assert.Equal(f.t, fasthttp.StatusForbidden, complete.Response.StatusCode())
}

func (f *moveFixture) submitEvent(pk, eventType string) *fasthttp.RequestCtx {
	f.t.Helper()
	return f.doJSON("POST", "/events", pk, map[string]any{"event": map[string]any{
		"id":               uuid.NewString(),
		"type":             eventType,
		"creatorPublicKey": pk,
		"createdAt":        time.Now().Unix(),
		"version":          1,
		"data":             map[string]any{"applicationId": moveAppID, "componentId": "comp-1", "componentGroupId": "group-1", "changedFields": map[string]any{}},
	}})
}

func (f *moveFixture) upload(pk, storageID string) *fasthttp.RequestCtx {
	f.t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	require.NoError(f.t, w.WriteField("id", storageID))
	part, err := w.CreateFormFile("file", "note.txt")
	require.NoError(f.t, err)
	_, err = part.Write([]byte("hello"))
	require.NoError(f.t, err)
	require.NoError(f.t, w.Close())
	return f.do("POST", "/storage/upload?applicationId="+moveAppID, pk, body.Bytes(), w.FormDataContentType())
}

func (f *moveFixture) initChunked(pk string) *fasthttp.RequestCtx {
	f.t.Helper()
	return f.doJSON("POST", "/storage/chunks/init?applicationId="+moveAppID, pk, map[string]any{
		"id": uuid.NewString(), "filename": "big.txt", "contentType": "text/plain", "totalSize": 10, "chunkSize": 10, "totalChunks": 1,
	})
}

func (f *moveFixture) createInvite(pk string) *fasthttp.RequestCtx {
	f.t.Helper()
	return f.doJSON("POST", "/applications/"+moveAppID+"/invites", pk, map[string]any{"role": "member"})
}

func (f *moveFixture) startMove(pk string) *fasthttp.RequestCtx {
	f.t.Helper()
	return f.doJSON("POST", "/applications/"+moveAppID+"/move", pk, map[string]any{"targetSpaceUrl": moveTargetURL})
}

func (f *moveFixture) completeMove(pk string) *fasthttp.RequestCtx {
	f.t.Helper()
	return f.doJSON("POST", "/applications/"+moveAppID+"/move/complete", pk, map[string]any{"targetSpaceUrl": moveTargetURL, "inviteToken": moveToken})
}

func (f *moveFixture) count(query string) int {
	f.t.Helper()
	var n int
	require.NoError(f.t, f.db.QueryRow(query, moveAppID).Scan(&n))
	return n
}

func responseBody(t *testing.T, ctx *fasthttp.RequestCtx) map[string]any {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &body), string(ctx.Response.Body()))
	return body
}

func assertCode(t *testing.T, ctx *fasthttp.RequestCtx, status int, code string) {
	t.Helper()
	assert.Equal(t, status, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	if ctx.Response.StatusCode() == status {
		assert.Equal(t, code, responseBody(t, ctx)["code"])
	}
}

func assertMoved(t *testing.T, ctx *fasthttp.RequestCtx) {
	t.Helper()
	assert.Equal(t, fasthttp.StatusGone, ctx.Response.StatusCode(), string(ctx.Response.Body()))
	if ctx.Response.StatusCode() != fasthttp.StatusGone {
		return
	}
	body := responseBody(t, ctx)
	assert.Equal(t, "application_moved", body["code"])
	assert.Equal(t, moveTargetURL, body["targetSpaceUrl"])
	assert.Equal(t, moveToken, body["inviteToken"])
}

func TestMove_ShouldRejectWritesWhileMoving(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUp()

	// when
	start := f.startMove(moveOwnerPK)

	// then
	assert.Equal(t, fasthttp.StatusOK, start.Response.StatusCode(), string(start.Response.Body()))
	assertCode(t, f.submitEvent(moveMemberPK, "component_data_changed"), fasthttp.StatusConflict, "application_moving")
	assertCode(t, f.upload(moveMemberPK, uuid.NewString()), fasthttp.StatusConflict, "application_moving")
	assertCode(t, f.initChunked(moveMemberPK), fasthttp.StatusConflict, "application_moving")
	assertCode(t, f.createInvite(moveOwnerPK), fasthttp.StatusConflict, "application_moving")
	assertCode(t, f.doJSON("DELETE", "/applications/"+moveAppID, moveOwnerPK, nil), fasthttp.StatusConflict, "application_moving")
	assert.Equal(t, fasthttp.StatusOK, f.doJSON("GET", "/applications/"+moveAppID, moveMemberPK, nil).Response.StatusCode())
	assert.Equal(t, fasthttp.StatusOK, f.doJSON("GET", "/applications/"+moveAppID+"/state", moveMemberPK, nil).Response.StatusCode())
}

func TestMove_ShouldBeIdempotent(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUp()
	require.Equal(t, fasthttp.StatusOK, f.startMove(moveOwnerPK).Response.StatusCode())

	// when
	again := f.startMove(moveOwnerPK)

	// then
	assert.Equal(t, fasthttp.StatusOK, again.Response.StatusCode(), string(again.Response.Body()))
}

func TestMove_ShouldRestoreWritesAfterAbort(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUp()
	require.Equal(t, fasthttp.StatusOK, f.startMove(moveOwnerPK).Response.StatusCode())

	// when
	abort := f.doJSON("DELETE", "/applications/"+moveAppID+"/move", moveOwnerPK, nil)

	// then
	assert.Equal(t, fasthttp.StatusOK, abort.Response.StatusCode(), string(abort.Response.Body()))
	assert.Equal(t, fasthttp.StatusOK, f.submitEvent(moveMemberPK, "component_data_changed").Response.StatusCode())
	assert.Equal(t, fasthttp.StatusCreated, f.upload(moveMemberPK, uuid.NewString()).Response.StatusCode())
	assert.Equal(t, fasthttp.StatusCreated, f.createInvite(moveOwnerPK).Response.StatusCode())
}

func TestMoveEndpoints_ShouldReturn403ForNonOwner(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUp()

	// when / then
	f.assertMoveForbidden(moveMemberPK)
}

func TestMoveEndpoints_ShouldReturn403ForAdmin(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUp()
	f.setMemberRole(moveMemberPK, "admin")

	// when / then
	f.assertMoveForbidden(moveMemberPK)
}

func TestCompleteMove_ShouldReturn409WhenNotMoving(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUp()

	// when
	complete := f.completeMove(moveOwnerPK)

	// then
	assertCode(t, complete, fasthttp.StatusConflict, "application_not_moving")
}

func TestCompleteMove_ShouldNotifyMembersPurgeAndAnswer410(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUp()
	require.Equal(t, fasthttp.StatusOK, f.submitEvent(moveMemberPK, "component_data_changed").Response.StatusCode())
	require.Equal(t, fasthttp.StatusCreated, f.upload(moveMemberPK, "file-1").Response.StatusCode())
	require.Equal(t, fasthttp.StatusCreated, f.createInvite(moveOwnerPK).Response.StatusCode())
	var blobPath string
	require.NoError(t, f.db.QueryRow(`SELECT storage_path FROM storage WHERE id = 'file-1'`).Scan(&blobPath))
	_, err := os.Stat(filepath.Join(f.storageDir, blobPath))
	require.NoError(t, err)
	require.Equal(t, fasthttp.StatusOK, f.startMove(moveOwnerPK).Response.StatusCode())

	// when
	complete := f.completeMove(moveOwnerPK)

	// then
	require.Equal(t, fasthttp.StatusOK, complete.Response.StatusCode(), string(complete.Response.Body()))

	f.spy.mu.Lock()
	require.NotEmpty(t, f.spy.appEvents)
	moved := f.spy.appEvents[len(f.spy.appEvents)-1]
	memberCasts := f.spy.userCasts[moveMemberPK]
	f.spy.mu.Unlock()
	assert.Equal(t, event.EventType("application_moved"), moved.Type)
	assert.Equal(t, moveAppID, moved.Data["applicationId"])
	assert.Equal(t, moveTargetURL, moved.Data["targetSpaceUrl"])
	assert.Equal(t, moveToken, moved.Data["inviteToken"])
	require.NotEmpty(t, memberCasts)
	assert.Equal(t, moved.ID, memberCasts[len(memberCasts)-1].ID)

	polled := responseBody(t, f.doJSON("GET", "/events", moveMemberPK, nil))
	polledEvents, _ := polled["events"].([]any)
	require.Len(t, polledEvents, 1)
	assert.Equal(t, "application_moved", polledEvents[0].(map[string]any)["type"])

	assert.Equal(t, 1, f.count(`SELECT COUNT(*) FROM events WHERE application_id = $1`))
	assert.Equal(t, 0, f.count(`SELECT COUNT(*) FROM components WHERE application_id = $1`))
	assert.Equal(t, 0, f.count(`SELECT COUNT(*) FROM component_groups WHERE application_id = $1`))
	assert.Equal(t, 0, f.count(`SELECT COUNT(*) FROM invitations WHERE application_id = $1`))
	assert.Equal(t, 0, f.count(`SELECT COUNT(*) FROM storage WHERE application_id = $1`))
	_, err = os.Stat(filepath.Join(f.storageDir, blobPath))
	assert.True(t, os.IsNotExist(err))

	assertMoved(t, f.doJSON("GET", "/applications/"+moveAppID, moveMemberPK, nil))
	assertMoved(t, f.doJSON("GET", "/applications/"+moveAppID+"/state", moveMemberPK, nil))
	assertMoved(t, f.submitEvent(moveMemberPK, "component_data_changed"))
	assertMoved(t, f.upload(moveMemberPK, uuid.NewString()))
	assertMoved(t, f.createInvite(moveOwnerPK))
	assertMoved(t, f.completeMove(moveOwnerPK))
	assert.Equal(t, fasthttp.StatusNotFound, f.doJSON("GET", "/applications/"+moveAppID, moveOutsidePK, nil).Response.StatusCode())
}

func TestCompleteMove_ShouldHardDeleteTombstoneAfter30Days(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUp()
	require.Equal(t, fasthttp.StatusOK, f.startMove(moveOwnerPK).Response.StatusCode())
	require.Equal(t, fasthttp.StatusOK, f.completeMove(moveOwnerPK).Response.StatusCode())
	_, err := f.db.Exec(`UPDATE applications SET deleted_at = $1 WHERE id = $2`, time.Now().Add(-31*24*time.Hour).Unix(), moveAppID)
	require.NoError(t, err)

	// when
	f.purger.PurgeDeletedApps(context.Background())

	// then
	assert.Equal(t, 0, f.count(`SELECT COUNT(*) FROM applications WHERE id = $1`))
	assert.Equal(t, 0, f.count(`SELECT COUNT(*) FROM members WHERE application_id = $1`))
}

func TestSubmitEvent_ShouldRejectClientApplicationMoved(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUp()

	// when
	ctx := f.doJSON("POST", "/events", moveOwnerPK, map[string]any{"event": map[string]any{
		"id": uuid.NewString(), "type": "application_moved", "creatorPublicKey": moveOwnerPK, "version": 1,
		"data": map[string]any{"applicationId": moveAppID, "targetSpaceUrl": moveTargetURL, "inviteToken": moveToken},
	}})

	// then
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode(), string(ctx.Response.Body()))
}

func TestRegisterApplication_ShouldSucceedOnRetryBySameOwner(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUp()

	// when
	retry := f.registerApp(moveOwnerPK)

	// then
	assert.Equal(t, fasthttp.StatusCreated, retry.Response.StatusCode(), string(retry.Response.Body()))
	assert.Equal(t, 2, f.count(`SELECT COUNT(*) FROM members WHERE application_id = $1`))
	assert.Equal(t, 1, f.count(`SELECT COUNT(*) FROM components WHERE application_id = $1`))
}

func TestRegisterApplication_ShouldReviveMovedAppForMoveBack(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUp()
	require.Equal(t, fasthttp.StatusOK, f.startMove(moveOwnerPK).Response.StatusCode())
	require.Equal(t, fasthttp.StatusOK, f.completeMove(moveOwnerPK).Response.StatusCode())

	// when
	again := f.registerApp(moveOwnerPK)

	// then
	assert.Equal(t, fasthttp.StatusCreated, again.Response.StatusCode(), string(again.Response.Body()))
	assert.Equal(t, fasthttp.StatusOK, f.doJSON("GET", "/applications/"+moveAppID, moveMemberPK, nil).Response.StatusCode())
	assert.Equal(t, fasthttp.StatusOK, f.submitEvent(moveMemberPK, "component_data_changed").Response.StatusCode())
}

func TestRegisterApplication_ShouldReturn409WhileMoving(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUp()
	require.Equal(t, fasthttp.StatusOK, f.startMove(moveOwnerPK).Response.StatusCode())

	// when
	register := f.registerApp(moveOwnerPK)

	// then
	assertCode(t, register, fasthttp.StatusConflict, "application_moving")
	assertCode(t, f.submitEvent(moveMemberPK, "component_data_changed"), fasthttp.StatusConflict, "application_moving")
}

func TestLeaveApplication_ShouldReturn410AfterMove(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUp()
	require.Equal(t, fasthttp.StatusOK, f.startMove(moveOwnerPK).Response.StatusCode())
	require.Equal(t, fasthttp.StatusOK, f.completeMove(moveOwnerPK).Response.StatusCode())

	// when
	leave := f.doJSON("DELETE", "/applications/"+moveAppID+"/members/me", moveMemberPK, nil)

	// then
	assertMoved(t, leave)
}

func TestStartMove_ShouldReturn400ForNonHTTPURL(t *testing.T) {
	// given
	f := newMoveFixture(t)
	f.setUp()

	// when
	start := f.doJSON("POST", "/applications/"+moveAppID+"/move", moveOwnerPK, map[string]any{"targetSpaceUrl": "javascript:alert(1)"})

	// then
	assert.Equal(t, fasthttp.StatusBadRequest, start.Response.StatusCode(), string(start.Response.Body()))
}
