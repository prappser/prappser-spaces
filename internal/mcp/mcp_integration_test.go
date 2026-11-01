//go:build integration

package mcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/component"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/invitation"
	"github.com/prappser/prappser-spaces/internal/testdb"
	"github.com/prappser/prappser-spaces/internal/user"
)

type recordingBroadcaster struct {
	mu   sync.Mutex
	apps []string
}

func (b *recordingBroadcaster) BroadcastToApplication(appID string, _ *event.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.apps = append(b.apps, appID)
}
func (b *recordingBroadcaster) BroadcastToUser(string, *event.Event) {}

func (b *recordingBroadcaster) saw(appID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, a := range b.apps {
		if a == appID {
			return true
		}
	}
	return false
}

type env struct {
	t        *testing.T
	db       *sql.DB
	base     string
	apps     *application.ApplicationService
	agents   *user.AgentService
	userRepo user.UserRepository
	bc       *recordingBroadcaster
	events   *event.EventService
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db := testdb.Connect(t, "mcp")
	t.Cleanup(func() { db.Close() })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	base := "http://" + ln.Addr().String()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	appRepo := application.NewRepository(db)
	userRepo := user.NewUserRepository(db)
	bc := &recordingBroadcaster{}
	events := event.NewEventService(event.NewEventRepository(db), appRepo, bc, nil)
	invites := invitation.NewInvitationService(invitation.NewInvitationRepository(db), priv, pub, appRepo, db, userRepo, events, "space-key")
	invites.ExternalURL = "https://prappser.app"
	agents := user.NewAgentService(db, userRepo, priv, pub, base)
	apps := application.NewApplicationService(appRepo, 0, "space-key")

	validator, err := component.NewValidator()
	require.NoError(t, err)

	next := func(ctx *fasthttp.RequestCtx) { ctx.Error("fallthrough", fasthttp.StatusNotFound) }
	srv := &fasthttp.Server{Handler: Mount(next, Deps{Apps: apps, Invitations: invites, Events: events, Agents: agents, Validator: validator, ExternalURL: base})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Shutdown() })
	return &env{t: t, db: db, base: base, apps: apps, agents: agents, userRepo: userRepo, bc: bc, events: events}
}

func (e *env) account() *user.User {
	key := "mcp-" + uuid.NewString()
	testdb.InsertTestUser(e.t, e.db, key)
	return &user.User{PublicKey: key, Role: user.RoleUser}
}

func (e *env) app(owner *user.User, chats int, members ...*user.User) string {
	appID := uuid.NewString()
	app := &application.Application{
		ID:      appID,
		Name:    "Trip",
		Members: []application.Member{{ID: appID + "-o", Role: application.MemberRoleOwner, PublicKey: owner.PublicKey}},
	}
	for i, m := range members {
		app.Members = append(app.Members, application.Member{ID: appID + "-m" + string(rune('a'+i)), Role: application.MemberRoleMember, PublicKey: m.PublicKey})
	}
	group := application.ComponentGroup{ID: appID + "-g", Name: "Main", Components: []application.Component{{ID: appID + "-notes", Name: "Notes"}}}
	for i := 0; i < chats; i++ {
		group.Components = append(group.Components, application.Component{ID: appID + "-chat" + string(rune('a'+i)), Name: "Chat"})
	}
	app.ComponentGroups = []application.ComponentGroup{group}
	_, err := e.apps.RegisterApplication(owner, app)
	require.NoError(e.t, err)
	return appID
}

func (e *env) makeAdmin(appID string, u *user.User) {
	e.t.Helper()
	_, err := e.db.Exec(`UPDATE members SET role = $1 WHERE application_id = $2 AND public_key = $3`, string(application.MemberRoleAdmin), appID, u.PublicKey)
	require.NoError(e.t, err)
}

func (e *env) checklistApp(owner *user.User, checklists int, data map[string]any, members ...*user.User) string {
	e.t.Helper()
	appID := e.app(owner, 0, members...)
	_, err := e.db.Exec(`DELETE FROM components WHERE application_id = $1`, appID)
	require.NoError(e.t, err)
	for i := 0; i < checklists; i++ {
		raw, _ := json.Marshal(data)
		_, err = e.db.Exec(`INSERT INTO components (id, component_group_id, application_id, name, data, index_order) VALUES ($1, $2, $3, 'Checklist', $4, $5)`,
			appID+"-list"+string(rune('a'+i)), appID+"-g", appID, string(raw), i)
		require.NoError(e.t, err)
	}
	return appID
}

func (e *env) listData(appID string) map[string]any {
	e.t.Helper()
	var raw string
	require.NoError(e.t, e.db.QueryRow(`SELECT data FROM components WHERE id = $1`, appID+"-lista").Scan(&raw))
	var out map[string]any
	require.NoError(e.t, json.Unmarshal([]byte(raw), &out))
	return out
}

type bearer string

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+string(b))
	return http.DefaultTransport.RoundTrip(r)
}

func (e *env) connect(u *user.User) (*sdk.ClientSession, *user.AgentTokens) {
	tokens, err := e.agents.IssueTokens(u.PublicKey, "test")
	require.NoError(e.t, err)
	client := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(context.Background(), &sdk.StreamableClientTransport{
		Endpoint:   e.base + "/mcp",
		HTTPClient: &http.Client{Transport: bearer(tokens.AccessToken)},
	}, nil)
	require.NoError(e.t, err)
	e.t.Cleanup(func() { session.Close() })
	return session, tokens
}

func call(t *testing.T, s *sdk.ClientSession, tool string, args map[string]any) (*sdk.CallToolResult, map[string]any) {
	t.Helper()
	res, err := s.CallTool(context.Background(), &sdk.CallToolParams{Name: tool, Arguments: args})
	require.NoError(t, err)
	var out map[string]any
	if len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*sdk.TextContent); ok {
			_ = json.Unmarshal([]byte(tc.Text), &out)
		}
	}
	return res, out
}

func errText(res *sdk.CallToolResult) string {
	return res.Content[0].(*sdk.TextContent).Text
}

func TestMCP_ListAndGetApp_ShouldWrapMemberTextAsUntrusted(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID := e.app(owner, 1)
	session, _ := e.connect(owner)

	// when
	_, list := call(t, session, "list_apps", nil)
	_, get := call(t, session, "get_app", map[string]any{"appId": appID})

	// then
	assert.Equal(t, untrustedNote, list["note"])
	listed := list["apps"].([]any)[0].(map[string]any)
	assert.Equal(t, appID, listed["id"])
	assert.Equal(t, "owner", listed["role"])
	assert.Equal(t, "Trip", listed["untrusted"].(map[string]any)["name"])
	assert.Equal(t, untrustedNote, get["note"])
	content := get["untrusted"].(map[string]any)
	assert.Equal(t, "Trip", content["name"])
	assert.Len(t, content["componentGroups"], 1)
	assert.NotContains(t, get, "name")
	assert.NotContains(t, toJSON(get), "ublicKey")
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestMCP_PostChatMessage_ShouldPersistAsCallerAndBroadcast(t *testing.T) {
	// given
	e := newEnv(t)
	owner, member := e.account(), e.account()
	appID := e.app(owner, 1, member)
	session, _ := e.connect(member)

	// when
	res, out := call(t, session, "post_chat_message", map[string]any{"appId": appID, "text": "  hello team  "})

	// then
	require.False(t, res.IsError, toJSON(out))
	key := out["messageId"].(string)
	assert.True(t, strings.HasPrefix(key, "m_"))
	var count int
	require.NoError(t, e.db.QueryRow(`SELECT COUNT(*) FROM events WHERE application_id = $1 AND id = $2 AND creator_public_key = $3`, appID, out["eventId"], member.PublicKey).Scan(&count))
	assert.Equal(t, 1, count)
	var data string
	require.NoError(t, e.db.QueryRow(`SELECT data FROM components WHERE id = $1`, appID+"-chata").Scan(&data))
	var comp map[string]any
	require.NoError(t, json.Unmarshal([]byte(data), &comp))
	var msg map[string]any
	require.NoError(t, json.Unmarshal([]byte(comp[key].(string)), &msg))
	assert.Equal(t, member.PublicKey, msg["sender"])
	assert.Equal(t, "hello team", msg["body"])
	assert.True(t, e.bc.saw(appID))
}

func TestMCP_PostChatMessage_ShouldListChatsWhenSeveralAndNoComponentID(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID := e.app(owner, 2)
	session, _ := e.connect(owner)

	// when
	res, out := call(t, session, "post_chat_message", map[string]any{"appId": appID, "text": "hi"})

	// then
	assert.True(t, res.IsError)
	assert.Equal(t, untrustedNote, out["note"])
	assert.Len(t, out["untrusted"].(map[string]any)["chats"], 2)
	assert.Contains(t, toJSON(out), appID+"-chata")
	assert.Contains(t, toJSON(out), appID+"-chatb")
}

func TestMCP_PostChatMessage_ShouldFailWhenChatIsOff(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID := e.app(owner, 0)
	session, _ := e.connect(owner)

	// when
	res, _ := call(t, session, "post_chat_message", map[string]any{"appId": appID, "text": "hi"})

	// then
	assert.True(t, res.IsError)
	assert.Contains(t, errText(res), "chat is off for this app")
}

func TestMCP_CreateInvite_ShouldReturnJoinURL(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID := e.app(owner, 0)
	session, _ := e.connect(owner)

	// when
	res, out := call(t, session, "create_invite", map[string]any{"appId": appID, "role": "viewer", "expiresInHours": 2})

	// then
	require.False(t, res.IsError, toJSON(out))
	assert.True(t, strings.HasPrefix(out["url"].(string), "https://prappser.app/join?token="))
	assert.NotEmpty(t, out["expiresAt"])
}

func TestMCP_CreateInvite_ShouldRejectPlainMember(t *testing.T) {
	// given
	e := newEnv(t)
	owner, member := e.account(), e.account()
	appID := e.app(owner, 0, member)
	session, _ := e.connect(member)

	// when
	res, _ := call(t, session, "create_invite", map[string]any{"appId": appID})

	// then
	assert.True(t, res.IsError)
	assert.Contains(t, errText(res), "only the app owner or an admin can invite")
}

func TestMCP_AgentReadOff_ShouldHideAppFromMemberAgentButNotOwnerAgent(t *testing.T) {
	// given
	e := newEnv(t)
	owner, member := e.account(), e.account()
	appID := e.app(owner, 1, member)
	require.NoError(t, e.apps.SetAgentRead(appID, owner, false))
	memberSession, _ := e.connect(member)
	ownerSession, _ := e.connect(owner)

	// when
	_, memberList := call(t, memberSession, "list_apps", nil)
	getRes, _ := call(t, memberSession, "get_app", map[string]any{"appId": appID})
	postRes, _ := call(t, memberSession, "post_chat_message", map[string]any{"appId": appID, "text": "hi"})
	_, ownerList := call(t, ownerSession, "list_apps", nil)

	// then
	assert.Empty(t, memberList["apps"])
	assert.True(t, getRes.IsError)
	assert.Contains(t, errText(getRes), "app not found or not open to agents")
	assert.True(t, postRes.IsError)
	assert.Len(t, ownerList["apps"], 1)
}

func TestMCP_AgentReadOff_ShouldDenyAdminAgentInviteAndAnswerLikeMissingApp(t *testing.T) {
	// given
	e := newEnv(t)
	owner, admin := e.account(), e.account()
	appID := e.app(owner, 0, admin)
	e.makeAdmin(appID, admin)
	require.NoError(t, e.apps.SetAgentRead(appID, owner, false))
	session, _ := e.connect(admin)

	// when
	closed, _ := call(t, session, "create_invite", map[string]any{"appId": appID})
	missing, _ := call(t, session, "create_invite", map[string]any{"appId": uuid.NewString()})

	// then
	assert.True(t, closed.IsError)
	assert.Equal(t, "app not found or not open to agents", errText(closed))
	assert.Equal(t, errText(closed), errText(missing))
}

func TestMCP_CreateInvite_ShouldAnswerNonMemberAgentLikeMissingApp(t *testing.T) {
	// given
	e := newEnv(t)
	owner, stranger := e.account(), e.account()
	appID := e.app(owner, 0)
	session, _ := e.connect(stranger)

	// when
	notMember, _ := call(t, session, "create_invite", map[string]any{"appId": appID})
	missing, _ := call(t, session, "create_invite", map[string]any{"appId": uuid.NewString()})

	// then
	assert.True(t, notMember.IsError)
	assert.Equal(t, "app not found or not open to agents", errText(notMember))
	assert.Equal(t, errText(missing), errText(notMember))
}

func TestMCP_AgentReadOff_ShouldLetOwnerAgentPostChat(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID := e.app(owner, 1)
	require.NoError(t, e.apps.SetAgentRead(appID, owner, false))
	session, _ := e.connect(owner)

	// when
	res, out := call(t, session, "post_chat_message", map[string]any{"appId": appID, "text": "hi"})

	// then
	require.False(t, res.IsError, toJSON(out))
	assert.NotEmpty(t, out["messageId"])
}

func TestMCP_GetApp_ShouldReturnChatMessagesUnderUntrusted(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID := e.app(owner, 1)
	session, _ := e.connect(owner)
	call(t, session, "post_chat_message", map[string]any{"appId": appID, "text": "hello team"})

	// when
	_, get := call(t, session, "get_app", map[string]any{"appId": appID})

	// then
	assert.NotContains(t, get, "componentGroups")
	untrusted := get["untrusted"].(map[string]any)
	assert.Contains(t, toJSON(untrusted["componentGroups"]), "hello team")
	assert.Contains(t, toJSON(untrusted["componentGroups"]), owner.PublicKey)
}

func rawPost(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestMCP_RevokedOrMissingToken_ShouldGet401WithMetadataPointer(t *testing.T) {
	// given
	e := newEnv(t)
	u := e.account()
	tokens, err := e.agents.IssueTokens(u.PublicKey, "test")
	require.NoError(t, err)
	require.NoError(t, e.userRepo.RevokeDevice(tokens.DevicePublicKey, time.Now().Unix()))

	// when
	revoked := rawPost(t, e.base+"/mcp", tokens.AccessToken)
	missing := rawPost(t, e.base+"/mcp", "")

	// then
	for _, resp := range []*http.Response{revoked, missing} {
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		header := resp.Header.Get("WWW-Authenticate")
		assert.Contains(t, header, `resource_metadata="`+e.base+`/.well-known/oauth-protected-resource/mcp"`)
		assert.Contains(t, header, `scope="mcp"`)
	}
}

func TestMCP_ProtectedResourceMetadata_ShouldPointAtTheSpace(t *testing.T) {
	// given
	e := newEnv(t)

	// when
	resp, err := http.Get(e.base + "/.well-known/oauth-protected-resource/mcp")
	require.NoError(t, err)
	defer resp.Body.Close()

	// then
	var meta map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))
	assert.Equal(t, e.base+"/mcp", meta["resource"])
	assert.Equal(t, []any{e.base}, meta["authorization_servers"])
}

func TestMCP_ToolCalls_ShouldNotUpdateLastSeen(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID := e.app(owner, 1)
	session, tokens := e.connect(owner)
	row := func() string {
		var s string
		require.NoError(t, e.db.QueryRow(`SELECT to_jsonb(u)::text FROM users u WHERE public_key = $1`, owner.PublicKey).Scan(&s))
		return s
	}
	before := row()

	// when
	call(t, session, "list_apps", nil)
	call(t, session, "post_chat_message", map[string]any{"appId": appID, "text": "hi"})

	// then
	var lastSeen sql.NullInt64
	require.NoError(t, e.db.QueryRow(`SELECT last_seen_at FROM user_devices WHERE device_public_key = $1`, tokens.DevicePublicKey).Scan(&lastSeen))
	assert.False(t, lastSeen.Valid)
	assert.Equal(t, before, row())
}

func TestMCP_OtherPaths_ShouldFallThrough(t *testing.T) {
	// given
	e := newEnv(t)

	// when
	resp, err := http.Get(e.base + "/health")
	require.NoError(t, err)
	defer resp.Body.Close()
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(resp.Body)

	// then
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Contains(t, body.String(), "fallthrough")
}

func TestMCP_AddChecklistItem_ShouldWriteOnlyTheNewKeyAndBroadcast(t *testing.T) {
	// given
	e := newEnv(t)
	owner, friend := e.account(), e.account()
	appID := e.checklistApp(owner, 1, map[string]any{"title": "Packing", "item_f": map[string]any{"title": "friend", "checked": false, "order": 4.5}}, friend)
	session, _ := e.connect(owner)
	friendItem := map[string]any{"title": "friend edit", "checked": true, "order": 4.5}
	ev := event.Event{ID: uuid.NewString(), Type: event.EventTypeComponentDataChanged, Version: 1, CreatedAt: time.Now().UnixMilli(), Data: map[string]interface{}{
		"version": float64(1), "applicationId": appID, "componentId": appID + "-lista", "componentGroupId": appID + "-g",
		"changedFields": map[string]interface{}{"item_f": map[string]interface{}{"oldValue": nil, "newValue": friendItem}},
	}}
	_, err := e.events.AcceptEvent(context.Background(), &ev, friend)
	require.NoError(t, err)

	// when
	res, out := call(t, session, "add_checklist_item", map[string]any{"appId": appID, "title": "  sunscreen "})

	// then
	require.False(t, res.IsError, toJSON(out))
	key := "item_" + out["itemId"].(string)
	data := e.listData(appID)
	assert.Equal(t, map[string]any{"title": "sunscreen", "checked": false, "order": 5.5}, data[key])
	assert.Equal(t, friendItem, data["item_f"])
	assert.Equal(t, "Packing", data["title"])
	assert.Len(t, data, 3)
	assert.True(t, e.bc.saw(appID))
}

func TestMCP_UpdateChecklistItem_ShouldWriteLegacyItemUnderItsOwnKey(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	legacy := []any{map[string]any{"id": "a", "title": "x", "checked": false}}
	appID := e.checklistApp(owner, 1, map[string]any{"items": legacy})
	session, _ := e.connect(owner)

	// when
	res, out := call(t, session, "update_checklist_item", map[string]any{"appId": appID, "itemId": "a", "checked": true})

	// then
	require.False(t, res.IsError, toJSON(out))
	data := e.listData(appID)
	assert.Equal(t, map[string]any{"title": "x", "checked": true, "order": 0.0}, data["item_a"])
	assert.Equal(t, legacy, data["items"])
}

func TestMCP_UpdateChecklistItem_ShouldRenameKeyedItemAndRejectUnknownOrDeleted(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID := e.checklistApp(owner, 1, map[string]any{
		"item_a": map[string]any{"title": "old", "checked": true, "order": 1.0},
		"item_d": "",
	})
	session, _ := e.connect(owner)

	// when
	ok, okOut := call(t, session, "update_checklist_item", map[string]any{"appId": appID, "itemId": "a", "title": "new"})
	unknown, _ := call(t, session, "update_checklist_item", map[string]any{"appId": appID, "itemId": "zzz", "title": "n"})
	deleted, _ := call(t, session, "update_checklist_item", map[string]any{"appId": appID, "itemId": "d", "checked": true})
	empty, _ := call(t, session, "update_checklist_item", map[string]any{"appId": appID, "itemId": "a"})

	// then
	require.False(t, ok.IsError, toJSON(okOut))
	assert.Equal(t, map[string]any{"title": "new", "checked": true, "order": 1.0}, e.listData(appID)["item_a"])
	assert.Contains(t, errText(unknown), "item not found")
	assert.Contains(t, errText(deleted), "item not found")
	assert.True(t, empty.IsError)
}

func TestMCP_ChecklistTools_ShouldEnforceRolesAndUsageFlags(t *testing.T) {
	// given
	e := newEnv(t)
	owner, member, viewer, admin := e.account(), e.account(), e.account(), e.account()
	appID := e.checklistApp(owner, 1, map[string]any{
		"allowToggleInUsage": false,
		"allowAddInUsage":    false,
		"item_a":             map[string]any{"title": "x", "checked": false, "order": 0.0},
	}, member, viewer, admin)
	e.makeAdmin(appID, admin)
	_, err := e.db.Exec(`UPDATE members SET role = 'viewer' WHERE application_id = $1 AND public_key = $2`, appID, viewer.PublicKey)
	require.NoError(t, err)
	memberSession, _ := e.connect(member)
	viewerSession, _ := e.connect(viewer)
	adminSession, _ := e.connect(admin)

	// when
	viewed, _ := call(t, viewerSession, "add_checklist_item", map[string]any{"appId": appID, "title": "t"})
	added, _ := call(t, memberSession, "add_checklist_item", map[string]any{"appId": appID, "title": "t"})
	renamed, _ := call(t, memberSession, "update_checklist_item", map[string]any{"appId": appID, "itemId": "a", "title": "t"})
	checked, _ := call(t, memberSession, "update_checklist_item", map[string]any{"appId": appID, "itemId": "a", "checked": true})
	byAdmin, adminOut := call(t, adminSession, "update_checklist_item", map[string]any{"appId": appID, "itemId": "a", "checked": true})

	// then
	assert.Contains(t, errText(viewed), "viewers cannot edit")
	assert.Contains(t, errText(added), "does not allow adding")
	assert.Contains(t, errText(renamed), "does not allow renaming")
	assert.Contains(t, errText(checked), "does not allow checking")
	assert.False(t, byAdmin.IsError, toJSON(adminOut))
}

func TestMCP_ChecklistTools_ShouldHideAppWhenAgentReadIsOff(t *testing.T) {
	// given
	e := newEnv(t)
	owner, member := e.account(), e.account()
	appID := e.checklistApp(owner, 1, map[string]any{}, member)
	require.NoError(t, e.apps.SetAgentRead(appID, owner, false))
	session, _ := e.connect(member)

	// when
	res, _ := call(t, session, "add_checklist_item", map[string]any{"appId": appID, "title": "t"})

	// then
	assert.Equal(t, "app not found or not open to agents", errText(res))
}

func TestMCP_AgentReadOff_ShouldLetOwnerAgentAddChecklistItem(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID := e.checklistApp(owner, 1, map[string]any{})
	require.NoError(t, e.apps.SetAgentRead(appID, owner, false))
	session, _ := e.connect(owner)

	// when
	res, out := call(t, session, "add_checklist_item", map[string]any{"appId": appID, "title": "t"})

	// then
	require.False(t, res.IsError, toJSON(out))
	assert.NotEmpty(t, out["itemId"])
}

func TestMCP_UpdateChecklistItem_ShouldReportFieldPathWhenPatchIsInvalid(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID := e.checklistApp(owner, 1, map[string]any{"item_a": map[string]any{"title": "x", "checked": false, "bogus": 1.0}})
	session, _ := e.connect(owner)

	// when
	res, out := call(t, session, "update_checklist_item", map[string]any{"appId": appID, "itemId": "a", "checked": true})

	// then
	assert.True(t, res.IsError)
	assert.Equal(t, "invalid data", out["error"])
	assert.Contains(t, toJSON(out["untrusted"]), "/item_a")
}

func TestMCP_ChecklistTools_ShouldListChecklistsWhenSeveralAndNoComponentID(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID := e.checklistApp(owner, 2, map[string]any{})
	session, _ := e.connect(owner)

	// when
	res, out := call(t, session, "add_checklist_item", map[string]any{"appId": appID, "title": "t"})

	// then
	assert.True(t, res.IsError)
	assert.Len(t, out["untrusted"].(map[string]any)["checklists"], 2)
}
