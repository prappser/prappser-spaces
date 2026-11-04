//go:build integration

package mcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
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
	"github.com/prappser/prappser-spaces/internal/middleware"
	"github.com/prappser/prappser-spaces/internal/testdb"
	"github.com/prappser/prappser-spaces/internal/user"
)

type recordingBroadcaster struct {
	mu    sync.Mutex
	apps  []string
	users []string
}

func (b *recordingBroadcaster) BroadcastToApplication(appID string, _ *event.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.apps = append(b.apps, appID)
}
func (b *recordingBroadcaster) BroadcastToUser(userKey string, _ *event.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.users = append(b.users, userKey)
}

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
	return newEnvWithAppLimit(t, 0)
}

func newEnvWithAppLimit(t *testing.T, maxApps int) *env {
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
	apps := application.NewApplicationService(appRepo, maxApps, "space-key")

	validator, err := component.NewValidator()
	require.NoError(t, err)

	next := func(ctx *fasthttp.RequestCtx) { ctx.Error("fallthrough", fasthttp.StatusNotFound) }
	srv := &fasthttp.Server{Handler: Mount(next, Deps{Apps: apps, Invitations: invites, Events: events, Agents: agents, Validator: validator, ExternalURL: base, ClientIP: middleware.NewClientIPResolver("", false)})}
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

func (e *env) makeRole(appID string, u *user.User, role application.MemberRole) {
	e.t.Helper()
	_, err := e.db.Exec(`UPDATE members SET role = $1 WHERE application_id = $2 AND public_key = $3`, string(role), appID, u.PublicKey)
	require.NoError(e.t, err)
}

func (e *env) componentApp(owner *user.User, typ string, data map[string]any, members ...*user.User) (appID, compID string) {
	e.t.Helper()
	appID = e.app(owner, 0, members...)
	compID = appID + "-comp"
	raw, _ := json.Marshal(data)
	_, err := e.db.Exec(`INSERT INTO components (id, component_group_id, application_id, name, data, index_order) VALUES ($1, $2, $3, $4, $5, 0)`,
		compID, appID+"-g", appID, typ, string(raw))
	require.NoError(e.t, err)
	return appID, compID
}

func (e *env) compData(compID string) map[string]any {
	e.t.Helper()
	var raw string
	require.NoError(e.t, e.db.QueryRow(`SELECT data FROM components WHERE id = $1`, compID).Scan(&raw))
	var out map[string]any
	require.NoError(e.t, json.Unmarshal([]byte(raw), &out))
	return out
}

func (e *env) eventCount(appID string) int {
	e.t.Helper()
	var n int
	require.NoError(e.t, e.db.QueryRow(`SELECT COUNT(*) FROM events WHERE application_id = $1`, appID).Scan(&n))
	return n
}

func update(t *testing.T, s *sdk.ClientSession, appID, compID string, set map[string]any) (*sdk.CallToolResult, map[string]any) {
	t.Helper()
	return call(t, s, "update_component", map[string]any{"appId": appID, "componentId": compID, "set": set})
}

func chatMsg(sender, body string) string {
	return toJSON(map[string]any{"v": 1, "sender": sender, "ts": time.Now().UnixMilli(), "body": body})
}

func newMsgKey() string { return "m_" + uuid.NewString() }

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
	assert.Equal(t, owner.PublicKey, get["myPublicKey"])
	assert.Contains(t, toJSON(content["members"]), owner.PublicKey)
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
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

func TestMCP_CreateInvite_ShouldExplainExpiryLimit(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID := e.app(owner, 0)
	session, _ := e.connect(owner)

	// when
	res, _ := call(t, session, "create_invite", map[string]any{"appId": appID, "expiresInHours": 168})

	// then
	require.True(t, res.IsError)
	assert.Contains(t, errText(res), "expiresInHours must be between 0 and 48")
	assert.NotContains(t, errText(res), "internal error")
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

func TestMCP_CreateInvite_ShouldRejectAdminRoleAndCreateNothing(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID := e.app(owner, 0)
	session, _ := e.connect(owner)

	// when
	res, _ := call(t, session, "create_invite", map[string]any{"appId": appID, "role": "admin"})

	// then
	assert.True(t, res.IsError)
	assert.Contains(t, errText(res), "member or viewer")
	var count int
	require.NoError(t, e.db.QueryRow(`SELECT COUNT(*) FROM invitations WHERE application_id = $1`, appID).Scan(&count))
	assert.Zero(t, count)
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
	postRes, _ := update(t, memberSession, appID, appID+"-chata", map[string]any{newMsgKey(): chatMsg(member.PublicKey, "hi")})
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
	e.makeRole(appID, admin, application.MemberRoleAdmin)
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
	update(t, session, appID, appID+"-chata", map[string]any{newMsgKey(): chatMsg(owner.PublicKey, "hi")})

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

func templateDoc(name string, comps ...map[string]any) map[string]any {
	groups := []any{}
	for i, c := range comps {
		groups = append(groups, map[string]any{"name": "G" + string(rune('a'+i)), "index": 5 - i, "components": []any{c}})
	}
	return map[string]any{"name": name, "description": "d", "icon": "home", "groups": groups}
}

func checklistComp(item map[string]any) map[string]any {
	return map[string]any{"type": "Checklist", "index": 0, "data": map[string]any{"item_x": item}}
}

func (e *env) appCount(u *user.User) int {
	e.t.Helper()
	var n int
	require.NoError(e.t, e.db.QueryRow(`SELECT COUNT(*) FROM members WHERE public_key = $1`, u.PublicKey).Scan(&n))
	return n
}

func TestMCP_CreateApp_ShouldCreateAppOwnedByCallerWithFreshIDs(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	session, _ := e.connect(owner)
	doc := templateDoc("  Trip plan ",
		checklistComp(map[string]any{"title": "Pack", "checked": false, "order": 0.0}),
		map[string]any{"type": "Text", "index": 2, "data": map[string]any{"document": []any{map[string]any{"insert": "hello\n"}}}},
	)

	// when
	res, out := call(t, session, "create_app", map[string]any{"doc": doc})

	// then
	require.False(t, res.IsError, toJSON(out))
	appID := out["appId"].(string)
	assert.Equal(t, "Trip plan", out["name"])
	_, got := call(t, session, "get_app", map[string]any{"appId": appID})
	assert.Equal(t, "owner", got["role"])
	content := got["untrusted"].(map[string]any)
	assert.Equal(t, "Trip plan", content["name"])
	assert.Len(t, content["members"], 1)
	groups := content["componentGroups"].([]any)
	require.Len(t, groups, 2)
	var checklist map[string]any
	for _, g := range groups {
		for _, c := range g.(map[string]any)["components"].([]any) {
			if c.(map[string]any)["name"] == "Checklist" {
				checklist = c.(map[string]any)
			}
		}
	}
	require.NotNil(t, checklist)
	assert.Equal(t, map[string]any{"title": "Pack", "checked": false, "order": 0.0}, checklist["data"].(map[string]any)["item_x"])
	var indexes []int
	rows, err := e.db.Query(`SELECT index_order FROM component_groups WHERE application_id = $1 ORDER BY index_order`, appID)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var i int
		require.NoError(t, rows.Scan(&i))
		indexes = append(indexes, i)
	}
	assert.Equal(t, []int{4, 5}, indexes)
	var ownerKey string
	require.NoError(t, e.db.QueryRow(`SELECT public_key FROM members WHERE application_id = $1 AND role = 'owner'`, appID).Scan(&ownerKey))
	assert.Equal(t, owner.PublicKey, ownerKey)
	e.bc.mu.Lock()
	defer e.bc.mu.Unlock()
	assert.Contains(t, e.bc.users, owner.PublicKey)
}

func TestMCP_CreateApp_ShouldRejectDocWithMessageKey(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	session, _ := e.connect(owner)
	doc := templateDoc("Chatty", map[string]any{"type": "Chat", "index": 0, "data": map[string]any{"m_1": "x"}})

	// when
	res, out := call(t, session, "create_app", map[string]any{"doc": doc})

	// then
	assert.True(t, res.IsError)
	assert.Equal(t, "invalid template", out["error"])
	assert.Equal(t, 0, e.appCount(owner))
}

func TestMCP_CreateApp_ShouldRejectAssignedMemberAndNameTooLongInUTF16(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	session, _ := e.connect(owner)
	assigned := templateDoc("Ok", checklistComp(map[string]any{"title": "t", "checked": false, "assignedMemberId": "somebody"}))
	tooLong := templateDoc(strings.Repeat("a", 63) + "😀")

	// when
	resAssigned, outAssigned := call(t, session, "create_app", map[string]any{"doc": assigned})
	resLong, outLong := call(t, session, "create_app", map[string]any{"doc": tooLong})

	// then
	assert.True(t, resAssigned.IsError)
	assert.Contains(t, toJSON(outAssigned["untrusted"]), "/groups/0/components/0/data/item_x/assignedMemberId")
	assert.True(t, resLong.IsError)
	assert.Contains(t, toJSON(outLong["untrusted"]), "/name")
	assert.Equal(t, 0, e.appCount(owner))
}

func TestMCP_CreateApp_ShouldRefuseWhenAppLimitIsReached(t *testing.T) {
	// given
	e := newEnvWithAppLimit(t, 1)
	owner := e.account()
	session, _ := e.connect(owner)
	first, _ := call(t, session, "create_app", map[string]any{"doc": templateDoc("One")})
	require.False(t, first.IsError)

	// when
	res, out := call(t, session, "create_app", map[string]any{"doc": templateDoc("Two")})

	// then
	assert.True(t, res.IsError)
	assert.Equal(t, "you have reached your app limit", out["error"])
	assert.Equal(t, map[string]any{"fields": []any{}}, out["untrusted"])
	assert.Equal(t, 1, e.appCount(owner))
}

func TestMCP_GetApp_ShouldReturnIndexesAndPublicKeys(t *testing.T) {
	// given
	e := newEnv(t)
	owner, member := e.account(), e.account()
	appID, _ := e.componentApp(owner, "Text", map[string]any{}, member)
	session, _ := e.connect(member)

	// when
	_, get := call(t, session, "get_app", map[string]any{"appId": appID})

	// then
	assert.Equal(t, member.PublicKey, get["myPublicKey"])
	content := get["untrusted"].(map[string]any)
	group := content["componentGroups"].([]any)[0].(map[string]any)
	assert.Contains(t, group, "index")
	assert.Contains(t, group["components"].([]any)[0], "index")
	var keys []string
	for _, m := range content["members"].([]any) {
		keys = append(keys, m.(map[string]any)["publicKey"].(string))
	}
	assert.ElementsMatch(t, []string{owner.PublicKey, member.PublicKey}, keys)
}

func TestMCP_DescribeComponent_ShouldListTypesAndReturnSchemaForAnySignedInCaller(t *testing.T) {
	// given
	e := newEnv(t)
	session, _ := e.connect(e.account())

	// when
	_, list := call(t, session, "describe_component", nil)
	_, chat := call(t, session, "describe_component", map[string]any{"type": "Chat"})
	unknown, _ := call(t, session, "describe_component", map[string]any{"type": "Nope"})

	// then
	listed := toJSON(list["types"])
	assert.Contains(t, listed, `"Chat"`)
	assert.Contains(t, listed, `"Checklist"`)
	assert.Contains(t, listed, `"Poll"`)
	assert.NotContains(t, listed, `"Common"`)
	assert.Equal(t, "Chat", chat["type"])
	assert.Contains(t, toJSON(chat["schema"]), "x-access")
	assert.True(t, unknown.IsError)
	assert.Contains(t, errText(unknown), "unknown component type")
}

func TestMCP_UpdateComponent_ShouldPersistChatMessageAsCallerAndBroadcast(t *testing.T) {
	// given
	e := newEnv(t)
	owner, member := e.account(), e.account()
	appID := e.app(owner, 1, member)
	session, _ := e.connect(member)

	// when
	res, out := update(t, session, appID, appID+"-chata", map[string]any{"m_*": chatMsg(member.PublicKey, "hello team")})

	// then
	require.False(t, res.IsError, toJSON(out))
	key := out["keys"].([]any)[0].(string)
	assert.True(t, strings.HasPrefix(key, "m_"))
	var count int
	require.NoError(t, e.db.QueryRow(`SELECT COUNT(*) FROM events WHERE application_id = $1 AND creator_public_key = $2`, appID, member.PublicKey).Scan(&count))
	assert.Equal(t, 1, count)
	var msg map[string]any
	require.NoError(t, json.Unmarshal([]byte(e.compData(appID + "-chata")[key].(string)), &msg))
	assert.Equal(t, member.PublicKey, msg["sender"])
	assert.True(t, e.bc.saw(appID))
}

func TestMCP_UpdateComponent_ShouldReturnWrittenChatMessagesUnderUntrusted(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID := e.app(owner, 1)
	session, _ := e.connect(owner)
	update(t, session, appID, appID+"-chata", map[string]any{"m_*": chatMsg(owner.PublicKey, "hello team")})

	// when
	_, get := call(t, session, "get_app", map[string]any{"appId": appID})

	// then
	assert.NotContains(t, get, "componentGroups")
	groups := get["untrusted"].(map[string]any)["componentGroups"]
	assert.Contains(t, toJSON(groups), "hello team")
}

func TestMCP_UpdateComponent_ShouldHideAppWhenAgentReadIsOff(t *testing.T) {
	// given
	e := newEnv(t)
	owner, member := e.account(), e.account()
	appID, compID := e.componentApp(owner, "Checklist", map[string]any{}, member)
	require.NoError(t, e.apps.SetAgentRead(appID, owner, false))
	session, _ := e.connect(member)

	// when
	res, _ := update(t, session, appID, compID, map[string]any{"item_*": map[string]any{"title": "t", "checked": false}})

	// then
	assert.Equal(t, "app not found or not open to agents", errText(res))
}

func TestMCP_UpdateComponent_ShouldRejectNonMember(t *testing.T) {
	// given
	e := newEnv(t)
	owner, stranger := e.account(), e.account()
	appID, compID := e.componentApp(owner, "Checklist", map[string]any{})
	session, _ := e.connect(stranger)

	// when
	res, _ := update(t, session, appID, compID, map[string]any{"item_*": map[string]any{"title": "t", "checked": false}})

	// then
	assert.Equal(t, "app not found or not open to agents", errText(res))
	assert.Equal(t, 0, e.eventCount(appID))
}

func TestMCP_UpdateComponent_ShouldLetOwnerAgentWriteWhenAgentReadIsOff(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID, compID := e.componentApp(owner, "Checklist", map[string]any{})
	require.NoError(t, e.apps.SetAgentRead(appID, owner, false))
	session, _ := e.connect(owner)

	// when
	res, out := update(t, session, appID, compID, map[string]any{"item_*": map[string]any{"title": "t", "checked": false}})

	// then
	require.False(t, res.IsError, toJSON(out))
	assert.NotEmpty(t, out["keys"])
}

func TestMCP_UpdateComponent_ShouldRejectViewerAndWriteNothing(t *testing.T) {
	// given
	e := newEnv(t)
	owner, viewer := e.account(), e.account()
	appID, compID := e.componentApp(owner, "Poll", map[string]any{"question": "q", "options": []any{}}, viewer)
	e.makeRole(appID, viewer, application.MemberRoleViewer)
	session, _ := e.connect(viewer)

	// when
	res, _ := update(t, session, appID, compID, map[string]any{"vote_" + viewer.PublicKey: "a"})

	// then
	assert.Contains(t, errText(res), "viewers cannot change this app")
	assert.Equal(t, 0, e.eventCount(appID))
}

func TestMCP_UpdateComponent_ShouldRejectUnknownComponentAndUnknownKey(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID, compID := e.componentApp(owner, "Text", map[string]any{})
	session, _ := e.connect(owner)

	// when
	noComp, _ := update(t, session, appID, "nope", map[string]any{"document": []any{}})
	noKey, _ := update(t, session, appID, compID, map[string]any{"bogus": 1})
	empty, _ := update(t, session, appID, compID, map[string]any{})

	// then
	assert.Contains(t, errText(noComp), "component not found")
	assert.Contains(t, errText(noKey), "not a key of Text")
	assert.Contains(t, errText(empty), "set is empty")
}

func TestMCP_UpdateComponent_ShouldWriteOnlyTheNewKeyAndKeepConcurrentEdits(t *testing.T) {
	// given
	e := newEnv(t)
	owner, friend := e.account(), e.account()
	friendItem := map[string]any{"title": "friend edit", "checked": true, "order": 4.5}
	appID, compID := e.componentApp(owner, "Checklist", map[string]any{"title": "Packing", "item_f": friendItem}, friend)
	session, _ := e.connect(owner)

	// when
	res, out := update(t, session, appID, compID, map[string]any{"item_*": map[string]any{"title": "sunscreen", "checked": false, "order": 5.5}})

	// then
	require.False(t, res.IsError, toJSON(out))
	data := e.compData(compID)
	assert.Equal(t, map[string]any{"title": "sunscreen", "checked": false, "order": 5.5}, data[out["keys"].([]any)[0].(string)])
	assert.Equal(t, friendItem, data["item_f"])
	assert.Equal(t, "Packing", data["title"])
	assert.Len(t, data, 3)
	assert.True(t, e.bc.saw(appID))
}

func TestMCP_UpdateComponent_ShouldWriteKeyedItemAndLeaveLegacyItemsAlone(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	legacy := []any{map[string]any{"id": "a", "title": "x", "checked": false}}
	appID, compID := e.componentApp(owner, "Checklist", map[string]any{"items": legacy})
	session, _ := e.connect(owner)

	// when
	res, out := update(t, session, appID, compID, map[string]any{"item_a": map[string]any{"title": "x", "checked": true, "order": 0}})

	// then
	require.False(t, res.IsError, toJSON(out))
	data := e.compData(compID)
	assert.Equal(t, map[string]any{"title": "x", "checked": true, "order": 0.0}, data["item_a"])
	assert.Equal(t, legacy, data["items"])
}

func TestMCP_UpdateComponent_ShouldReportFieldPathWhenValueIsInvalid(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID, compID := e.componentApp(owner, "Checklist", map[string]any{})
	session, _ := e.connect(owner)

	// when
	res, out := update(t, session, appID, compID, map[string]any{"item_a": map[string]any{"title": "x", "checked": false, "bogus": 1}})

	// then
	assert.True(t, res.IsError)
	assert.Equal(t, "invalid data", out["error"])
	assert.Contains(t, toJSON(out["untrusted"]), "/item_a")
}

func TestMCP_UpdateComponent_ShouldLetMemberWriteOnlyTheirOwnPollCell(t *testing.T) {
	// given
	e := newEnv(t)
	owner, member, other := e.account(), e.account(), e.account()
	appID, compID := e.componentApp(owner, "Poll", map[string]any{"question": "q", "options": []any{}}, member, other)
	session, _ := e.connect(member)

	// when
	own, ownOut := update(t, session, appID, compID, map[string]any{"vote_" + member.PublicKey: "a"})
	theirs, _ := update(t, session, appID, compID, map[string]any{"vote_" + other.PublicKey: "a"})
	forged, _ := update(t, session, appID, compID, map[string]any{"vote_X_" + member.PublicKey: "a"})

	// then
	require.False(t, own.IsError, toJSON(ownOut))
	assert.Contains(t, errText(theirs), "you can only write your own cell")
	assert.Contains(t, errText(forged), "you can only write your own cell")
	assert.Equal(t, 1, e.eventCount(appID))
}

func TestMCP_UpdateComponent_ShouldTurnVotesOffWhenPollIsClosed(t *testing.T) {
	// given
	e := newEnv(t)
	owner, member := e.account(), e.account()
	appID, compID := e.componentApp(owner, "Poll", map[string]any{"question": "q", "options": []any{}, "closed": true}, member)
	memberSession, _ := e.connect(member)
	ownerSession, _ := e.connect(owner)

	// when
	byMember, _ := update(t, memberSession, appID, compID, map[string]any{"vote_" + member.PublicKey: "a"})
	byOwner, _ := update(t, ownerSession, appID, compID, map[string]any{"vote_" + owner.PublicKey: "a"})

	// then
	assert.Contains(t, errText(byMember), "turned off by closed")
	assert.Contains(t, errText(byOwner), "turned off by closed")
	assert.Equal(t, 0, e.eventCount(appID))
}

func TestMCP_UpdateComponent_ShouldKeepAppendOnlyMessagesAppendOnly(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	existing := newMsgKey()
	appID, compID := e.componentApp(owner, "Chat", map[string]any{existing: chatMsg(owner.PublicKey, "first")})
	session, _ := e.connect(owner)

	// when
	again, _ := update(t, session, appID, compID, map[string]any{existing: chatMsg(owner.PublicKey, "edit")})
	blank, _ := update(t, session, appID, compID, map[string]any{"m_*": ""})

	// then
	assert.Contains(t, errText(again), "already exists")
	assert.Contains(t, errText(blank), "cannot be deleted")
	assert.Equal(t, 0, e.eventCount(appID))
}

func TestMCP_UpdateComponent_ShouldRejectMessageFromAnotherSender(t *testing.T) {
	// given
	e := newEnv(t)
	owner, member := e.account(), e.account()
	appID, compID := e.componentApp(owner, "Chat", map[string]any{}, member)
	session, _ := e.connect(member)

	// when
	res, _ := update(t, session, appID, compID, map[string]any{"m_*": chatMsg(owner.PublicKey, "forged")})

	// then
	assert.Contains(t, errText(res), "sender must be your publicKey")
	assert.Equal(t, 0, e.eventCount(appID))
}

func TestMCP_UpdateComponent_ShouldRejectOverwriteAndTombstoneOfSomeoneElsesSettlement(t *testing.T) {
	// given
	e := newEnv(t)
	owner, a, b := e.account(), e.account(), e.account()
	appID, compID := e.componentApp(owner, "Expenses", map[string]any{}, a, b)
	sessionA, _ := e.connect(a)
	sessionB, _ := e.connect(b)
	recorded, recordedOut := update(t, sessionA, appID, compID, map[string]any{"s_*": toJSON(map[string]any{"from": b.PublicKey, "to": a.PublicKey, "amount": 100})})
	require.False(t, recorded.IsError, toJSON(recordedOut))
	key := recordedOut["keys"].([]any)[0].(string)

	// when
	overwrite, _ := update(t, sessionB, appID, compID, map[string]any{key: toJSON(map[string]any{"from": b.PublicKey, "to": b.PublicKey, "amount": 100})})
	tombstone, _ := update(t, sessionB, appID, compID, map[string]any{key: ""})

	// then
	assert.Contains(t, errText(overwrite), "to must be your publicKey")
	assert.Contains(t, errText(tombstone), "to must be your publicKey")
	assert.Equal(t, 1, e.eventCount(appID))
}

func TestMCP_UpdateComponent_ShouldValidateEncodedContent(t *testing.T) {
	// given
	e := newEnv(t)
	owner, member := e.account(), e.account()
	oldExpense := "e_" + uuid.NewString()
	appID, compID := e.componentApp(owner, "Expenses", map[string]any{oldExpense: toJSON(map[string]any{"what": "x", "payer": owner.PublicKey, "amount": 1})}, member)
	session, _ := e.connect(member)

	// when
	notJSON, _ := update(t, session, appID, compID, map[string]any{"e_*": "not json"})
	ok, okOut := update(t, session, appID, compID, map[string]any{"e_*": toJSON(map[string]any{"what": "Dinner", "payer": member.PublicKey, "amount": 4500})})
	deleted, deletedOut := update(t, session, appID, compID, map[string]any{oldExpense: ""})

	// then
	assert.True(t, notJSON.IsError)
	require.False(t, ok.IsError, toJSON(okOut))
	require.False(t, deleted.IsError, toJSON(deletedOut))
	assert.Equal(t, "", e.compData(compID)[oldExpense])
}

func TestMCP_UpdateComponent_ShouldRejectMessageWithoutBody(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID, compID := e.componentApp(owner, "Chat", map[string]any{})
	session, _ := e.connect(owner)

	// when
	res, out := update(t, session, appID, compID, map[string]any{"m_*": toJSON(map[string]any{"v": 1, "sender": owner.PublicKey, "ts": 1})})

	// then
	assert.True(t, res.IsError)
	assert.Contains(t, toJSON(out), "invalid value")
	assert.Equal(t, 0, e.eventCount(appID))
}

func TestMCP_UpdateComponent_ShouldLimitManageKeysToOwnerAndAdmin(t *testing.T) {
	// given
	e := newEnv(t)
	owner, member, admin := e.account(), e.account(), e.account()
	appID, compID := e.componentApp(owner, "Poll", map[string]any{"question": "q", "options": []any{}}, member, admin)
	e.makeRole(appID, admin, application.MemberRoleAdmin)
	memberSession, _ := e.connect(member)
	adminSession, _ := e.connect(admin)
	ownerSession, _ := e.connect(owner)

	// when
	byMember, _ := update(t, memberSession, appID, compID, map[string]any{"question": "x"})
	byAdmin, _ := update(t, adminSession, appID, compID, map[string]any{"question": "by admin"})
	byOwner, _ := update(t, ownerSession, appID, compID, map[string]any{"question": "by owner"})

	// then
	assert.Contains(t, errText(byMember), "owner or admin only")
	assert.False(t, byAdmin.IsError)
	assert.False(t, byOwner.IsError)
	assert.Equal(t, "by owner", e.compData(compID)["question"])
}

func TestMCP_UpdateComponent_ShouldRejectKeysNotWritableByAgents(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID, compID := e.componentApp(owner, "Checklist", map[string]any{})
	session, _ := e.connect(owner)

	// when
	res, _ := update(t, session, appID, compID, map[string]any{"items": []any{}})

	// then
	assert.Contains(t, errText(res), "not writable by agents")
	assert.Equal(t, 0, e.eventCount(appID))
}

func TestMCP_UpdateComponent_ShouldApplyChecklistGatesPerField(t *testing.T) {
	// given
	e := newEnv(t)
	owner, member, admin := e.account(), e.account(), e.account()
	item := map[string]any{"title": "x", "checked": false, "order": 0.0}
	appID, compID := e.componentApp(owner, "Checklist", map[string]any{"allowAddInUsage": false, "allowToggleInUsage": false, "item_a": item}, member, admin)
	e.makeRole(appID, admin, application.MemberRoleAdmin)
	memberSession, _ := e.connect(member)
	adminSession, _ := e.connect(admin)
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range item {
			m[kk] = vv
		}
		m[k] = v
		return map[string]any{"item_a": m}
	}

	// when
	created, _ := update(t, memberSession, appID, compID, map[string]any{"item_*": item})
	retitled, _ := update(t, memberSession, appID, compID, with("title", "y"))
	toggled, _ := update(t, memberSession, appID, compID, with("checked", true))
	noted, notedOut := update(t, memberSession, appID, compID, with("detailsDocument", []any{map[string]any{"insert": "note\n"}}))
	byAdmin, adminOut := update(t, adminSession, appID, compID, with("checked", true))

	// then
	assert.Contains(t, errText(created), "turned off by allowAddInUsage")
	assert.Contains(t, errText(retitled), "turned off by allowAddInUsage")
	assert.Contains(t, errText(toggled), "turned off by allowToggleInUsage")
	assert.False(t, noted.IsError, toJSON(notedOut))
	assert.False(t, byAdmin.IsError, toJSON(adminOut))
}

func TestMCP_UpdateComponent_ShouldUseFlagDefaultsWhenFlagIsAbsent(t *testing.T) {
	// given
	e := newEnv(t)
	owner, member := e.account(), e.account()
	listApp, listID := e.componentApp(owner, "Checklist", map[string]any{}, member)
	countApp, countID := e.componentApp(owner, "Countdown", map[string]any{}, member)
	countOn, countOnID := e.componentApp(owner, "Countdown", map[string]any{"runEditable": true}, member)
	session, _ := e.connect(member)

	// when
	added, addedOut := update(t, session, listApp, listID, map[string]any{"item_*": map[string]any{"title": "t", "checked": false}})
	off, _ := update(t, session, countApp, countID, map[string]any{"what": "Holiday"})
	on, onOut := update(t, session, countOn, countOnID, map[string]any{"what": "Holiday"})

	// then
	require.False(t, added.IsError, toJSON(addedOut))
	assert.Contains(t, errText(off), "turned off by runEditable")
	require.False(t, on.IsError, toJSON(onOut))
}

func TestMCP_UpdateComponent_ShouldWriteAllKeysInOneEvent(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID, compID := e.componentApp(owner, "Checklist", map[string]any{})
	session, _ := e.connect(owner)

	// when
	res, out := update(t, session, appID, compID, map[string]any{"item_*": map[string]any{"title": "t", "checked": false}, "_title": "Packing"})

	// then
	require.False(t, res.IsError, toJSON(out))
	assert.Len(t, out["keys"], 2)
	assert.Equal(t, 1, e.eventCount(appID))
	var raw string
	require.NoError(t, e.db.QueryRow(`SELECT data FROM events WHERE application_id = $1`, appID).Scan(&raw))
	var data map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &data))
	assert.Len(t, data["changedFields"], 2)
	assert.Len(t, e.compData(compID), 2)
}

func TestMCP_UpdateComponent_ShouldWriteNothingWhenOneKeyFails(t *testing.T) {
	// given
	e := newEnv(t)
	owner, member := e.account(), e.account()
	appID, compID := e.componentApp(owner, "Checklist", map[string]any{}, member)
	session, _ := e.connect(member)

	// when
	res, _ := update(t, session, appID, compID, map[string]any{"item_*": map[string]any{"title": "t", "checked": false}, "_title": "Packing"})

	// then
	assert.Contains(t, errText(res), "owner or admin only")
	assert.Equal(t, 0, e.eventCount(appID))
	assert.Empty(t, e.compData(compID))
}

func TestMCP_UpdateComponent_ShouldGateToggleOnLegacyItemWrittenAsKeyedItem(t *testing.T) {
	// given
	e := newEnv(t)
	owner, member := e.account(), e.account()
	legacy := []any{map[string]any{"id": "a", "title": "x", "checked": false}}
	appID, compID := e.componentApp(owner, "Checklist", map[string]any{"items": legacy, "allowToggleInUsage": false}, member)
	session, _ := e.connect(member)

	// when
	res, _ := update(t, session, appID, compID, map[string]any{"item_a": map[string]any{"title": "x", "checked": true, "order": 0}})

	// then
	assert.Contains(t, errText(res), "turned off by allowToggleInUsage")
	assert.Equal(t, 0, e.eventCount(appID))
	assert.NotContains(t, e.compData(compID), "item_a")
}

func TestMCP_UpdateComponent_ShouldGateToggleThroughCreateAndTombstone(t *testing.T) {
	// given
	e := newEnv(t)
	owner, member := e.account(), e.account()
	checked := map[string]any{"title": "a", "checked": true, "order": 0.0}
	unchecked := map[string]any{"title": "b", "checked": false, "order": 1.0}
	appID, compID := e.componentApp(owner, "Checklist", map[string]any{"allowToggleInUsage": false, "item_a": checked, "item_b": unchecked}, member)
	session, _ := e.connect(member)

	// when
	tombChecked, _ := update(t, session, appID, compID, map[string]any{"item_a": ""})
	tombUnchecked, tombOut := update(t, session, appID, compID, map[string]any{"item_b": ""})
	recreated, _ := update(t, session, appID, compID, map[string]any{"item_b": map[string]any{"title": "b", "checked": true, "order": 1.0}})
	createdOff, offOut := update(t, session, appID, compID, map[string]any{"item_*": map[string]any{"title": "c", "checked": false, "order": 2.0}})
	createdOn, _ := update(t, session, appID, compID, map[string]any{"item_*": map[string]any{"title": "d", "checked": true, "order": 3.0}})

	// then
	assert.Contains(t, errText(tombChecked), "turned off by allowToggleInUsage")
	assert.False(t, tombUnchecked.IsError, toJSON(tombOut))
	assert.Contains(t, errText(recreated), "turned off by allowToggleInUsage")
	assert.False(t, createdOff.IsError, toJSON(offOut))
	assert.Contains(t, errText(createdOn), "turned off by allowToggleInUsage")
	assert.Equal(t, checked, e.compData(compID)["item_a"])
	assert.Equal(t, 2, e.eventCount(appID))
	assert.Equal(t, "", e.compData(compID)["item_b"])
	for k, v := range e.compData(compID) {
		if m, ok := v.(map[string]any); ok && strings.HasPrefix(k, "item_") {
			assert.NotEqual(t, "d", m["title"], k)
		}
	}
}

func TestMCP_UpdateComponent_ShouldLetMemberWriteOnlyTheirOwnReactionCell(t *testing.T) {
	// given
	e := newEnv(t)
	owner, member, other := e.account(), e.account(), e.account()
	msg := newMsgKey()
	appID, compID := e.componentApp(owner, "Chat", map[string]any{msg: chatMsg(owner.PublicKey, "hi")}, member, other)
	session, _ := e.connect(member)

	// when
	own, ownOut := update(t, session, appID, compID, map[string]any{"react_" + msg + "_" + member.PublicKey: "👍"})
	theirs, _ := update(t, session, appID, compID, map[string]any{"react_" + msg + "_" + other.PublicKey: "👍"})

	// then
	require.False(t, own.IsError, toJSON(ownOut))
	assert.Contains(t, errText(theirs), "you can only write your own cell")
	assert.Equal(t, 1, e.eventCount(appID))
}

func TestMCP_UpdateComponent_ShouldLetOwnerAndAdminSetCountdownWhatWhenRunEditableIsAbsent(t *testing.T) {
	// given
	e := newEnv(t)
	owner, admin := e.account(), e.account()
	appID, compID := e.componentApp(owner, "Countdown", map[string]any{}, admin)
	e.makeRole(appID, admin, application.MemberRoleAdmin)
	adminSession, _ := e.connect(admin)
	ownerSession, _ := e.connect(owner)

	// when
	byAdmin, adminOut := update(t, adminSession, appID, compID, map[string]any{"what": "Holiday"})
	byOwner, ownerOut := update(t, ownerSession, appID, compID, map[string]any{"what": "Trip"})

	// then
	require.False(t, byAdmin.IsError, toJSON(adminOut))
	require.False(t, byOwner.IsError, toJSON(ownerOut))
	assert.Equal(t, "Trip", e.compData(compID)["what"])
}

func TestMCP_UpdateComponent_ShouldCheckAccessBeforeSchemaValidation(t *testing.T) {
	// given
	e := newEnv(t)
	owner, member := e.account(), e.account()
	appID, compID := e.componentApp(owner, "Poll", map[string]any{"question": "q", "options": []any{}}, member)
	session, _ := e.connect(member)

	// when
	res, _ := update(t, session, appID, compID, map[string]any{"question": 123})

	// then
	assert.Contains(t, errText(res), "owner or admin only")
	assert.Equal(t, 0, e.eventCount(appID))
}

func edit(t *testing.T, s *sdk.ClientSession, appID string, changes ...map[string]any) (*sdk.CallToolResult, map[string]any) {
	t.Helper()
	return call(t, s, "edit_app", map[string]any{"appId": appID, "changes": changes})
}

func TestMCP_EditApp_ShouldLimitChangesToOwnerAndAdmin(t *testing.T) {
	// given
	e := newEnv(t)
	owner, admin, member, viewer, stranger := e.account(), e.account(), e.account(), e.account(), e.account()
	appID := e.app(owner, 0, admin, member, viewer)
	e.makeRole(appID, admin, application.MemberRoleAdmin)
	e.makeRole(appID, viewer, application.MemberRoleViewer)
	add := map[string]any{"op": "add_group", "name": "New"}

	// when
	strangerRes, _ := edit(t, mustSession(e, stranger), appID, add)
	viewerRes, _ := edit(t, mustSession(e, viewer), appID, add)
	memberRes, _ := edit(t, mustSession(e, member), appID, add)

	// then
	assert.Equal(t, "app not found or not open to agents", errText(strangerRes))
	assert.Equal(t, "you are not allowed to change this app", errText(viewerRes))
	assert.Equal(t, "you are not allowed to change this app", errText(memberRes))
	assert.Equal(t, 0, e.eventCount(appID))

	// when
	adminRes, adminOut := edit(t, mustSession(e, admin), appID, add)
	ownerRes, ownerOut := edit(t, mustSession(e, owner), appID, add)

	// then
	require.False(t, adminRes.IsError, toJSON(adminOut))
	require.False(t, ownerRes.IsError, toJSON(ownerOut))
	assert.Equal(t, 2, e.eventCount(appID))
}

func mustSession(e *env, u *user.User) *sdk.ClientSession {
	session, _ := e.connect(u)
	return session
}

func TestMCP_EditApp_ShouldSendEveryOpAsTheAppsStructureChange(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID, compID := e.componentApp(owner, "Checklist", map[string]any{})
	groupID, notesID := appID+"-g", appID+"-notes"
	session, _ := e.connect(owner)

	// when
	res, out := edit(t, session, appID,
		map[string]any{"op": "add_group", "name": "Extras"},
		map[string]any{"op": "add_group", "name": "Second", "index": 0},
		map[string]any{"op": "add_component", "groupId": "$0", "type": "Checklist", "data": map[string]any{"_title": "Packing"}},
		map[string]any{"op": "add_component", "groupId": "$1", "type": "Checklist", "index": 1},
		map[string]any{"op": "rename_group", "groupId": groupID, "name": "Renamed"},
		map[string]any{"op": "move_group", "groupId": "$1", "index": 2},
		map[string]any{"op": "move_component", "componentId": notesID, "index": 3},
		map[string]any{"op": "remove_component", "componentId": compID},
		map[string]any{"op": "remove_group", "groupId": "$0"},
	)

	// then
	require.False(t, res.IsError, toJSON(out))
	ids, _ := out["ids"].([]any)
	require.Len(t, ids, 9)
	extras, second, packing, listed := ids[0], ids[1], ids[2], ids[3]
	assert.Nil(t, ids[4])
	assert.Nil(t, ids[8])
	var raw string
	require.NoError(t, e.db.QueryRow(`SELECT data FROM events WHERE application_id = $1`, appID).Scan(&raw))
	var data struct {
		Version       int               `json:"version"`
		ApplicationID string            `json:"applicationId"`
		Changes       []json.RawMessage `json:"changes"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &data))
	assert.Equal(t, appID, data.ApplicationID)
	expected := []string{
		fmt.Sprintf(`{"changeType":"component_group_added","entityType":"component_group","entityId":%q,"data":{"id":%q,"applicationId":%q,"index":1,"name":"Extras"},"index":null,"changedFields":null}`, extras, extras, appID),
		fmt.Sprintf(`{"changeType":"component_group_added","entityType":"component_group","entityId":%q,"data":{"id":%q,"applicationId":%q,"index":0,"name":"Second"},"index":null,"changedFields":null}`, second, second, appID),
		fmt.Sprintf(`{"changeType":"component_added","entityType":"component","entityId":%q,"data":{"id":%q,"componentGroupId":%q,"applicationId":%q,"index":0,"name":"Checklist","data":{"_title":"Packing"}},"index":null,"changedFields":null}`, packing, packing, extras, appID),
		fmt.Sprintf(`{"changeType":"component_added","entityType":"component","entityId":%q,"data":{"id":%q,"componentGroupId":%q,"applicationId":%q,"index":1,"name":"Checklist","data":{}},"index":null,"changedFields":null}`, listed, listed, second, appID),
		fmt.Sprintf(`{"changeType":"component_group_changed","entityType":"component_group","entityId":%q,"data":{"name":"Renamed","index":0},"index":null,"changedFields":null}`, groupID),
		fmt.Sprintf(`{"changeType":"component_group_reordered","entityType":"component_group","entityId":%q,"data":null,"index":2,"changedFields":null}`, second),
		fmt.Sprintf(`{"changeType":"component_reordered","entityType":"component","entityId":%q,"data":null,"index":3,"changedFields":null}`, notesID),
		fmt.Sprintf(`{"changeType":"component_removed","entityType":"component","entityId":%q,"data":null,"index":null,"changedFields":null}`, compID),
		fmt.Sprintf(`{"changeType":"component_group_removed","entityType":"component_group","entityId":%q,"data":null,"index":null,"changedFields":null}`, extras),
		fmt.Sprintf(`{"changeType":"component_removed","entityType":"component","entityId":%q,"data":null,"index":null,"changedFields":null}`, packing),
	}
	require.Len(t, data.Changes, len(expected))
	for i, want := range expected {
		assert.JSONEq(t, want, string(data.Changes[i]), "change %d", i)
	}
	groups := map[string]int{}
	rows, err := e.db.Query(`SELECT name, index_order FROM component_groups WHERE application_id = $1`, appID)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var name string
		var index int
		require.NoError(t, rows.Scan(&name, &index))
		groups[name] = index
	}
	assert.Equal(t, map[string]int{"Renamed": 0, "Second": 2}, groups)
	var remaining, notesIndex int
	require.NoError(t, e.db.QueryRow(`SELECT COUNT(*) FROM components WHERE application_id = $1`, appID).Scan(&remaining))
	require.NoError(t, e.db.QueryRow(`SELECT index_order FROM components WHERE id = $1`, notesID).Scan(&notesIndex))
	assert.Equal(t, 2, remaining, "notes and the checklist added to Second")
	assert.Equal(t, 3, notesIndex)
}

func TestMCP_EditApp_ShouldRejectBadChangesAndWriteNothing(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID := e.app(owner, 0)
	session, _ := e.connect(owner)
	groupID := appID + "-g"
	cases := []struct {
		name   string
		change map[string]any
		want   string
	}{
		{"unknown group", map[string]any{"op": "rename_group", "groupId": "nope", "name": "x"}, "group nope not found"},
		{"unknown $N", map[string]any{"op": "move_group", "groupId": "$0", "index": 1}, "group $0 not found"},
		{"unknown component", map[string]any{"op": "remove_component", "componentId": "nope"}, "component nope not found"},
		{"unknown type", map[string]any{"op": "add_component", "groupId": groupID, "type": "Nope"}, "unknown component type"},
		{"none key", map[string]any{"op": "add_component", "groupId": groupID, "type": "Checklist", "data": map[string]any{"items": []any{}}}, "not writable by agents"},
		{"missing index", map[string]any{"op": "move_component", "componentId": appID + "-notes"}, "index is required"},
		{"missing name", map[string]any{"op": "add_group"}, "name is required"},
		{"unknown op", map[string]any{"op": "explode"}, "unknown op explode"},
		{"negative add_group index", map[string]any{"op": "add_group", "name": "x", "index": -1}, "index must be 0 or more"},
		{"negative add_component index", map[string]any{"op": "add_component", "groupId": groupID, "type": "Checklist", "index": -1}, "index must be 0 or more"},
		{"negative move_group index", map[string]any{"op": "move_group", "groupId": groupID, "index": -1}, "index must be 0 or more"},
		{"negative move_component index", map[string]any{"op": "move_component", "componentId": appID + "-notes", "index": -1}, "index must be 0 or more"},
	}

	// when / then
	for _, c := range cases {
		res, _ := edit(t, session, appID, c.change)
		assert.Contains(t, errText(res), c.want, c.name)
	}
	empty, _ := edit(t, session, appID)
	assert.Contains(t, errText(empty), "changes is empty")
	many := make([]map[string]any, 101)
	for i := range many {
		many[i] = map[string]any{"op": "add_group", "name": "x"}
	}
	tooMany, _ := edit(t, session, appID, many...)
	assert.Contains(t, errText(tooMany), "at most 100 changes per call")
	assert.Equal(t, 0, e.eventCount(appID))
}

func TestMCP_EditApp_ShouldWriteNothingWhenALaterChangeFails(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID := e.app(owner, 0)
	session, _ := e.connect(owner)
	var groupsBefore int
	require.NoError(t, e.db.QueryRow(`SELECT COUNT(*) FROM component_groups WHERE application_id = $1`, appID).Scan(&groupsBefore))

	// when
	res, _ := edit(t, session, appID,
		map[string]any{"op": "add_group", "name": "Kept?"},
		map[string]any{"op": "rename_group", "groupId": "nope", "name": "x"},
	)

	// then
	assert.Contains(t, errText(res), "group nope not found")
	assert.Equal(t, 0, e.eventCount(appID))
	var groupsAfter, kept int
	require.NoError(t, e.db.QueryRow(`SELECT COUNT(*) FROM component_groups WHERE application_id = $1`, appID).Scan(&groupsAfter))
	require.NoError(t, e.db.QueryRow(`SELECT COUNT(*) FROM component_groups WHERE application_id = $1 AND name = 'Kept?'`, appID).Scan(&kept))
	assert.Equal(t, groupsBefore, groupsAfter)
	assert.Equal(t, 0, kept)
}

func TestMCP_EditApp_ShouldReportFieldsWhenComponentDataIsInvalid(t *testing.T) {
	// given
	e := newEnv(t)
	owner := e.account()
	appID := e.app(owner, 0)
	session, _ := e.connect(owner)

	// when
	res, out := edit(t, session, appID, map[string]any{"op": "add_component", "groupId": appID + "-g", "type": "Checklist", "data": map[string]any{"_title": 5}})

	// then
	require.True(t, res.IsError)
	assert.Equal(t, "invalid data", out["error"])
	assert.NotEmpty(t, out["untrusted"].(map[string]any)["fields"])
	assert.Equal(t, 0, e.eventCount(appID))
}
