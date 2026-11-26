//go:build integration

package websocket

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	gws "github.com/fasthttp/websocket"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

const wsIssuer = "https://space.test"

type handlerFixture struct {
	hub    *Hub
	users  user.UserRepository
	userSv *user.UserService
	agents *user.AgentService
	priv   ed25519.PrivateKey
	dialer gws.Dialer
}

func newHandlerFixture(t *testing.T) *handlerFixture {
	t.Helper()
	db, repo, hub := newIntegrationHub(t)
	registerApp(t, repo, appA, integrationMember(appA, ownerKey, application.MemberRoleOwner, nil))
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	users := user.NewUserRepository(db)
	userSv := user.NewUserService(users, nil, user.Config{JWTExpirationHours: 24}, priv, pub)
	agents := user.NewAgentService(db, users, priv, pub, wsIssuer)
	go hub.Run()

	return &handlerFixture{hub: hub, users: users, userSv: userSv, agents: agents, priv: priv,
		dialer: serveHandler(t, NewHandler(hub, userSv, agents))}
}

func serveHandler(t *testing.T, h *Handler) gws.Dialer {
	t.Helper()
	ln := fasthttputil.NewInmemoryListener()
	srv := &fasthttp.Server{KeepHijackedConns: true, Handler: h.HandleFastHTTP}
	go srv.Serve(ln)
	t.Cleanup(func() { _ = srv.Shutdown(); _ = ln.Close() })
	return gws.Dialer{NetDial: func(_, _ string) (net.Conn, error) { return ln.Dial() }}
}

// dialReady dials and consumes the connected message, so the client is registered when it returns.
func (f *handlerFixture) dialReady(t *testing.T, token string) *gws.Conn {
	t.Helper()
	conn, _, err := f.dial(t, token)
	require.NoError(t, err)
	var msg OutgoingMessage
	require.NoError(t, conn.ReadJSON(&msg))
	require.Equal(t, MessageTypeConnected, msg.Type)
	return conn
}

func (f *handlerFixture) humanToken(t *testing.T) string {
	t.Helper()
	require.NoError(t, f.users.EnsureDevice(ownerKey, ownerKey, nil, time.Now().Unix()))
	token, _, err := f.userSv.GenerateJWT(&user.User{PublicKey: ownerKey, Username: "owner", Role: user.RoleUser}, ownerKey)
	require.NoError(t, err)
	return token
}

func requireClosed(t *testing.T, conn *gws.Conn, within time.Duration) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(within))
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			var ne net.Error
			require.False(t, errors.As(err, &ne) && ne.Timeout(), "socket still open after %s", within)
			return
		}
	}
}

func requireOpen(t *testing.T, conn *gws.Conn) {
	t.Helper()
	require.NoError(t, conn.WriteJSON(IncomingMessage{Type: MessageTypePing}))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg OutgoingMessage
	require.NoError(t, conn.ReadJSON(&msg))
	assert.Equal(t, MessageTypePong, msg.Type)
}

// requireNoEventBeforePong round-trips a ping; anything queued on conn earlier arrives first, so an event fails the test.
func requireNoEventBeforePong(t *testing.T, conn *gws.Conn) {
	t.Helper()
	require.NoError(t, conn.WriteJSON(IncomingMessage{Type: MessageTypePing}))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		var msg OutgoingMessage
		require.NoError(t, conn.ReadJSON(&msg))
		require.NotEqual(t, MessageTypeEvents, msg.Type, "agent received an event")
		if msg.Type == MessageTypePong {
			return
		}
	}
}

func (f *handlerFixture) dial(t *testing.T, token string) (*gws.Conn, *http.Response, error) {
	t.Helper()
	conn, resp, err := f.dialer.Dial("ws://test/ws?token="+token, nil)
	if conn != nil {
		t.Cleanup(func() { conn.Close() })
	}
	return conn, resp, err
}

func (f *handlerFixture) assertRejected(t *testing.T, token string) {
	t.Helper()
	_, resp, err := f.dial(t, token)
	require.ErrorIs(t, err, gws.ErrBadHandshake)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func (f *handlerFixture) signAgentToken(t *testing.T, device, iss, aud, typ string, exp time.Time) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.RegisteredClaims{
		Issuer: iss, Subject: device, Audience: jwt.ClaimStrings{aud},
		IssuedAt: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)), ExpiresAt: jwt.NewNumericDate(exp),
	})
	tok.Header["typ"] = typ
	s, err := tok.SignedString(f.priv)
	require.NoError(t, err)
	return s
}

func TestHandler_ShouldDeliverEventsToAgentToken_Integration(t *testing.T) {
	// given
	f := newHandlerFixture(t)
	tokens, err := f.agents.IssueTokens(ownerKey, "daemon")
	require.NoError(t, err)

	// when
	conn, _, err := f.dial(t, tokens.AccessToken)
	require.NoError(t, err)
	require.NoError(t, conn.WriteJSON(IncomingMessage{Type: MessageTypeSubscribe, ApplicationID: appA}))
	require.Eventually(t, func() bool {
		f.hub.mu.RLock()
		defer f.hub.mu.RUnlock()
		return len(f.hub.byApp[appA]) == 1
	}, 2*time.Second, 10*time.Millisecond)
	f.hub.BroadcastToApplication(appA, componentEvent("agent-event"))

	// then
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var got []string
	for len(got) == 0 {
		var msg EventsMessage
		require.NoError(t, conn.ReadJSON(&msg))
		for _, ev := range msg.Events {
			got = append(got, ev.ID)
		}
	}
	assert.Equal(t, []string{"agent-event"}, got)
}

func TestHandler_ShouldRejectRevokedAgentToken_Integration(t *testing.T) {
	// given
	f := newHandlerFixture(t)
	tokens, err := f.agents.IssueTokens(ownerKey, "daemon")
	require.NoError(t, err)
	require.NoError(t, f.users.RevokeDevice(tokens.DevicePublicKey, time.Now().Unix()))

	// when / then
	f.assertRejected(t, tokens.AccessToken)
}

func TestHandler_ShouldRejectAgentTokenWithWrongClaims_Integration(t *testing.T) {
	// given
	f := newHandlerFixture(t)
	tokens, err := f.agents.IssueTokens(ownerKey, "daemon")
	require.NoError(t, err)
	exp := time.Now().Add(time.Hour)
	d := tokens.DevicePublicKey

	// when / then
	f.assertRejected(t, f.signAgentToken(t, d, wsIssuer, wsIssuer+"/other", "at+jwt", exp))
	f.assertRejected(t, f.signAgentToken(t, d, "https://evil.test", wsIssuer+"/mcp", "at+jwt", exp))
	f.assertRejected(t, f.signAgentToken(t, d, wsIssuer, wsIssuer+"/mcp", "JWT", exp))
}

func TestHandler_ShouldRejectExpiredAgentToken_Integration(t *testing.T) {
	// given
	f := newHandlerFixture(t)
	tokens, err := f.agents.IssueTokens(ownerKey, "daemon")
	require.NoError(t, err)
	expired := f.signAgentToken(t, tokens.DevicePublicKey, wsIssuer, wsIssuer+"/mcp", "at+jwt", time.Now().Add(-time.Minute))

	// when / then
	f.assertRejected(t, expired)
}

func TestHandler_ShouldAcceptHumanJWT_Integration(t *testing.T) {
	// given
	f := newHandlerFixture(t)
	require.NoError(t, f.users.EnsureDevice(ownerKey, ownerKey, nil, time.Now().Unix()))
	jwtToken, _, err := f.userSv.GenerateJWT(&user.User{PublicKey: ownerKey, Username: "owner", Role: user.RoleUser}, ownerKey)
	require.NoError(t, err)

	// when
	conn, _, err := f.dial(t, jwtToken)

	// then
	require.NoError(t, err)
	var msg OutgoingMessage
	require.NoError(t, conn.ReadJSON(&msg))
	assert.Equal(t, MessageTypeConnected, msg.Type)
}

func TestHandler_ShouldRejectGarbageToken_Integration(t *testing.T) {
	// given
	f := newHandlerFixture(t)

	// when / then
	f.assertRejected(t, "not-a-token")
}

func TestHandler_ShouldRejectSubscribeOfNonOwnerAgentWhenAgentReadDisabled_Integration(t *testing.T) {
	// given
	f := newHandlerFixture(t)
	require.NoError(t, f.hub.appRepo.CreateMember(&application.Member{ID: "m1", ApplicationID: appA, Role: application.MemberRoleMember, PublicKey: memberKey}))
	require.NoError(t, f.hub.appRepo.SetAgentReadEnabled(appA, false))
	memberAgent, err := f.agents.IssueTokens(memberKey, "member-agent")
	require.NoError(t, err)
	ownerAgent, err := f.agents.IssueTokens(ownerKey, "owner-agent")
	require.NoError(t, err)
	memberConn := f.dialReady(t, memberAgent.AccessToken)
	ownerConn := f.dialReady(t, ownerAgent.AccessToken)

	// when
	require.NoError(t, memberConn.WriteJSON(IncomingMessage{Type: MessageTypeSubscribe, ApplicationID: appA}))
	require.NoError(t, ownerConn.WriteJSON(IncomingMessage{Type: MessageTypeSubscribe, ApplicationID: appA}))

	// then
	_ = memberConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var rejected OutgoingMessage
	require.NoError(t, memberConn.ReadJSON(&rejected))
	assert.Equal(t, MessageTypeError, rejected.Type)
	require.Eventually(t, func() bool {
		f.hub.mu.RLock()
		defer f.hub.mu.RUnlock()
		return len(f.hub.byApp[appA]) == 1 && f.hub.byApp[appA][0].user.PublicKey == ownerKey
	}, 2*time.Second, 10*time.Millisecond)
}

func TestHandler_ShouldDisconnectOnlyTargetedDevice_Integration(t *testing.T) {
	// given
	f := newHandlerFixture(t)
	agent, err := f.agents.IssueTokens(ownerKey, "daemon")
	require.NoError(t, err)
	human := f.dialReady(t, f.humanToken(t))
	agentConn := f.dialReady(t, agent.AccessToken)

	// when
	f.hub.Disconnect(ownerKey, agent.DevicePublicKey)

	// then
	requireClosed(t, agentConn, 2*time.Second)
	requireOpen(t, human)

	// and when the human device is disconnected
	agent2 := f.dialReady(t, agent.AccessToken)
	f.hub.Disconnect(ownerKey, ownerKey)

	// then
	requireClosed(t, human, 2*time.Second)
	requireOpen(t, agent2)
}

func TestHandler_ShouldRejectHumanDeviceInAgentToken_Integration(t *testing.T) {
	// given
	f := newHandlerFixture(t)
	require.NoError(t, f.users.EnsureDevice(ownerKey, ownerKey, nil, time.Now().Unix()))
	token := f.signAgentToken(t, ownerKey, wsIssuer, wsIssuer+"/mcp", "at+jwt", time.Now().Add(time.Hour))

	// when / then
	f.assertRejected(t, token)
}

func TestHandler_ShouldCloseAgentSocketAtTokenExpiry_Integration(t *testing.T) {
	// given
	f := newHandlerFixture(t)
	agent, err := f.agents.IssueTokens(ownerKey, "daemon")
	require.NoError(t, err)
	token := f.signAgentToken(t, agent.DevicePublicKey, wsIssuer, wsIssuer+"/mcp", "at+jwt", time.Now().Add(2*time.Second))
	conn := f.dialReady(t, token)
	requireOpen(t, conn)

	// when / then
	requireClosed(t, conn, 5*time.Second)
}

func TestHandler_ShouldRevokeDeviceAndCloseSocketOnRefreshTokenReuse_Integration(t *testing.T) {
	// given
	f := newHandlerFixture(t)
	f.agents.Disconnect = f.hub.Disconnect
	first, err := f.agents.IssueTokens(ownerKey, "daemon")
	require.NoError(t, err)
	_, err = f.agents.Refresh(first.RefreshToken)
	require.NoError(t, err)
	conn := f.dialReady(t, first.AccessToken)

	// when
	_, err = f.agents.Refresh(first.RefreshToken)

	// then
	require.ErrorIs(t, err, user.ErrInvalidRefreshToken)
	device, err := f.users.GetDevice(first.DevicePublicKey)
	require.NoError(t, err)
	assert.NotNil(t, device.RevokedAt)
	requireClosed(t, conn, 2*time.Second)
}

func TestHandler_ShouldNotDeliverUserBroadcastToAgent_Integration(t *testing.T) {
	// given
	f := newHandlerFixture(t)
	agent, err := f.agents.IssueTokens(ownerKey, "daemon")
	require.NoError(t, err)
	human := f.dialReady(t, f.humanToken(t))
	agentConn := f.dialReady(t, agent.AccessToken)

	// when
	f.hub.BroadcastToUser(ownerKey, componentEvent("user-event"))
	f.hub.BroadcastToUser(ownerKey, componentEvent("user-marker"))

	// then
	_ = human.SetReadDeadline(time.Now().Add(2 * time.Second))
	for _, id := range []string{"user-event", "user-marker"} {
		var got EventsMessage
		require.NoError(t, human.ReadJSON(&got))
		require.Len(t, got.Events, 1)
		assert.Equal(t, id, got.Events[0].ID)
	}
	// Run handles broadcasts in order, so the first one is fully fanned out once the marker has been delivered.
	requireNoEventBeforePong(t, agentConn)
}

func TestHandler_ShouldRejectAgentTokenWhenAgentsDisabled_Integration(t *testing.T) {
	// given
	f := newHandlerFixture(t)
	agent, err := f.agents.IssueTokens(ownerKey, "daemon")
	require.NoError(t, err)
	f.dialer = serveHandler(t, NewHandler(f.hub, f.userSv, nil))

	// when / then
	f.assertRejected(t, agent.AccessToken)
}

func TestHandler_ShouldCloseOpenAgentSocketWhenRevoked_Integration(t *testing.T) {
	// given
	f := newHandlerFixture(t)
	f.agents.Disconnect = f.hub.Disconnect
	agent, err := f.agents.IssueTokens(ownerKey, "daemon")
	require.NoError(t, err)
	conn := f.dialReady(t, agent.AccessToken)
	requireOpen(t, conn)

	// when
	require.NoError(t, f.agents.RevokeAgent(ownerKey, agent.DevicePublicKey))

	// then
	requireClosed(t, conn, 2*time.Second)
}

func TestHandler_ShouldCloseAgentSocketRevokedBetweenValidateAndRegister_Integration(t *testing.T) {
	// given
	f := newHandlerFixture(t)
	f.agents.Disconnect = f.hub.Disconnect
	agent, err := f.agents.IssueTokens(ownerKey, "daemon")
	require.NoError(t, err)
	h := NewHandler(f.hub, f.userSv, f.agents)
	h.beforeRegister = func() { require.NoError(t, f.agents.RevokeAgent(ownerKey, agent.DevicePublicKey)) }
	f.dialer = serveHandler(t, h)

	// when
	conn, _, err := f.dial(t, agent.AccessToken)
	require.NoError(t, err)

	// then
	requireClosed(t, conn, 2*time.Second)
	require.Eventually(t, func() bool { return clientCount(f.hub) == 0 }, 2*time.Second, 10*time.Millisecond)
}

func TestHandler_ShouldStopDeliveringToNonOwnerAgentWhenAgentReadSwitchedOff_Integration(t *testing.T) {
	// given
	f := newHandlerFixture(t)
	require.NoError(t, f.hub.appRepo.CreateMember(&application.Member{ID: "m1", ApplicationID: appA, Role: application.MemberRoleMember, PublicKey: memberKey}))
	memberAgent, err := f.agents.IssueTokens(memberKey, "member-agent")
	require.NoError(t, err)
	ownerAgent, err := f.agents.IssueTokens(ownerKey, "owner-agent")
	require.NoError(t, err)
	memberConn := f.dialReady(t, memberAgent.AccessToken)
	ownerConn := f.dialReady(t, ownerAgent.AccessToken)
	for _, c := range []*gws.Conn{memberConn, ownerConn} {
		require.NoError(t, c.WriteJSON(IncomingMessage{Type: MessageTypeSubscribe, ApplicationID: appA}))
	}
	require.Eventually(t, func() bool {
		f.hub.mu.RLock()
		defer f.hub.mu.RUnlock()
		return len(f.hub.byApp[appA]) == 2
	}, 2*time.Second, 10*time.Millisecond)
	appSvc := application.NewApplicationService(f.hub.appRepo, 0, "")
	appSvc.OnAgentReadOff = f.hub.EvictAgents

	// when
	require.NoError(t, appSvc.SetAgentRead(appA, &user.User{PublicKey: ownerKey}, false))
	f.hub.BroadcastToApplication(appA, componentEvent("after-off"))
	f.hub.BroadcastToApplication(appA, componentEvent("after-off-marker"))

	// then
	_ = ownerConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for _, id := range []string{"after-off", "after-off-marker"} {
		var got EventsMessage
		require.NoError(t, ownerConn.ReadJSON(&got))
		require.Len(t, got.Events, 1)
		assert.Equal(t, id, got.Events[0].ID)
	}
	f.hub.mu.RLock()
	assert.Equal(t, []string{ownerKey}, subscriberKeys(f.hub, appA))
	f.hub.mu.RUnlock()
	requireNoEventBeforePong(t, memberConn)
}

func subscriberKeys(h *Hub, appID string) []string {
	var keys []string
	for _, c := range h.byApp[appID] {
		keys = append(keys, c.user.PublicKey)
	}
	return keys
}
