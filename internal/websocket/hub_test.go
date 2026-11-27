package websocket

import (
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	gws "github.com/fasthttp/websocket"
	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

const (
	appA      = "app-a"
	appB      = "app-b"
	ownerKey  = "owner-public-key-00000000"
	adminKey  = "admin-public-key-00000000"
	memberKey = "member-public-key-0000000"
	otherKey  = "other-public-key-00000000"
)

func addMember(repo *application.MemoryRepository, appID, publicKey string, role application.MemberRole) *application.Member {
	m := &application.Member{ID: appID + "/" + publicKey, ApplicationID: appID, Role: role, PublicKey: publicKey}
	_ = repo.CreateMember(m)
	return m
}

func connect(hub *Hub, publicKey string) *Client {
	c := NewClient(hub, nil, &user.User{PublicKey: publicKey})
	hub.registerClient(c)
	return c
}

func subscribe(c *Client, appID string) {
	c.handleMessage(&IncomingMessage{Type: MessageTypeSubscribe, ApplicationID: appID})
}

// broadcast runs one message through the same path Hub.Run takes, synchronously.
func broadcast(hub *Hub, appID string, ev *event.Event) {
	hub.BroadcastToApplication(appID, ev)
	select {
	case msg := <-hub.broadcast:
		hub.broadcastToApp(msg)
	default:
	}
}

func componentEvent(id string) *event.Event {
	return &event.Event{ID: id, Type: event.EventTypeComponentDataChanged, Data: map[string]interface{}{}}
}

func memberRemovedEvent(id, appID, publicKey string) *event.Event {
	return &event.Event{ID: id, Type: event.EventTypeMemberRemoved, Data: map[string]interface{}{
		"applicationId":   appID,
		"memberPublicKey": publicKey,
	}}
}

// drain returns the ids of delivered events and any error messages sent to c.
func drain(c *Client) (eventIDs []string, errs []string) {
	for {
		select {
		case msg := <-c.send:
			switch m := msg.(type) {
			case *EventsMessage:
				for _, ev := range m.Events {
					eventIDs = append(eventIDs, ev.ID)
				}
			case *OutgoingMessage:
				if m.Type == MessageTypeError {
					errs = append(errs, m.Error)
				}
			}
		default:
			return eventIDs, errs
		}
	}
}

func TestSubscribe_ShouldRejectNonMember(t *testing.T) {
	// given
	repo := application.NewMemoryRepository()
	addMember(repo, appA, ownerKey, application.MemberRoleOwner)
	hub := NewHub(repo)
	c := connect(hub, otherKey)

	// when
	subscribe(c, appA)
	broadcast(hub, appA, componentEvent("e1"))

	// then
	events, errs := drain(c)
	assert.Empty(t, events)
	assert.Len(t, errs, 1)
	assert.False(t, c.IsSubscribed(appA))
}

func TestSubscribe_ShouldRejectExpiredMember(t *testing.T) {
	// given
	repo := application.NewMemoryRepository()
	m := addMember(repo, appA, memberKey, application.MemberRoleMember)
	m.MembershipExpiresAt = expiresIn(-time.Minute)
	hub := NewHub(repo)
	c := connect(hub, memberKey)

	// when
	subscribe(c, appA)
	broadcast(hub, appA, componentEvent("e1"))

	// then
	events, errs := drain(c)
	assert.Empty(t, events)
	assert.Len(t, errs, 1)
}

func TestBroadcast_ShouldDeliverToOwnerAdminAndMember(t *testing.T) {
	// given
	repo := application.NewMemoryRepository()
	addMember(repo, appA, ownerKey, application.MemberRoleOwner)
	addMember(repo, appA, adminKey, application.MemberRoleAdmin)
	m := addMember(repo, appA, memberKey, application.MemberRoleMember)
	m.MembershipExpiresAt = expiresIn(time.Hour)
	hub := NewHub(repo)
	clients := []*Client{connect(hub, ownerKey), connect(hub, adminKey), connect(hub, memberKey)}
	for _, c := range clients {
		subscribe(c, appA)
	}

	// when
	broadcast(hub, appA, componentEvent("e1"))

	// then
	for _, c := range clients {
		events, errs := drain(c)
		assert.Equal(t, []string{"e1"}, events)
		assert.Empty(t, errs)
	}
}

func TestBroadcast_ShouldStopDeliveringToRemovedMember(t *testing.T) {
	// given
	repo := application.NewMemoryRepository()
	addMember(repo, appA, ownerKey, application.MemberRoleOwner)
	m := addMember(repo, appA, memberKey, application.MemberRoleMember)
	hub := NewHub(repo)
	owner := connect(hub, ownerKey)
	member := connect(hub, memberKey)
	subscribe(owner, appA)
	subscribe(member, appA)

	// when
	_ = repo.DeleteMember(m.ID)
	broadcast(hub, appA, memberRemovedEvent("removed", appA, memberKey))
	broadcast(hub, appA, componentEvent("after"))

	// then
	memberEvents, _ := drain(member)
	assert.Equal(t, []string{"removed"}, memberEvents)
	ownerEvents, _ := drain(owner)
	assert.Equal(t, []string{"removed", "after"}, ownerEvents)
}

func TestBroadcast_ShouldNotDeliverAnotherMembersRemovalToFormerMember(t *testing.T) {
	// given
	repo := application.NewMemoryRepository()
	addMember(repo, appA, ownerKey, application.MemberRoleOwner)
	former := addMember(repo, appA, memberKey, application.MemberRoleMember)
	other := addMember(repo, appA, otherKey, application.MemberRoleMember)
	hub := NewHub(repo)
	formerClient := connect(hub, memberKey)
	subscribe(formerClient, appA)
	_ = repo.DeleteMember(former.ID)

	// when
	_ = repo.DeleteMember(other.ID)
	broadcast(hub, appA, memberRemovedEvent("other-removed", appA, otherKey))

	// then
	events, _ := drain(formerClient)
	assert.Empty(t, events)
}

func TestBroadcast_ShouldStopDeliveringToExpiredMember(t *testing.T) {
	// given
	repo := application.NewMemoryRepository()
	m := addMember(repo, appA, memberKey, application.MemberRoleMember)
	m.MembershipExpiresAt = expiresIn(time.Hour)
	hub := NewHub(repo)
	c := connect(hub, memberKey)
	subscribe(c, appA)

	// when
	m.MembershipExpiresAt = expiresIn(-time.Second)
	broadcast(hub, appA, componentEvent("after-expiry"))

	// then
	events, _ := drain(c)
	assert.Empty(t, events)
}

func TestBroadcast_ShouldResumeForReAddedMember(t *testing.T) {
	// given
	repo := application.NewMemoryRepository()
	m := addMember(repo, appA, memberKey, application.MemberRoleMember)
	hub := NewHub(repo)
	c := connect(hub, memberKey)
	subscribe(c, appA)
	_ = repo.DeleteMember(m.ID)
	broadcast(hub, appA, componentEvent("while-removed"))

	// when
	addMember(repo, appA, memberKey, application.MemberRoleMember)
	broadcast(hub, appA, componentEvent("re-added"))

	// then
	events, _ := drain(c)
	assert.Equal(t, []string{"re-added"}, events)
}

func TestBroadcast_ShouldKeepOtherAppWhenRemovedFromOne(t *testing.T) {
	// given
	repo := application.NewMemoryRepository()
	inA := addMember(repo, appA, memberKey, application.MemberRoleMember)
	addMember(repo, appB, memberKey, application.MemberRoleMember)
	hub := NewHub(repo)
	c := connect(hub, memberKey)
	subscribe(c, appA)
	subscribe(c, appB)

	// when
	_ = repo.DeleteMember(inA.ID)
	broadcast(hub, appA, componentEvent("a"))
	broadcast(hub, appB, componentEvent("b"))

	// then
	events, _ := drain(c)
	assert.Equal(t, []string{"b"}, events)
}

func expiresIn(d time.Duration) *int64 {
	at := time.Now().Add(d).Unix()
	return &at
}

type wsFixture struct {
	hub  *Hub
	dial func(t *testing.T, account, device string) *gws.Conn
}

func newWSFixture(t *testing.T) *wsFixture {
	t.Helper()
	return newWSFixtureWith(t, true)
}

func newWSFixtureWith(t *testing.T, run bool) *wsFixture {
	t.Helper()
	hub := NewHub(application.NewMemoryRepository())
	if run {
		go hub.Run()
	}
	ln := fasthttputil.NewInmemoryListener()
	srv := &fasthttp.Server{KeepHijackedConns: true, Handler: func(ctx *fasthttp.RequestCtx) {
		u := &user.User{
			PublicKey:       string(ctx.QueryArgs().Peek("account")),
			DevicePublicKey: string(ctx.QueryArgs().Peek("device")),
		}
		_ = upgrader.Upgrade(ctx, func(conn *gws.Conn) {
			client := NewClient(hub, conn, u)
			hub.Register(client)
			go client.WritePump()
			client.ReadPump()
		})
	}}
	go srv.Serve(ln)
	t.Cleanup(func() { _ = srv.Shutdown(); _ = ln.Close() })

	d := gws.Dialer{NetDial: func(_, _ string) (net.Conn, error) { return ln.Dial() }}
	return &wsFixture{hub: hub, dial: func(t *testing.T, account, device string) *gws.Conn {
		conn, _, err := d.Dial("ws://test/ws?account="+account+"&device="+device, nil)
		require.NoError(t, err)
		t.Cleanup(func() { conn.Close() })
		return conn
	}}
}

func readOutcome(conn *gws.Conn, wait time.Duration) (timedOut bool) {
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	_, _, err := conn.ReadMessage()
	var te interface{ Timeout() bool }
	return errors.As(err, &te) && te.Timeout()
}

func clientCount(hub *Hub) int {
	n, _ := hub.GetStats()
	return n
}

func TestDisconnect_ShouldCloseOnlyMatchingDevice(t *testing.T) {
	// given
	f := newWSFixture(t)
	a1 := f.dial(t, ownerKey, "device-1-000000000000")
	a2 := f.dial(t, ownerKey, "device-2-000000000000")
	b1 := f.dial(t, otherKey, "device-1-000000000000")
	assert.Eventually(t, func() bool { return clientCount(f.hub) == 3 }, 2*time.Second, 10*time.Millisecond)

	// when
	f.hub.Disconnect(ownerKey, "device-1-000000000000")

	// then
	assert.False(t, readOutcome(a1, 2*time.Second))
	assert.True(t, readOutcome(a2, 200*time.Millisecond))
	assert.True(t, readOutcome(b1, 200*time.Millisecond))
	assert.Eventually(t, func() bool { return clientCount(f.hub) == 2 }, 2*time.Second, 10*time.Millisecond)
}

func TestDisconnect_ShouldCloseAllAccountSocketsWhenDeviceEmpty(t *testing.T) {
	// given
	f := newWSFixture(t)
	a1 := f.dial(t, ownerKey, "device-1-000000000000")
	a2 := f.dial(t, ownerKey, "device-2-000000000000")
	b1 := f.dial(t, otherKey, "device-1-000000000000")
	assert.Eventually(t, func() bool { return clientCount(f.hub) == 3 }, 2*time.Second, 10*time.Millisecond)

	// when
	f.hub.Disconnect(ownerKey, "")

	// then
	assert.False(t, readOutcome(a1, 2*time.Second))
	assert.False(t, readOutcome(a2, 2*time.Second))
	assert.True(t, readOutcome(b1, 200*time.Millisecond))
	assert.Eventually(t, func() bool { return clientCount(f.hub) == 1 }, 2*time.Second, 10*time.Millisecond)
}

func connectDevice(hub *Hub, account, device string) *Client {
	c := NewClient(hub, nil, &user.User{PublicKey: account, DevicePublicKey: device})
	hub.registerClient(c)
	return c
}

func TestHub_SendPush_ShouldReachOnlyMatchingDevice(t *testing.T) {
	// given
	hub := NewHub(application.NewMemoryRepository())
	target := connectDevice(hub, ownerKey, "device-1")
	sibling := connectDevice(hub, ownerKey, "device-2")
	stranger := connectDevice(hub, otherKey, "device-1")

	// when
	ok := hub.SendPush(ownerKey, "device-1", []byte(`{"v":2,"title":"t"}`))

	// then
	assert.True(t, ok)
	assert.Len(t, target.send, 1)
	assert.Empty(t, sibling.send)
	assert.Empty(t, stranger.send)
	raw, err := json.Marshal(<-target.send)
	require.NoError(t, err)
	assert.JSONEq(t, `{"type":"push","payload":{"v":2,"title":"t"}}`, string(raw))
}

func TestHub_SendPush_ShouldReturnFalseWhenDeviceOffline(t *testing.T) {
	// given
	hub := NewHub(application.NewMemoryRepository())
	connectDevice(hub, ownerKey, "device-2")

	// when
	ok := hub.SendPush(ownerKey, "device-1", []byte(`{}`))

	// then
	assert.False(t, ok)
}

func TestHub_SendPush_ShouldReturnFalseWhenBufferFull(t *testing.T) {
	// given
	hub := NewHub(application.NewMemoryRepository())
	c := connectDevice(hub, ownerKey, "device-1")
	for i := 0; i < cap(c.send); i++ {
		c.send <- &PushMessage{}
	}

	// when
	ok := hub.SendPush(ownerKey, "device-1", []byte(`{}`))

	// then
	assert.False(t, ok)
	assert.Len(t, c.send, cap(c.send))
}

func TestHub_Disconnect_ShouldNotBlockWhenRunIsNotStarted(t *testing.T) {
	// given
	hub := NewHub(application.NewMemoryRepository())

	// when
	done := make(chan struct{})
	go func() {
		for range 3 * cap(hub.disconnect) {
			hub.Disconnect(ownerKey, "device")
		}
		close(done)
	}()

	// then
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Disconnect blocked without a running hub")
	}
}

func TestHub_EvictAgents_ShouldDropOnlyNonOwnerAgentSubscriptions(t *testing.T) {
	// given
	hub := NewHub(application.NewMemoryRepository())
	subscribed := func(u *user.User) *Client {
		c := NewClient(hub, nil, u)
		c.subscriptions[appA] = true
		hub.Subscribe(c, appA)
		return c
	}
	memberAgent := subscribed(&user.User{PublicKey: memberKey, Agent: true})
	ownerAgent := subscribed(&user.User{PublicKey: ownerKey, Agent: true})
	memberHuman := subscribed(&user.User{PublicKey: memberKey})

	// when
	hub.EvictAgents(appA, ownerKey)

	// then
	assert.False(t, memberAgent.IsSubscribed(appA))
	assert.True(t, ownerAgent.IsSubscribed(appA))
	assert.True(t, memberHuman.IsSubscribed(appA))
	assert.ElementsMatch(t, []*Client{ownerAgent, memberHuman}, hub.byApp[appA])
	_, memberAgentErrs := drain(memberAgent)
	assert.Equal(t, []string{"agent access to this application was turned off"}, memberAgentErrs)
	_, ownerAgentErrs := drain(ownerAgent)
	_, memberHumanErrs := drain(memberHuman)
	assert.Empty(t, ownerAgentErrs)
	assert.Empty(t, memberHumanErrs)
}

// flipOnFirstCheck turns agent read off and evicts between the subscribe check and the hub insert.
type flipOnFirstCheck struct {
	*application.MemoryRepository
	hub   *Hub
	calls int
}

func (r *flipOnFirstCheck) GetAgentAccess(appID string) (bool, string, error) {
	enabled, owner, err := r.MemoryRepository.GetAgentAccess(appID)
	r.calls++
	if r.calls == 1 {
		_ = r.SetAgentReadEnabled(appID, false)
		r.hub.EvictAgents(appID, owner)
	}
	return enabled, owner, err
}

func TestSubscribe_ShouldNotLeaveAgentSubscribedWhenAgentReadSwitchedOffAfterCheck(t *testing.T) {
	// given
	mem := application.NewMemoryRepository()
	require.NoError(t, mem.RegisterApplication(&application.Application{ID: appA, Name: appA}))
	addMember(mem, appA, ownerKey, application.MemberRoleOwner)
	addMember(mem, appA, memberKey, application.MemberRoleMember)
	repo := &flipOnFirstCheck{MemoryRepository: mem}
	hub := NewHub(repo)
	repo.hub = hub
	agent := NewClient(hub, nil, &user.User{PublicKey: memberKey, Agent: true})
	hub.registerClient(agent)

	// when
	subscribe(agent, appA)

	// then
	assert.False(t, agent.IsSubscribed(appA))
	assert.Empty(t, hub.byApp[appA])
	_, errs := drain(agent)
	assert.Equal(t, []string{"agent access is disabled for this application"}, errs)
}

func TestHub_Register_ShouldInsertClientBeforeReturning(t *testing.T) {
	// given
	hub := NewHub(application.NewMemoryRepository())

	// when
	hub.Register(NewClient(hub, nil, &user.User{PublicKey: ownerKey}))

	// then
	assert.Equal(t, 1, clientCount(hub))
}

func TestHub_Disconnect_ShouldExecuteEveryRequestWhenQueueIsFull(t *testing.T) {
	// given
	f := newWSFixtureWith(t, false)
	devices := []string{"device-1-000000000000", "device-2-000000000000", "device-3-000000000000"}
	conns := make([]*gws.Conn, len(devices))
	for i, d := range devices {
		conns[i] = f.dial(t, ownerKey, d)
	}
	require.Eventually(t, func() bool { return clientCount(f.hub) == len(devices) }, 2*time.Second, 10*time.Millisecond)
	for range cap(f.hub.disconnect) {
		f.hub.disconnect <- disconnectReq{account: otherKey}
	}

	// when
	for _, d := range devices {
		f.hub.Disconnect(ownerKey, d)
	}

	// then
	for _, c := range conns {
		assert.False(t, readOutcome(c, 2*time.Second))
	}
}
