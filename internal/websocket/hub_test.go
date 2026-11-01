package websocket

import (
	"testing"
	"time"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
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
