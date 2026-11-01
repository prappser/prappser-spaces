//go:build integration

package websocket

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/testdb"
	"github.com/stretchr/testify/assert"
)

func newIntegrationHub(t *testing.T) (*sql.DB, *application.Repository, *Hub) {
	t.Helper()
	db := testdb.Connect(t, "websocket")
	t.Cleanup(func() { db.Close() })
	for _, key := range []string{ownerKey, adminKey, memberKey, otherKey} {
		testdb.InsertTestUser(t, db, key)
	}
	repo := application.NewRepository(db)
	return db, repo, NewHub(repo)
}

func registerApp(t *testing.T, repo *application.Repository, appID string, members ...application.Member) {
	t.Helper()
	now := time.Now().Unix()
	err := repo.RegisterApplication(&application.Application{ID: appID, Name: appID, CreatedAt: now, UpdatedAt: now, Members: members})
	assert.NoError(t, err)
}

func integrationMember(appID, publicKey string, role application.MemberRole, expiresAt *int64) application.Member {
	return application.Member{ID: appID + "/" + publicKey, ApplicationID: appID, Role: role, PublicKey: publicKey, MembershipExpiresAt: expiresAt}
}

// flushApp runs queued app broadcasts and discards the user-channel fan-out so
// only the app channel is asserted.
func flushApp(hub *Hub) {
	for {
		select {
		case msg := <-hub.broadcast:
			hub.broadcastToApp(msg)
		case <-hub.userBroadcast:
		default:
			return
		}
	}
}

func drainTypes(c *Client) (types []event.EventType) {
	for {
		select {
		case msg := <-c.send:
			if m, ok := msg.(*EventsMessage); ok {
				for _, ev := range m.Events {
					types = append(types, ev.Type)
				}
			}
		default:
			return types
		}
	}
}

func TestBroadcast_ShouldStopDeliveringToExpiredMember_Integration(t *testing.T) {
	// given
	db, repo, hub := newIntegrationHub(t)
	inOneHour := expiresIn(time.Hour)
	registerApp(t, repo, appA,
		integrationMember(appA, ownerKey, application.MemberRoleOwner, nil),
		integrationMember(appA, memberKey, application.MemberRoleMember, inOneHour))
	owner := connect(hub, ownerKey)
	member := connect(hub, memberKey)
	subscribe(owner, appA)
	subscribe(member, appA)
	_, ownerErrs := drain(owner)
	_, memberErrs := drain(member)
	assert.Empty(t, ownerErrs)
	assert.Empty(t, memberErrs)

	// when
	_, err := db.Exec("UPDATE members SET membership_expires_at = $1 WHERE application_id = $2 AND public_key = $3",
		time.Now().Add(-time.Hour).Unix(), appA, memberKey)
	assert.NoError(t, err)
	broadcast(hub, appA, componentEvent("after-expiry"))

	// then
	ownerEvents, _ := drain(owner)
	assert.Equal(t, []string{"after-expiry"}, ownerEvents)
	memberEvents, _ := drain(member)
	assert.Empty(t, memberEvents)
	fresh := connect(hub, memberKey)
	subscribe(fresh, appA)
	_, freshErrs := drain(fresh)
	assert.Len(t, freshErrs, 1)
	assert.False(t, fresh.IsSubscribed(appA))
}

func TestProduceEvent_ApplicationDeleted_ShouldReachMembers_Integration(t *testing.T) {
	// given
	db, repo, hub := newIntegrationHub(t)
	registerApp(t, repo, appA,
		integrationMember(appA, ownerKey, application.MemberRoleOwner, nil),
		integrationMember(appA, memberKey, application.MemberRoleMember, nil))
	owner := connect(hub, ownerKey)
	member := connect(hub, memberKey)
	subscribe(owner, appA)
	subscribe(member, appA)
	svc := event.NewEventService(event.NewEventRepository(db), repo, hub, nil)

	// when
	_, err := svc.ProduceEvent(context.Background(), &event.Event{
		ID:               "deleted-event-1",
		Type:             event.EventTypeApplicationDeleted,
		CreatorPublicKey: ownerKey,
		Version:          1,
		Data:             map[string]interface{}{"version": 1, "applicationId": appA, "deletedAt": time.Now().UnixMilli()},
	})
	flushApp(hub)

	// then
	assert.NoError(t, err)
	live, err := repo.IsApplicationLive(appA)
	assert.NoError(t, err)
	assert.False(t, live)
	ownerEvents, _ := drain(owner)
	memberEvents, _ := drain(member)
	assert.Equal(t, []string{"deleted-event-1"}, ownerEvents)
	assert.Equal(t, []string{"deleted-event-1"}, memberEvents)
}

func TestProduceApplicationMoved_ShouldReachMembers_Integration(t *testing.T) {
	// given
	db, repo, hub := newIntegrationHub(t)
	registerApp(t, repo, appA,
		integrationMember(appA, ownerKey, application.MemberRoleOwner, nil),
		integrationMember(appA, memberKey, application.MemberRoleMember, nil))
	owner := connect(hub, ownerKey)
	member := connect(hub, memberKey)
	subscribe(owner, appA)
	subscribe(member, appA)
	svc := event.NewEventService(event.NewEventRepository(db), repo, hub, nil)
	rows, err := repo.StartMove(appA, "https://target.example")
	assert.NoError(t, err)
	assert.EqualValues(t, 1, rows)
	assert.NoError(t, repo.CompleteMove(appA, "https://target.example", "invite-token", time.Now().Unix()))

	// when
	err = svc.ProduceApplicationMoved(context.Background(), appA, ownerKey, "https://target.example", "invite-token")
	flushApp(hub)

	// then
	assert.NoError(t, err)
	assert.Equal(t, []event.EventType{event.EventTypeApplicationMoved}, drainTypes(owner))
	assert.Equal(t, []event.EventType{event.EventTypeApplicationMoved}, drainTypes(member))
}

func TestProduceEvent_MemberRemoved_ShouldReachLeavingMemberThenStop_Integration(t *testing.T) {
	// given
	db, repo, hub := newIntegrationHub(t)
	registerApp(t, repo, appA,
		integrationMember(appA, ownerKey, application.MemberRoleOwner, nil),
		integrationMember(appA, memberKey, application.MemberRoleMember, nil))
	owner := connect(hub, ownerKey)
	member := connect(hub, memberKey)
	subscribe(owner, appA)
	subscribe(member, appA)
	svc := event.NewEventService(event.NewEventRepository(db), repo, hub, nil)

	// when
	_, err := svc.ProduceEvent(context.Background(), &event.Event{
		ID:               "removed-event-1",
		Type:             event.EventTypeMemberRemoved,
		CreatorPublicKey: memberKey,
		Version:          1,
		Data:             map[string]interface{}{"version": 1, "applicationId": appA, "memberPublicKey": memberKey, "reason": "left"},
	})
	flushApp(hub)
	broadcast(hub, appA, componentEvent("after"))

	// then
	assert.NoError(t, err)
	isMember, err := repo.IsMember(appA, memberKey)
	assert.NoError(t, err)
	assert.False(t, isMember)
	memberEvents, _ := drain(member)
	ownerEvents, _ := drain(owner)
	assert.Equal(t, []string{"removed-event-1"}, memberEvents)
	assert.Equal(t, []string{"removed-event-1", "after"}, ownerEvents)
}
