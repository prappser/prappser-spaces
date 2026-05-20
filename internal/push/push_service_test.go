package push

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/stretchr/testify/assert"
)

// mockPushRepository is a hand-written in-memory repository for unit tests.
type mockPushRepository struct {
	mu            sync.Mutex
	subscriptions map[string]*Subscription
	spaceVapid    *SpaceVapid
	markSuccessCalls []struct {
		id string
		ts int64
	}
	incrementFailureCalls []string
	deleteSubscriptionCalls []struct {
		id            string
		userPublicKey string
	}
}

func newMockPushRepository() *mockPushRepository {
	return &mockPushRepository{
		subscriptions: make(map[string]*Subscription),
	}
}

func (m *mockPushRepository) UpsertSpaceVapid(v *SpaceVapid) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.spaceVapid = v
	return nil
}

func (m *mockPushRepository) GetSpaceVapid() (*SpaceVapid, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.spaceVapid, nil
}

func (m *mockPushRepository) CreateSubscription(s *Subscription) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subscriptions[s.ID] = s
	return nil
}

func (m *mockPushRepository) UpdateSubscription(s *Subscription) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subscriptions[s.ID] = s
	return nil
}

func (m *mockPushRepository) DeleteSubscription(id, userPublicKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.subscriptions[id]
	if !ok || s.UserPublicKey != userPublicKey {
		return fmt.Errorf("subscription not found")
	}
	m.deleteSubscriptionCalls = append(m.deleteSubscriptionCalls, struct {
		id            string
		userPublicKey string
	}{id, userPublicKey})
	delete(m.subscriptions, id)
	return nil
}

func (m *mockPushRepository) GetSubscriptionsForUsers(userPublicKeys []string) ([]*Subscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keySet := make(map[string]struct{}, len(userPublicKeys))
	for _, pk := range userPublicKeys {
		keySet[pk] = struct{}{}
	}
	var result []*Subscription
	for _, s := range m.subscriptions {
		if _, ok := keySet[s.UserPublicKey]; ok {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *mockPushRepository) GetSubscriptionByID(id, userPublicKey string) (*Subscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.subscriptions[id]
	if !ok || s.UserPublicKey != userPublicKey {
		return nil, nil
	}
	return s, nil
}

func (m *mockPushRepository) MarkSuccess(id string, ts int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.markSuccessCalls = append(m.markSuccessCalls, struct {
		id string
		ts int64
	}{id, ts})
	return nil
}

func (m *mockPushRepository) IncrementFailure(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.incrementFailureCalls = append(m.incrementFailureCalls, id)
	return nil
}

func newMockSpaceVapidService(pub, priv string) *SpaceVapidService {
	return &SpaceVapidService{
		publicKey:  pub,
		privateKey: priv,
	}
}

// mockWebpushSender is a hand-written mock sender for unit tests.
type mockWebpushSender struct {
	mu     sync.Mutex
	calls  []sendCall
	result SendResult
}

type sendCall struct {
	sub     *Subscription
	vapid   *SpaceVapid
	payload []byte
}

func newMockWebpushSender(result SendResult) *mockWebpushSender {
	return &mockWebpushSender{result: result}
}

func (m *mockWebpushSender) Send(sub *Subscription, vapid *SpaceVapid, payloadJSON []byte) SendResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, sendCall{sub: sub, vapid: vapid, payload: payloadJSON})
	return m.result
}

func (m *mockWebpushSender) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

// waitForCalls blocks until at least n Send calls have been recorded or the deadline passes.
func (m *mockWebpushSender) waitForCalls(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if m.callCount() >= n {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// helper to build a test event
func makeEvent(eventType event.EventType, creatorKey string, appID string) *event.Event {
	return &event.Event{
		ID:               "evt-1",
		Type:             eventType,
		CreatorPublicKey: creatorKey,
		ApplicationID:    appID,
		CreatedAt:        time.Now().Unix(),
		Data:             map[string]interface{}{"applicationId": appID},
	}
}

func TestPushService_Push_ShouldSendForMemberAddedEvent(t *testing.T) {
	// given
	repo := newMockPushRepository()
	sender := newMockWebpushSender(SendResult{StatusCode: 201})
	vapidSvc := newMockSpaceVapidService("pub", "priv")
	svc := NewPushService(repo, sender, vapidSvc)

	repo.subscriptions["sub-1"] = &Subscription{
		ID:                  "sub-1",
		UserPublicKey:       "user-pk-1",
		Endpoint:            "https://push.example.com/1",
		P256dh:              "p256dh-value",
		Auth:                "auth-value",
		MutedApplicationIDs: []string{},
	}

	ev := makeEvent(event.EventTypeMemberAdded, "creator-pk", "app-1")

	// when
	svc.Push(ev, "", "", []string{"user-pk-1"})

	// then
	assert.True(t, sender.waitForCalls(1, 2*time.Second), "expected 1 Send call")
	assert.Equal(t, 1, sender.callCount())
	assert.Len(t, repo.markSuccessCalls, 1)
	assert.Equal(t, "sub-1", repo.markSuccessCalls[0].id)
}

func TestPushService_Push_ShouldSkipWhenApplicationMuted(t *testing.T) {
	// given
	repo := newMockPushRepository()
	sender := newMockWebpushSender(SendResult{StatusCode: 201})
	vapidSvc := newMockSpaceVapidService("pub", "priv")
	svc := NewPushService(repo, sender, vapidSvc)

	repo.subscriptions["sub-1"] = &Subscription{
		ID:                  "sub-1",
		UserPublicKey:       "user-pk-1",
		Endpoint:            "https://push.example.com/1",
		P256dh:              "p256dh-value",
		Auth:                "auth-value",
		MutedApplicationIDs: []string{"app-1"},
	}

	ev := makeEvent(event.EventTypeMemberAdded, "creator-pk", "app-1")

	// when
	svc.Push(ev, "", "", []string{"user-pk-1"})

	// then: no send because app-1 is muted
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 0, sender.callCount())
}

func TestPushService_Push_ShouldSendWhenDifferentApplicationMuted(t *testing.T) {
	// given
	repo := newMockPushRepository()
	sender := newMockWebpushSender(SendResult{StatusCode: 201})
	vapidSvc := newMockSpaceVapidService("pub", "priv")
	svc := NewPushService(repo, sender, vapidSvc)

	repo.subscriptions["sub-1"] = &Subscription{
		ID:                  "sub-1",
		UserPublicKey:       "user-pk-1",
		Endpoint:            "https://push.example.com/1",
		P256dh:              "p256dh-value",
		Auth:                "auth-value",
		MutedApplicationIDs: []string{"app-2"},
	}

	ev := makeEvent(event.EventTypeMemberAdded, "creator-pk", "app-1")

	// when
	svc.Push(ev, "", "", []string{"user-pk-1"})

	// then: send proceeds because app-1 is not in muted list (only app-2 is)
	assert.True(t, sender.waitForCalls(1, 2*time.Second), "expected 1 Send call")
	assert.Equal(t, 1, sender.callCount())
}

func TestPushService_Push_ShouldDeleteSubscriptionOn410(t *testing.T) {
	// given
	repo := newMockPushRepository()
	sender := newMockWebpushSender(SendResult{StatusCode: 410})
	vapidSvc := newMockSpaceVapidService("pub", "priv")
	svc := NewPushService(repo, sender, vapidSvc)

	repo.subscriptions["sub-1"] = &Subscription{
		ID:                  "sub-1",
		UserPublicKey:       "user-pk-1",
		Endpoint:            "https://push.example.com/1",
		P256dh:              "p256dh-value",
		Auth:                "auth-value",
		MutedApplicationIDs: []string{},
	}

	ev := makeEvent(event.EventTypeMemberAdded, "creator-pk", "app-1")

	// when
	svc.Push(ev, "", "", []string{"user-pk-1"})

	// then: sender called and subscription deleted
	assert.True(t, sender.waitForCalls(1, 2*time.Second), "expected 1 Send call")
	repo.mu.Lock()
	deleteCalls := repo.deleteSubscriptionCalls
	repo.mu.Unlock()
	assert.Len(t, deleteCalls, 1)
	assert.Equal(t, "sub-1", deleteCalls[0].id)
}

func TestPushService_Push_ShouldIncrementFailureOn429(t *testing.T) {
	// given
	repo := newMockPushRepository()
	sender := newMockWebpushSender(SendResult{StatusCode: 429})
	vapidSvc := newMockSpaceVapidService("pub", "priv")
	svc := NewPushService(repo, sender, vapidSvc)

	repo.subscriptions["sub-1"] = &Subscription{
		ID:                  "sub-1",
		UserPublicKey:       "user-pk-1",
		Endpoint:            "https://push.example.com/1",
		P256dh:              "p256dh-value",
		Auth:                "auth-value",
		MutedApplicationIDs: []string{},
	}

	ev := makeEvent(event.EventTypeMemberAdded, "creator-pk", "app-1")

	// when
	svc.Push(ev, "", "", []string{"user-pk-1"})

	// then: failure incremented, subscription NOT deleted
	assert.True(t, sender.waitForCalls(1, 2*time.Second), "expected 1 Send call")
	repo.mu.Lock()
	failureCalls := repo.incrementFailureCalls
	deleteCalls := repo.deleteSubscriptionCalls
	repo.mu.Unlock()
	assert.Len(t, failureCalls, 1)
	assert.Equal(t, "sub-1", failureCalls[0])
	assert.Len(t, deleteCalls, 0, "subscription must not be deleted on 429")
}

func TestPushService_Push_ShouldSkipWhenEventTypeHasNoCategory(t *testing.T) {
	// given
	repo := newMockPushRepository()
	sender := newMockWebpushSender(SendResult{StatusCode: 201})
	vapidSvc := newMockSpaceVapidService("pub", "priv")
	svc := NewPushService(repo, sender, vapidSvc)

	repo.subscriptions["sub-1"] = &Subscription{
		ID:                  "sub-1",
		UserPublicKey:       "user-pk-1",
		Endpoint:            "https://push.example.com/1",
		P256dh:              "p256dh-value",
		Auth:                "auth-value",
		MutedApplicationIDs: []string{},
	}

	// application_created has no push category - CategoryForEventType returns ("", false)
	ev := makeEvent(event.EventTypeApplicationCreated, "creator-pk", "app-1")

	// when
	svc.Push(ev, "", "", []string{"user-pk-1"})

	// then: sender not called because the event type has no push story
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 0, sender.callCount())
}

func TestPushService_Push_ShouldUseSpaceVapidForAllRecipients(t *testing.T) {
	// given
	repo := newMockPushRepository()
	sender := newMockWebpushSender(SendResult{StatusCode: 201})
	vapidSvc := newMockSpaceVapidService("space-pub-key", "space-priv-key")
	svc := NewPushService(repo, sender, vapidSvc)

	repo.subscriptions["sub-1"] = &Subscription{
		ID:                  "sub-1",
		UserPublicKey:       "user-pk-1",
		Endpoint:            "https://push.example.com/1",
		P256dh:              "p256dh-1",
		Auth:                "auth-1",
		MutedApplicationIDs: []string{},
	}
	repo.subscriptions["sub-2"] = &Subscription{
		ID:                  "sub-2",
		UserPublicKey:       "user-pk-2",
		Endpoint:            "https://push.example.com/2",
		P256dh:              "p256dh-2",
		Auth:                "auth-2",
		MutedApplicationIDs: []string{},
	}

	ev := makeEvent(event.EventTypeMemberAdded, "creator-pk", "app-1")

	// when
	svc.Push(ev, "", "", []string{"user-pk-1", "user-pk-2"})

	// then: both deliveries used the same space VAPID keys
	assert.True(t, sender.waitForCalls(2, 2*time.Second), "expected 2 Send calls")
	sender.mu.Lock()
	calls := sender.calls
	sender.mu.Unlock()
	assert.Len(t, calls, 2)
	for _, c := range calls {
		assert.Equal(t, "space-pub-key", c.vapid.VapidPublicKey)
		assert.Equal(t, "space-priv-key", c.vapid.VapidPrivateKey)
	}
}
