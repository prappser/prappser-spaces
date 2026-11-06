package push

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/stretchr/testify/assert"
)

// mockPushRepository is a hand-written in-memory repository for unit tests.
type mockPushRepository struct {
	mu               sync.Mutex
	subscriptions    map[string]*Subscription
	spaceVapid       *SpaceVapid
	markSuccessCalls []struct {
		id string
		ts int64
	}
	incrementFailureCalls   []string
	deleteSubscriptionCalls []struct {
		id              string
		devicePublicKey string
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

func (m *mockPushRepository) DeleteSubscription(id, devicePublicKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.subscriptions[id]
	if !ok || s.DevicePublicKey != devicePublicKey {
		return fmt.Errorf("subscription not found")
	}
	m.deleteSubscriptionCalls = append(m.deleteSubscriptionCalls, struct {
		id              string
		devicePublicKey string
	}{id, devicePublicKey})
	delete(m.subscriptions, id)
	return nil
}

// GetSubscriptionsForUsers is a simplified fake: it doesn't model the
// user_devices join the real repository uses, so tests reuse the same
// string as both a subscription's device key and the "account" key passed
// in here (mirroring device #1 == account key).
func (m *mockPushRepository) GetSubscriptionsForUsers(userPublicKeys []string) ([]*Subscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keySet := make(map[string]struct{}, len(userPublicKeys))
	for _, pk := range userPublicKeys {
		keySet[pk] = struct{}{}
	}
	var result []*Subscription
	for _, s := range m.subscriptions {
		if _, ok := keySet[s.DevicePublicKey]; ok {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *mockPushRepository) GetSubscriptionByID(id, devicePublicKey string) (*Subscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.subscriptions[id]
	if !ok || s.DevicePublicKey != devicePublicKey {
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
	opts    SendOptions
}

func newMockWebpushSender(result SendResult) *mockWebpushSender {
	return &mockWebpushSender{result: result}
}

func (m *mockWebpushSender) Send(sub *Subscription, vapid *SpaceVapid, payloadJSON []byte, opts SendOptions) SendResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, sendCall{sub: sub, vapid: vapid, payload: payloadJSON, opts: opts})
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
	svc := NewPushService(repo, sender, vapidSvc, nil)

	repo.subscriptions["sub-1"] = &Subscription{
		ID:                  "sub-1",
		DevicePublicKey:     "user-pk-1",
		Endpoint:            "https://push.example.com/1",
		P256dh:              "p256dh-value",
		Auth:                "auth-value",
		MutedApplicationIDs: []string{},
	}

	ev := makeEvent(event.EventTypeMemberAdded, "creator-pk", "app-1")

	// when
	svc.Push(ev, nil, "", false, []string{"user-pk-1"})

	// then
	assert.True(t, sender.waitForCalls(1, 2*time.Second), "expected 1 Send call")
	assert.Equal(t, 1, sender.callCount())
	assert.Eventually(t, func() bool {
		repo.mu.Lock()
		defer repo.mu.Unlock()
		return len(repo.markSuccessCalls) == 1 && repo.markSuccessCalls[0].id == "sub-1"
	}, 2*time.Second, 5*time.Millisecond, "expected MarkSuccess for sub-1")
}

func TestPushService_Push_ShouldSkipWhenApplicationMuted(t *testing.T) {
	// given
	repo := newMockPushRepository()
	sender := newMockWebpushSender(SendResult{StatusCode: 201})
	vapidSvc := newMockSpaceVapidService("pub", "priv")
	svc := NewPushService(repo, sender, vapidSvc, nil)

	repo.subscriptions["sub-1"] = &Subscription{
		ID:                  "sub-1",
		DevicePublicKey:     "user-pk-1",
		Endpoint:            "https://push.example.com/1",
		P256dh:              "p256dh-value",
		Auth:                "auth-value",
		MutedApplicationIDs: []string{"app-1"},
	}

	ev := makeEvent(event.EventTypeMemberAdded, "creator-pk", "app-1")

	// when
	svc.Push(ev, nil, "", false, []string{"user-pk-1"})

	// then: no send because app-1 is muted
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 0, sender.callCount())
}

func TestPushService_Push_ShouldSendWhenDifferentApplicationMuted(t *testing.T) {
	// given
	repo := newMockPushRepository()
	sender := newMockWebpushSender(SendResult{StatusCode: 201})
	vapidSvc := newMockSpaceVapidService("pub", "priv")
	svc := NewPushService(repo, sender, vapidSvc, nil)

	repo.subscriptions["sub-1"] = &Subscription{
		ID:                  "sub-1",
		DevicePublicKey:     "user-pk-1",
		Endpoint:            "https://push.example.com/1",
		P256dh:              "p256dh-value",
		Auth:                "auth-value",
		MutedApplicationIDs: []string{"app-2"},
	}

	ev := makeEvent(event.EventTypeMemberAdded, "creator-pk", "app-1")

	// when
	svc.Push(ev, nil, "", false, []string{"user-pk-1"})

	// then: send proceeds because app-1 is not in muted list (only app-2 is)
	assert.True(t, sender.waitForCalls(1, 2*time.Second), "expected 1 Send call")
	assert.Equal(t, 1, sender.callCount())
}

func TestPushService_Push_ShouldDeleteSubscriptionOn410(t *testing.T) {
	// given
	repo := newMockPushRepository()
	sender := newMockWebpushSender(SendResult{StatusCode: 410})
	vapidSvc := newMockSpaceVapidService("pub", "priv")
	svc := NewPushService(repo, sender, vapidSvc, nil)

	repo.subscriptions["sub-1"] = &Subscription{
		ID:                  "sub-1",
		DevicePublicKey:     "user-pk-1",
		Endpoint:            "https://push.example.com/1",
		P256dh:              "p256dh-value",
		Auth:                "auth-value",
		MutedApplicationIDs: []string{},
	}

	ev := makeEvent(event.EventTypeMemberAdded, "creator-pk", "app-1")

	// when
	svc.Push(ev, nil, "", false, []string{"user-pk-1"})

	// then: sender called and subscription deleted
	assert.True(t, sender.waitForCalls(1, 2*time.Second), "expected 1 Send call")
	assert.Eventually(t, func() bool {
		repo.mu.Lock()
		defer repo.mu.Unlock()
		return len(repo.deleteSubscriptionCalls) == 1 && repo.deleteSubscriptionCalls[0].id == "sub-1"
	}, 2*time.Second, 5*time.Millisecond, "expected subscription deleted")
}

func TestPushService_Push_ShouldIncrementFailureOn429(t *testing.T) {
	// given
	repo := newMockPushRepository()
	sender := newMockWebpushSender(SendResult{StatusCode: 429})
	vapidSvc := newMockSpaceVapidService("pub", "priv")
	svc := NewPushService(repo, sender, vapidSvc, nil)

	repo.subscriptions["sub-1"] = &Subscription{
		ID:                  "sub-1",
		DevicePublicKey:     "user-pk-1",
		Endpoint:            "https://push.example.com/1",
		P256dh:              "p256dh-value",
		Auth:                "auth-value",
		MutedApplicationIDs: []string{},
	}

	ev := makeEvent(event.EventTypeMemberAdded, "creator-pk", "app-1")

	// when
	svc.Push(ev, nil, "", false, []string{"user-pk-1"})

	// then: failure incremented, subscription NOT deleted
	assert.True(t, sender.waitForCalls(1, 2*time.Second), "expected 1 Send call")
	assert.Eventually(t, func() bool {
		repo.mu.Lock()
		defer repo.mu.Unlock()
		return len(repo.incrementFailureCalls) == 1 && repo.incrementFailureCalls[0] == "sub-1"
	}, 2*time.Second, 5*time.Millisecond, "expected failure increment")
	repo.mu.Lock()
	assert.Len(t, repo.deleteSubscriptionCalls, 0, "subscription must not be deleted on 429")
	repo.mu.Unlock()
}

func TestPushService_Push_ShouldUseSpaceVapidForAllRecipients(t *testing.T) {
	// given
	repo := newMockPushRepository()
	sender := newMockWebpushSender(SendResult{StatusCode: 201})
	vapidSvc := newMockSpaceVapidService("space-pub-key", "space-priv-key")
	svc := NewPushService(repo, sender, vapidSvc, nil)

	repo.subscriptions["sub-1"] = &Subscription{
		ID:                  "sub-1",
		DevicePublicKey:     "user-pk-1",
		Endpoint:            "https://push.example.com/1",
		P256dh:              "p256dh-1",
		Auth:                "auth-1",
		MutedApplicationIDs: []string{},
	}
	repo.subscriptions["sub-2"] = &Subscription{
		ID:                  "sub-2",
		DevicePublicKey:     "user-pk-2",
		Endpoint:            "https://push.example.com/2",
		P256dh:              "p256dh-2",
		Auth:                "auth-2",
		MutedApplicationIDs: []string{},
	}

	ev := makeEvent(event.EventTypeMemberAdded, "creator-pk", "app-1")

	// when
	svc.Push(ev, nil, "", false, []string{"user-pk-1", "user-pk-2"})

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

func chatNotice() notice {
	return notice{kind: KindChat, scope: "comp-1", view: "chat", body: "Ann: hi"}
}

func TestBuildPayload_ShouldProduceExactKeySetV2(t *testing.T) {
	// given
	ev := makeEvent(event.EventTypeComponentDataChanged, "creator-pk", "app-1")

	// when
	payloadJSON, err := buildPayload(ev, "My App", chatNotice())

	// then
	assert.NoError(t, err)
	var decoded map[string]interface{}
	assert.NoError(t, json.Unmarshal(payloadJSON, &decoded))
	keys := make([]string, 0, len(decoded))
	for k := range decoded {
		keys = append(keys, k)
	}
	assert.ElementsMatch(t, []string{"v", "applicationId", "eventId", "kind", "title", "body", "tag", "view"}, keys)
	assert.Equal(t, float64(2), decoded["v"])
	assert.Equal(t, "app-1", decoded["applicationId"])
	assert.Equal(t, "evt-1", decoded["eventId"])
	assert.Equal(t, "chat", decoded["kind"])
	assert.Equal(t, "My App", decoded["title"])
	assert.Equal(t, "Ann: hi", decoded["body"])
	assert.Equal(t, "chat", decoded["view"])
}

func TestBuildPayload_ShouldOmitViewForNonChatKinds(t *testing.T) {
	// given
	ev := makeEvent(event.EventTypeMemberAdded, "creator-pk", "app-1")

	// when
	payloadJSON, err := buildPayload(ev, "My App", notice{kind: KindMember, scope: ev.ID, body: "New member: Bo"})

	// then
	assert.NoError(t, err)
	var decoded map[string]interface{}
	assert.NoError(t, json.Unmarshal(payloadJSON, &decoded))
	assert.NotContains(t, decoded, "view")
	assert.Len(t, decoded, 7)
}

func TestBuildPayload_ShouldFallBackToPrappserTitleWhenAppNameEmpty(t *testing.T) {
	// given
	ev := makeEvent(event.EventTypeMemberAdded, "creator-pk", "app-1")

	// when
	payloadJSON, err := buildPayload(ev, "", notice{kind: KindMember, scope: ev.ID})

	// then
	assert.NoError(t, err)
	var decoded map[string]interface{}
	assert.NoError(t, json.Unmarshal(payloadJSON, &decoded))
	assert.Equal(t, "Prappser", decoded["title"])
}

func TestBuildPayload_ShouldCutLongTitleAndKeepShortOne(t *testing.T) {
	// given
	ev := makeEvent(event.EventTypeMemberAdded, "creator-pk", "app-1")
	long := strings.Repeat("a", 200)

	// when
	longJSON, err1 := buildPayload(ev, long, notice{kind: KindMember, scope: ev.ID})
	shortJSON, err2 := buildPayload(ev, "Short", notice{kind: KindMember, scope: ev.ID})

	// then
	assert.NoError(t, err1)
	assert.NoError(t, err2)
	var l, sh map[string]interface{}
	assert.NoError(t, json.Unmarshal(longJSON, &l))
	assert.NoError(t, json.Unmarshal(shortJSON, &sh))
	title := []rune(l["title"].(string))
	assert.Len(t, title, 121)
	assert.Equal(t, '…', title[120])
	assert.Equal(t, "Short", sh["title"])
}

func TestBuildPayload_ShouldPrefixTagWithApplicationId(t *testing.T) {
	// given
	ev := makeEvent(event.EventTypeComponentDataChanged, "creator-pk", "app-1")

	// when
	payloadJSON, err := buildPayload(ev, "My App", chatNotice())

	// then
	assert.NoError(t, err)
	var decoded map[string]interface{}
	assert.NoError(t, json.Unmarshal(payloadJSON, &decoded))
	assert.Equal(t, "app-1|chat|comp-1", decoded["tag"])
}

func TestSendOptions_ShouldMatchHeadersPerKind(t *testing.T) {
	// given
	ev := makeEvent(event.EventTypeComponentDataChanged, "creator-pk", "app-1")
	topic := topicFor("app-1", "comp-1", "creator-pk")
	cases := []struct {
		kind Kind
		want SendOptions
	}{
		{KindChat, SendOptions{Urgency: webpush.UrgencyHigh, TTL: 21600}},
		{KindItem, SendOptions{Urgency: webpush.UrgencyNormal, TTL: 43200, Topic: topic}},
		{KindPoll, SendOptions{Urgency: webpush.UrgencyNormal, TTL: 43200}},
		{KindFile, SendOptions{Urgency: webpush.UrgencyNormal, TTL: 43200}},
		{KindMember, SendOptions{Urgency: webpush.UrgencyNormal, TTL: 43200}},
		{KindRole, SendOptions{Urgency: webpush.UrgencyHigh, TTL: 86400}},
		{KindReminder, SendOptions{Urgency: webpush.UrgencyHigh, TTL: 86400}},
	}

	for _, c := range cases {
		// when
		got := sendOptionsFor(notice{kind: c.kind, componentID: "comp-1"}, ev)

		// then
		assert.Equal(t, c.want, got, string(c.kind))
	}
}

func TestTopicFor_ShouldBeFirst32CharsOfUnpaddedBase64URLSha256(t *testing.T) {
	// given
	sum := sha256.Sum256([]byte("app-1|comp-1|creator-pk"))
	want := base64.RawURLEncoding.EncodeToString(sum[:])[:32]

	// when
	got := topicFor("app-1", "comp-1", "creator-pk")

	// then
	assert.Equal(t, want, got)
	assert.Len(t, got, 32)
}

func TestPushService_Push_ShouldPassSendOptionsToSender(t *testing.T) {
	// given
	repo := newMockPushRepository()
	sender := newMockWebpushSender(SendResult{StatusCode: 201})
	svc := NewPushService(repo, sender, newMockSpaceVapidService("pub", "priv"), nil)
	repo.subscriptions["sub-1"] = &Subscription{ID: "sub-1", DevicePublicKey: "user-pk-1", MutedApplicationIDs: []string{}}
	ev := makeEvent(event.EventTypeMemberRoleChanged, "creator-pk", "app-1")
	ev.Data["newRole"] = "admin"

	// when
	svc.Push(ev, nil, "", false, []string{"user-pk-1"})

	// then
	assert.True(t, sender.waitForCalls(1, 2*time.Second))
	sender.mu.Lock()
	defer sender.mu.Unlock()
	assert.Equal(t, SendOptions{Urgency: webpush.UrgencyHigh, TTL: 86400}, sender.calls[0].opts)
}

func TestPushService_Push_ShouldRenderOncePerLocaleAndFallBackToEnglish(t *testing.T) {
	// given
	repo := newMockPushRepository()
	sender := newMockWebpushSender(SendResult{StatusCode: 201})
	svc := NewPushService(repo, sender, newMockSpaceVapidService("pub", "priv"), nil)
	for id, locale := range map[string]string{"pl": "pl", "empty": "", "de": "de"} {
		repo.subscriptions[id] = &Subscription{ID: id, DevicePublicKey: "pk-" + id, Locale: locale, MutedApplicationIDs: []string{}}
	}
	ev := makeEvent(event.EventTypeMemberRoleChanged, "creator-pk", "app-1")
	ev.Data["newRole"] = "viewer"

	// when
	svc.Push(ev, nil, "", false, []string{"pk-pl", "pk-empty", "pk-de"})

	// then
	assert.True(t, sender.waitForCalls(3, 2*time.Second))
	sender.mu.Lock()
	defer sender.mu.Unlock()
	bodies := map[string]string{}
	for _, c := range sender.calls {
		var decoded map[string]interface{}
		assert.NoError(t, json.Unmarshal(c.payload, &decoded))
		bodies[c.sub.ID] = decoded["body"].(string)
	}
	assert.Equal(t, "Twoja rola: Obserwator", bodies["pl"])
	assert.Equal(t, "Your role is now: Viewer", bodies["empty"])
	assert.Equal(t, "Your role is now: Viewer", bodies["de"])
}

func TestPushService_Push_ShouldSkipWhenEventHasNoRule(t *testing.T) {
	// given
	repo := newMockPushRepository()
	sender := newMockWebpushSender(SendResult{StatusCode: 201})
	svc := NewPushService(repo, sender, newMockSpaceVapidService("pub", "priv"), nil)
	repo.subscriptions["sub-1"] = &Subscription{ID: "sub-1", DevicePublicKey: "user-pk-1", MutedApplicationIDs: []string{}}
	ev := makeEvent(event.EventTypeApplicationCreated, "creator-pk", "app-1")

	// when
	svc.Push(ev, nil, "", false, []string{"user-pk-1"})

	// then
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 0, sender.callCount())
}

func TestKindSendsIn_ShouldFollowNotifyMode(t *testing.T) {
	chatModeKinds := map[Kind]bool{KindChat: true, KindReminder: true, KindRole: true}
	for _, kind := range []Kind{KindChat, KindItem, KindPoll, KindFile, KindMember, KindRole, KindReminder} {
		// when
		inAll := kind.sendsIn(user.NotifyModeAll)
		inChat := kind.sendsIn(user.NotifyModeChat)
		inEmpty := kind.sendsIn("")

		// then
		assert.True(t, inAll, kind)
		assert.Equal(t, chatModeKinds[kind], inChat, kind)
		assert.True(t, inEmpty, kind)
	}
}

func TestPushService_Fanout_ShouldFilterEveryKindByNotifyMode(t *testing.T) {
	cases := []struct {
		name       string
		ev         *event.Event
		chatGetsIt bool
	}{
		{"chat", gComp("chat-1", gChange(gChatA, nil, `{"body":"hi"}`)), true},
		{"item", gComp("list-1", gChange("item_a", nil, gItem("Milk"))), false},
		{"poll", gComp("poll-1", gChange("closed", false, true)), false},
		{"file", gComp("files-1", gChange("items", nil, []any{map[string]any{"id": "f9", "filename": "a.pdf"}})), false},
		{"member", gTyped(event.EventTypeMemberAdded, map[string]any{"userDisplayName": "Bo"}), false},
		{"role", gTyped(event.EventTypeMemberRoleChanged, map[string]any{"newRole": "admin"}), true},
		{"reminder", gTyped(event.EventTypeReminderFired, map[string]any{"itemTitle": "Call mom"}), true},
	}
	for _, tc := range cases {
		// given
		repo := newMockPushRepository()
		sender := newMockWebpushSender(SendResult{StatusCode: 201})
		svc := newGoldenService(repo, sender)
		repo.subscriptions["sub-all"] = &Subscription{ID: "sub-all", DevicePublicKey: "pk-all", NotifyMode: user.NotifyModeAll, MutedApplicationIDs: []string{}}
		repo.subscriptions["sub-chat"] = &Subscription{ID: "sub-chat", DevicePublicKey: "pk-chat", NotifyMode: user.NotifyModeChat, MutedApplicationIDs: []string{}}

		// when
		svc.fanout(tc.ev, goldenApp(), "Ann", false, []string{"pk-all", "pk-chat"})

		// then
		got := map[string]bool{}
		for _, c := range sender.calls {
			got[c.sub.ID] = true
		}
		assert.True(t, got["sub-all"], tc.name)
		assert.Equal(t, tc.chatGetsIt, got["sub-chat"], tc.name)
		assert.Len(t, sender.calls, len(got), tc.name)
	}
}
