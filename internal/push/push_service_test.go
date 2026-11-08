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
	digestCounts []digestCountCall
	uncounts     []uncountCall
	uncountTakes bool
	prior        *PriorChange
	dailyUsers   []DigestUser
	claimRows    map[string][]DigestRow
	claimCalls   []string
}

type uncountCall struct {
	subscriptionID, applicationID, componentKey string
	countedAt, seenAt                           int64
}

type digestCountCall struct {
	subscriptionID, applicationID string
	bucket                        DigestBucket
	at, seenAt                    int64
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

func (m *mockPushRepository) UpsertWSSubscription(s *Subscription) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.subscriptions {
		if existing.Transport == TransportWS && existing.DevicePublicKey == s.DevicePublicKey {
			existing.MutedApplicationIDs = s.MutedApplicationIDs
			return existing.ID, nil
		}
	}
	m.subscriptions[s.ID] = s
	return s.ID, nil
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

func (m *mockPushRepository) CountDigest(subscriptionID, applicationID string, bucket DigestBucket, at, seenAt int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.digestCounts = append(m.digestCounts, digestCountCall{subscriptionID, applicationID, bucket, at, seenAt})
	return nil
}

func (m *mockPushRepository) UncountDigest(subscriptionID, applicationID, componentKey string, countedAt, seenAt int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.uncounts = append(m.uncounts, uncountCall{subscriptionID, applicationID, componentKey, countedAt, seenAt})
	return m.uncountTakes, nil
}

func (m *mockPushRepository) PreviousChange(applicationID, componentID, key string, sequence, since int64) (*PriorChange, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.prior, nil
}

func (m *mockPushRepository) GetDailyUsers() ([]DigestUser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]DigestUser(nil), m.dailyUsers...), nil
}

// ClaimDigest mirrors the real compare-and-set: it stamps the user and hands the rows out once.
func (m *mockPushRepository) ClaimDigest(userPublicKey string, due, now int64) ([]DigestRow, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.claimCalls = append(m.claimCalls, userPublicKey)
	for i := range m.dailyUsers {
		u := &m.dailyUsers[i]
		if u.PublicKey != userPublicKey {
			continue
		}
		if u.SentAt >= due {
			return nil, false, nil
		}
		u.SentAt = now
		rows := m.claimRows[userPublicKey]
		delete(m.claimRows, userPublicKey)
		return rows, true, nil
	}
	return nil, false, nil
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
	assert.ElementsMatch(t, []string{"v", "applicationId", "eventId", "kind", "title", "body", "tag", "view", "appName"}, keys)
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
	assert.Len(t, decoded, 8)
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
	assert.Equal(t, "Ktoś: Twoja rola to Obserwator", bodies["pl"])
	assert.Equal(t, "Someone: Your role is now Viewer", bodies["empty"])
	assert.Equal(t, "Someone: Your role is now Viewer", bodies["de"])
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

type wsPushCall struct {
	account, device string
	payload         []byte
}

type mockWSPusher struct {
	mu     sync.Mutex
	calls  []wsPushCall
	result bool
}

func (m *mockWSPusher) SendPush(account, device string, payload []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, wsPushCall{account, device, payload})
	return m.result
}

func (m *mockWSPusher) snapshot() []wsPushCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]wsPushCall(nil), m.calls...)
}

func newWSTestService(pusher WSPusher) (*PushService, *mockPushRepository, *mockWebpushSender) {
	repo := newMockPushRepository()
	sender := newMockWebpushSender(SendResult{StatusCode: 201})
	svc := NewPushService(repo, sender, newMockSpaceVapidService("pub", "priv"), nil)
	svc.SetWSPusher(pusher)
	return svc, repo, sender
}

func wsSub(id, device, user string, muted ...string) *Subscription {
	return &Subscription{ID: id, DevicePublicKey: device, UserPublicKey: user, Transport: TransportWS, MutedApplicationIDs: append([]string{}, muted...)}
}

func TestPushService_Push_ShouldSendV2PayloadToWSDevice(t *testing.T) {
	// given
	pusher := &mockWSPusher{result: true}
	svc, repo, sender := newWSTestService(pusher)
	repo.subscriptions["ws-1"] = wsSub("ws-1", "dev-1", "acct-1")
	repo.subscriptions["ws-1"].Locale = "pl"
	repo.subscriptions["wp-1"] = &Subscription{ID: "wp-1", DevicePublicKey: "dev-1", Transport: TransportWebpush, Endpoint: "https://push.example.com/1", P256dh: "p", Auth: "a", Locale: "pl", MutedApplicationIDs: []string{}}
	ev := makeEvent(event.EventTypeMemberAdded, "creator-pk", "app-1")

	// when
	svc.Push(ev, nil, "", false, []string{"dev-1"})

	// then: both subs of the device deliver through their own path with identical bytes
	assert.True(t, sender.waitForCalls(1, 2*time.Second))
	assert.Eventually(t, func() bool { return len(pusher.snapshot()) == 1 }, 2*time.Second, 5*time.Millisecond)
	call := pusher.snapshot()[0]
	assert.Equal(t, "acct-1", call.account)
	assert.Equal(t, "dev-1", call.device)
	assert.Equal(t, sender.calls[0].payload, call.payload)
	assert.Equal(t, "wp-1", sender.calls[0].sub.ID)
}

func TestPushService_Push_ShouldSkipWSDeviceWhenApplicationMuted(t *testing.T) {
	// given
	pusher := &mockWSPusher{result: true}
	svc, repo, _ := newWSTestService(pusher)
	repo.subscriptions["ws-1"] = wsSub("ws-1", "dev-1", "acct-1", "app-1")
	ev := makeEvent(event.EventTypeMemberAdded, "creator-pk", "app-1")

	// when
	svc.Push(ev, nil, "", false, []string{"dev-1"})

	// then
	time.Sleep(100 * time.Millisecond)
	assert.Empty(t, pusher.snapshot())
}

func TestPushService_Push_ShouldSkipWSDeviceInChatModeForNonChatKind(t *testing.T) {
	// given
	pusher := &mockWSPusher{result: true}
	svc, repo, _ := newWSTestService(pusher)
	repo.subscriptions["ws-1"] = wsSub("ws-1", "dev-1", "acct-1")
	repo.subscriptions["ws-1"].NotifyMode = user.NotifyModeChat
	ev := makeEvent(event.EventTypeMemberAdded, "creator-pk", "app-1")

	// when
	svc.Push(ev, nil, "", false, []string{"dev-1"})

	// then
	time.Sleep(100 * time.Millisecond)
	assert.Empty(t, pusher.snapshot())
}

func TestPushService_Push_ShouldNotTouchHealthWhenWSDeviceOffline(t *testing.T) {
	// given
	pusher := &mockWSPusher{result: false}
	svc, repo, sender := newWSTestService(pusher)
	repo.subscriptions["ws-1"] = wsSub("ws-1", "dev-1", "acct-1")
	ev := makeEvent(event.EventTypeMemberAdded, "creator-pk", "app-1")

	// when
	svc.Push(ev, nil, "", false, []string{"dev-1"})

	// then
	assert.Eventually(t, func() bool { return len(pusher.snapshot()) == 1 }, 2*time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	repo.mu.Lock()
	defer repo.mu.Unlock()
	assert.Empty(t, repo.incrementFailureCalls)
	assert.Empty(t, repo.deleteSubscriptionCalls)
	assert.Empty(t, repo.markSuccessCalls)
	assert.Equal(t, 0, sender.callCount())
}

func TestPushService_Push_ShouldDropWSPushWithoutPusher(t *testing.T) {
	// given
	svc, repo, sender := newWSTestService(nil)
	repo.subscriptions["ws-1"] = wsSub("ws-1", "dev-1", "acct-1")
	ev := makeEvent(event.EventTypeMemberAdded, "creator-pk", "app-1")

	// when
	svc.Push(ev, nil, "", false, []string{"dev-1"})

	// then
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 0, sender.callCount())
}

func TestKindDigestsIn_ShouldCoverOnlyDailyModeAndSkipReminderAndRole(t *testing.T) {
	for _, kind := range []Kind{KindChat, KindItem, KindPoll, KindFile, KindMember, KindRole, KindReminder} {
		// when
		inDaily := kind.digestsIn(user.NotifyModeDaily)
		inAll := kind.digestsIn(user.NotifyModeAll)
		inChat := kind.digestsIn(user.NotifyModeChat)

		// then
		assert.Equal(t, kind != KindRole && kind != KindReminder, inDaily, kind)
		assert.False(t, inAll, kind)
		assert.False(t, inChat, kind)
	}
}

func TestPushService_Fanout_ShouldCountInsteadOfSendInDailyMode(t *testing.T) {
	cases := []struct {
		name   string
		ev     *event.Event
		sends  bool
		bucket DigestBucket
	}{
		{"chat", gComp("chat-1", gChange(gChatA, nil, `{"body":"hi"}`)), false, DigestBucket{Key: "chat-1", Kind: KindChat}},
		{"item", gComp("list-2", gChange("item_a", nil, gItem("Milk"))), false, DigestBucket{Key: "list-2", Kind: KindItem, Title: "Groceries"}},
		{"poll", gComp("poll-1", gChange("closed", false, true)), false, DigestBucket{Key: "poll-1", Kind: KindPoll}},
		{"file", gComp("files-1", gChange("items", nil, []any{map[string]any{"id": "f9", "filename": "a.pdf"}})), false, DigestBucket{Key: "files-1", Kind: KindFile}},
		{"member", gTyped(event.EventTypeMemberAdded, map[string]any{"userDisplayName": "Bo"}), false, DigestBucket{Key: "member", Kind: KindMember}},
		{"role", gTyped(event.EventTypeMemberRoleChanged, map[string]any{"newRole": "admin"}), true, DigestBucket{}},
		{"reminder", gTyped(event.EventTypeReminderFired, map[string]any{"itemTitle": "Call mom"}), true, DigestBucket{}},
	}
	for _, tc := range cases {
		// given
		repo := newMockPushRepository()
		sender := newMockWebpushSender(SendResult{StatusCode: 201})
		svc := newGoldenService(repo, sender)
		repo.subscriptions["sub-d"] = &Subscription{ID: "sub-d", DevicePublicKey: "pk-d", NotifyMode: user.NotifyModeDaily, NotificationsSeenAt: 42, MutedApplicationIDs: []string{}}

		// when
		svc.fanout(tc.ev, goldenApp(), "Ann", false, []string{"pk-d"})

		// then
		assert.Equal(t, tc.sends, len(sender.calls) == 1, tc.name)
		if tc.sends {
			assert.Empty(t, repo.digestCounts, tc.name)
			continue
		}
		if assert.Len(t, repo.digestCounts, 1, tc.name) {
			c := repo.digestCounts[0]
			assert.Equal(t, "sub-d", c.subscriptionID, tc.name)
			assert.Equal(t, "app-1", c.applicationID, tc.name)
			assert.Equal(t, tc.bucket, c.bucket, tc.name)
			assert.Equal(t, int64(42), c.seenAt, tc.name)
			assert.NotZero(t, c.at, tc.name)
		}
	}
}

func TestPushService_Fanout_ShouldNotCountMutedAppOrEmptyApplicationID(t *testing.T) {
	// given
	repo := newMockPushRepository()
	sender := newMockWebpushSender(SendResult{StatusCode: 201})
	svc := newGoldenService(repo, sender)
	repo.subscriptions["sub-d"] = &Subscription{ID: "sub-d", DevicePublicKey: "pk-d", NotifyMode: user.NotifyModeDaily, MutedApplicationIDs: []string{"app-1"}}
	repo.subscriptions["sub-e"] = &Subscription{ID: "sub-e", DevicePublicKey: "pk-e", NotifyMode: user.NotifyModeDaily, MutedApplicationIDs: []string{}}
	muted := gTyped(event.EventTypeMemberAdded, map[string]any{"userDisplayName": "Bo"})
	noApp := gTyped(event.EventTypeMemberAdded, map[string]any{"userDisplayName": "Bo"})
	noApp.ApplicationID = ""

	// when
	svc.fanout(muted, goldenApp(), "Ann", false, []string{"pk-d"})
	svc.fanout(noApp, goldenApp(), "Ann", false, []string{"pk-e"})

	// then
	assert.Empty(t, repo.digestCounts)
	assert.Empty(t, sender.calls)
}

func TestPushService_Fanout_ShouldCancelDigestCountOfOwnCheckWhenUnchecking(t *testing.T) {
	// given
	checked := map[string]any{"title": "Milk", "checked": true}
	uncheck := func(extra ...map[string]any) *event.Event {
		return gComp("list-1", gMerge(append([]map[string]any{gChange("item_a", checked, map[string]any{"title": "Milk", "checked": false})}, extra...)...))
	}
	prior := func(mutate func(*PriorChange)) *PriorChange {
		p := &PriorChange{CreatorPublicKey: "creator-pk", CreatedAt: 1700000000, OldValue: gItem("Milk"), NewValue: checked, Keys: 1}
		mutate(p)
		return p
	}
	cases := []struct {
		name      string
		prior     *PriorChange
		takes     bool
		wantUndo  bool
		wantCount bool
		extra     map[string]any
		noCreator bool
	}{
		{"own check cancels", prior(func(*PriorChange) {}), true, true, false, nil, false},
		{"nothing to take off falls back to counting", prior(func(*PriorChange) {}), false, true, true, nil, false},
		{"no previous change counts", nil, true, false, true, nil, false},
		{"other person's check counts", prior(func(p *PriorChange) { p.CreatorPublicKey = "someone-else" }), true, false, true, nil, false},
		{"check inside a multi-entry event counts", prior(func(p *PriorChange) { p.Keys = 2 }), true, false, true, nil, false},
		{"previous change was not a check counts", prior(func(p *PriorChange) { p.NewValue = gItem("Milk") }), true, false, true, nil, false},
		{"previous change created the item counts", prior(func(p *PriorChange) { p.OldValue = nil }), true, false, true, nil, false},
		{"uncheck inside a multi-entry event counts", prior(func(*PriorChange) {}), true, false, true, gChange("item_b", nil, gItem("Bread")), false},
		{"empty creator is never the same person", prior(func(p *PriorChange) { p.CreatorPublicKey = "" }), true, false, true, nil, true},
	}
	for _, c := range cases {
		repo := newMockPushRepository()
		svc := newGoldenService(repo, newMockWebpushSender(SendResult{StatusCode: 201}))
		repo.subscriptions["sub-d"] = &Subscription{ID: "sub-d", DevicePublicKey: "pk-d", NotifyMode: user.NotifyModeDaily, NotificationsSeenAt: 42, MutedApplicationIDs: []string{}}
		repo.prior, repo.uncountTakes = c.prior, c.takes

		// when
		ev := uncheck()
		if c.extra != nil {
			ev = uncheck(c.extra)
		}
		if c.noCreator {
			ev.CreatorPublicKey = ""
		}
		svc.fanout(ev, goldenApp(), "Ann", false, []string{"pk-d"})

		// then
		assert.Equal(t, c.wantUndo, len(repo.uncounts) == 1, c.name)
		assert.Equal(t, c.wantCount, len(repo.digestCounts) == 1, c.name)
		if c.wantUndo {
			assert.Equal(t, uncountCall{"sub-d", "app-1", "list-1", 1700000000, 42}, repo.uncounts[0], c.name)
		}
	}
}
