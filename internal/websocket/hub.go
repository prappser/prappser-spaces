package websocket

import (
	"sync"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/rs/zerolog/log"
)

type disconnectReq struct{ account, device string }

type Hub struct {
	clients       map[*Client]bool
	byUser        map[string][]*Client // publicKey -> clients
	byApp         map[string][]*Client // applicationId -> subscribers
	unregister    chan *Client
	disconnect    chan disconnectReq
	pendingMu     sync.Mutex
	pending       map[disconnectReq]struct{} // overflow of disconnect, drained by one worker
	draining      bool
	broadcast     chan *BroadcastMessage
	userBroadcast chan *UserBroadcastMessage
	mu            sync.RWMutex
	appRepo       application.ApplicationRepository
}

func NewHub(appRepo application.ApplicationRepository) *Hub {
	return &Hub{
		appRepo:       appRepo,
		clients:       make(map[*Client]bool),
		byUser:        make(map[string][]*Client),
		byApp:         make(map[string][]*Client),
		unregister:    make(chan *Client),
		disconnect:    make(chan disconnectReq, 64),
		broadcast:     make(chan *BroadcastMessage, 256),
		userBroadcast: make(chan *UserBroadcastMessage, 256),
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.unregister:
			h.unregisterClient(client)

		case req := <-h.disconnect:
			h.disconnectClients(req)

		case message := <-h.broadcast:
			h.broadcastToApp(message)

		case message := <-h.userBroadcast:
			h.broadcastToUser(message)
		}
	}
}

func (h *Hub) registerClient(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.clients[client] = true
	h.byUser[client.user.PublicKey] = append(h.byUser[client.user.PublicKey], client)

	log.Debug().
		Str("userPublicKey", client.user.PublicKey[:20]+"...").
		Int("totalClients", len(h.clients)).
		Msg("[WS] Client registered")
}

func (h *Hub) unregisterClient(client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.clients[client]; !ok {
		return
	}

	delete(h.clients, client)
	close(client.send)

	// Remove from byUser map
	userClients := h.byUser[client.user.PublicKey]
	for i, c := range userClients {
		if c == client {
			h.byUser[client.user.PublicKey] = append(userClients[:i], userClients[i+1:]...)
			break
		}
	}
	if len(h.byUser[client.user.PublicKey]) == 0 {
		delete(h.byUser, client.user.PublicKey)
	}

	// Remove from all app subscriptions
	for _, appID := range client.GetSubscriptions() {
		h.removeFromAppSubscribers(client, appID)
	}

	log.Debug().
		Str("userPublicKey", client.user.PublicKey[:20]+"...").
		Int("totalClients", len(h.clients)).
		Msg("[WS] Client unregistered")
}

func (h *Hub) disconnectClients(req disconnectReq) {
	h.mu.RLock()
	clients := make([]*Client, len(h.byUser[req.account]))
	copy(clients, h.byUser[req.account])
	h.mu.RUnlock()

	closed := 0
	for _, c := range clients {
		if req.device == "" || c.user.DevicePublicKey == req.device {
			// close the conn, not send: ReadPump may still write to send
			c.conn.Close()
			closed++
		}
	}

	log.Debug().Int("closed", closed).Msg("[WS] Clients disconnected")
}

func (h *Hub) removeFromAppSubscribers(client *Client, appID string) {
	appClients := h.byApp[appID]
	for i, c := range appClients {
		if c == client {
			h.byApp[appID] = append(appClients[:i], appClients[i+1:]...)
			break
		}
	}
	if len(h.byApp[appID]) == 0 {
		delete(h.byApp, appID)
	}
}

func (h *Hub) Subscribe(client *Client, applicationID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Check if already subscribed
	for _, c := range h.byApp[applicationID] {
		if c == client {
			return
		}
	}

	h.byApp[applicationID] = append(h.byApp[applicationID], client)

	log.Debug().
		Str("applicationId", applicationID).
		Int("subscribers", len(h.byApp[applicationID])).
		Msg("[WS] Application subscription added")
}

func (h *Hub) Unsubscribe(client *Client, applicationID string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.removeFromAppSubscribers(client, applicationID)

	log.Debug().
		Str("applicationId", applicationID).
		Int("subscribers", len(h.byApp[applicationID])).
		Msg("[WS] Application subscription removed")
}

// broadcastToApp and broadcastToUser send under the read lock because unregisterClient closes client.send under the write lock.
func (h *Hub) broadcastToApp(msg *BroadcastMessage) {
	eventMsg := &EventsMessage{
		Type:   MessageTypeEvents,
		Events: []*event.Event{msg.Event},
	}

	h.mu.RLock()
	delivered := 0
	for _, client := range h.byApp[msg.ApplicationID] {
		if !msg.Recipients[client.user.PublicKey] {
			continue
		}
		delivered++
		select {
		case client.send <- eventMsg:
		default:
			// Client buffer full, skip this message
			log.Warn().
				Str("userPublicKey", client.user.PublicKey[:20]+"...").
				Str("applicationId", msg.ApplicationID).
				Msg("[WS] Client send buffer full, dropping message")
		}
	}
	h.mu.RUnlock()

	if delivered == 0 {
		return
	}

	log.Debug().
		Str("applicationId", msg.ApplicationID).
		Str("eventId", msg.Event.ID).
		Int("recipients", delivered).
		Msg("[WS] Event broadcast complete")
}

func (h *Hub) broadcastToUser(msg *UserBroadcastMessage) {
	eventMsg := &EventsMessage{
		Type:   MessageTypeEvents,
		Events: []*event.Event{msg.Event},
	}

	h.mu.RLock()
	delivered := 0
	for _, client := range h.byUser[msg.UserPublicKey] {
		if client.user.Agent {
			continue
		}
		delivered++
		select {
		case client.send <- eventMsg:
		default:
			log.Warn().
				Str("userPublicKey", client.user.PublicKey[:20]+"...").
				Msg("[WS] Client send buffer full, dropping user broadcast")
		}
	}
	h.mu.RUnlock()

	if delivered == 0 {
		return
	}

	pkLen := len(msg.UserPublicKey)
	if pkLen > 20 {
		pkLen = 20
	}
	log.Debug().
		Str("userPublicKey", msg.UserPublicKey[:pkLen]+"...").
		Str("eventId", msg.Event.ID).
		Int("recipients", delivered).
		Msg("[WS] User event broadcast complete")
}

// SendPush queues payload for the device's open connections and reports whether any accepted it.
// The send happens under the read lock because unregisterClient closes client.send under the write lock.
func (h *Hub) SendPush(account, device string, payload []byte) bool {
	msg := &PushMessage{Type: MessageTypePush, Payload: payload}

	h.mu.RLock()
	defer h.mu.RUnlock()

	delivered := false
	for _, c := range h.byUser[account] {
		if c.user.DevicePublicKey != device {
			continue
		}
		select {
		case c.send <- msg:
			delivered = true
		default:
			log.Warn().Str("devicePublicKey", device[:min(20, len(device))]+"...").Msg("[WS] Client send buffer full, dropping push")
		}
	}
	return delivered
}

// Register inserts the client before returning, so a Disconnect issued afterwards always sees it.
func (h *Hub) Register(client *Client) {
	h.registerClient(client)
}

func (h *Hub) Unregister(client *Client) {
	h.unregister <- client
}

// Disconnect closes the account's sockets for one device; an empty device means every socket of the account.
// It never blocks the caller: requests go to Run, and a full queue spills into a coalesced pending set
// that a single worker drains, so a flood cannot spawn goroutines and no request is dropped.
func (h *Hub) Disconnect(account, device string) {
	req := disconnectReq{account: account, device: device}
	select {
	case h.disconnect <- req:
		return
	default:
	}

	h.pendingMu.Lock()
	defer h.pendingMu.Unlock()
	if h.pending == nil {
		h.pending = make(map[disconnectReq]struct{})
	}
	h.pending[req] = struct{}{}
	if !h.draining {
		h.draining = true
		go h.drainPending()
	}
}

func (h *Hub) drainPending() {
	for {
		h.pendingMu.Lock()
		reqs := h.pending
		h.pending = nil
		if len(reqs) == 0 {
			h.draining = false
			h.pendingMu.Unlock()
			return
		}
		h.pendingMu.Unlock()

		for req := range reqs {
			h.disconnectClients(req)
		}
	}
}

// EvictAgents drops the live subscriptions of every agent on the app except the owner's own, keeping their sockets open.
func (h *Hub) EvictAgents(applicationID, ownerPublicKey string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, c := range append([]*Client(nil), h.byApp[applicationID]...) {
		if !c.user.Agent || c.user.PublicKey == ownerPublicKey {
			continue
		}
		h.removeFromAppSubscribers(c, applicationID)
		c.mu.Lock()
		delete(c.subscriptions, applicationID)
		c.mu.Unlock()
		select {
		case c.send <- &OutgoingMessage{Type: MessageTypeError, Error: "agent access to this application was turned off"}:
		default:
		}
	}
}

func (h *Hub) BroadcastToApplication(applicationID string, ev *event.Event) {
	members, err := h.appRepo.GetMembersByApplicationID(applicationID)
	if err != nil {
		log.Warn().
			Err(err).
			Str("applicationId", applicationID).
			Msg("[WS] Failed to load members, dropping broadcast")
		return
	}

	recipients := make(map[string]bool, len(members)+1)
	for _, m := range members {
		recipients[m.PublicKey] = true
	}
	if ev.Type == event.EventTypeMemberRemoved {
		// the member row is already deleted, but the removed client needs its own member_removed
		if key, ok := ev.Data["memberPublicKey"].(string); ok && key != "" {
			recipients[key] = true
		}
	}

	h.broadcast <- &BroadcastMessage{
		ApplicationID: applicationID,
		Event:         ev,
		Recipients:    recipients,
	}
}

func (h *Hub) BroadcastToUser(userPublicKey string, ev *event.Event) {
	h.userBroadcast <- &UserBroadcastMessage{
		UserPublicKey: userPublicKey,
		Event:         ev,
	}
}

func (h *Hub) GetStats() (totalClients, totalSubscriptions int) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	totalClients = len(h.clients)
	for _, clients := range h.byApp {
		totalSubscriptions += len(clients)
	}
	return
}
