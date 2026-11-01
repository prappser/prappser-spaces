package websocket

import (
	"sync"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/rs/zerolog/log"
)

type Hub struct {
	clients       map[*Client]bool
	byUser        map[string][]*Client // publicKey -> clients
	byApp         map[string][]*Client // applicationId -> subscribers
	register      chan *Client
	unregister    chan *Client
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
		register:      make(chan *Client),
		unregister:    make(chan *Client),
		broadcast:     make(chan *BroadcastMessage, 256),
		userBroadcast: make(chan *UserBroadcastMessage, 256),
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.registerClient(client)

		case client := <-h.unregister:
			h.unregisterClient(client)

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

func (h *Hub) broadcastToApp(msg *BroadcastMessage) {
	h.mu.RLock()
	var clients []*Client
	for _, c := range h.byApp[msg.ApplicationID] {
		if msg.Recipients[c.user.PublicKey] {
			clients = append(clients, c)
		}
	}
	h.mu.RUnlock()

	if len(clients) == 0 {
		return
	}

	eventMsg := &EventsMessage{
		Type:   MessageTypeEvents,
		Events: []*event.Event{msg.Event},
	}

	for _, client := range clients {
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

	log.Debug().
		Str("applicationId", msg.ApplicationID).
		Str("eventId", msg.Event.ID).
		Int("recipients", len(clients)).
		Msg("[WS] Event broadcast complete")
}

func (h *Hub) broadcastToUser(msg *UserBroadcastMessage) {
	h.mu.RLock()
	clients := make([]*Client, len(h.byUser[msg.UserPublicKey]))
	copy(clients, h.byUser[msg.UserPublicKey])
	h.mu.RUnlock()

	if len(clients) == 0 {
		return
	}

	eventMsg := &EventsMessage{
		Type:   MessageTypeEvents,
		Events: []*event.Event{msg.Event},
	}

	for _, client := range clients {
		select {
		case client.send <- eventMsg:
		default:
			log.Warn().
				Str("userPublicKey", client.user.PublicKey[:20]+"...").
				Msg("[WS] Client send buffer full, dropping user broadcast")
		}
	}

	pkLen := len(msg.UserPublicKey)
	if pkLen > 20 {
		pkLen = 20
	}
	log.Debug().
		Str("userPublicKey", msg.UserPublicKey[:pkLen]+"...").
		Str("eventId", msg.Event.ID).
		Int("recipients", len(clients)).
		Msg("[WS] User event broadcast complete")
}

func (h *Hub) Register(client *Client) {
	h.register <- client
}

func (h *Hub) Unregister(client *Client) {
	h.unregister <- client
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
