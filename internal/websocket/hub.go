package websocket

import (
	"sync"

	"github.com/prappser/prappser_server/internal/event"
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
}

func NewHub() *Hub {
	return &Hub{
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

	log.Info().
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
	for appID := range client.subscriptions {
		h.removeFromAppSubscribers(client, appID)
	}

	log.Info().
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
	clients := make([]*Client, len(h.byApp[msg.ApplicationID]))
	copy(clients, h.byApp[msg.ApplicationID])
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
	h.broadcast <- &BroadcastMessage{
		ApplicationID: applicationID,
		Event:         ev,
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
