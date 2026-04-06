package websocket

import (
	"sync"
	"time"

	"github.com/fasthttp/websocket"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
)

const (
	writeTimeout   = 10 * time.Second
	pongWait       = 60 * time.Second
	pingInterval   = 30 * time.Second
	maxMessageSize = 512 * 1024 // 512KB
	sendBufferSize = 256
)

type Client struct {
	hub           *Hub
	conn          *websocket.Conn
	user          *user.User
	send          chan interface{}
	subscriptions map[string]bool // applicationId -> subscribed
	mu            sync.RWMutex
}

func NewClient(hub *Hub, conn *websocket.Conn, user *user.User) *Client {
	return &Client{
		hub:           hub,
		conn:          conn,
		user:          user,
		send:          make(chan interface{}, sendBufferSize),
		subscriptions: make(map[string]bool),
	}
}

func (c *Client) Subscribe(applicationID string) {
	c.mu.Lock()
	c.subscriptions[applicationID] = true
	c.mu.Unlock()

	c.hub.Subscribe(c, applicationID)

	log.Debug().
		Str("userPublicKey", c.user.PublicKey[:20]+"...").
		Str("applicationId", applicationID).
		Msg("[WS] Client subscribed to application")
}

func (c *Client) Unsubscribe(applicationID string) {
	c.mu.Lock()
	delete(c.subscriptions, applicationID)
	c.mu.Unlock()

	c.hub.Unsubscribe(c, applicationID)

	log.Debug().
		Str("userPublicKey", c.user.PublicKey[:20]+"...").
		Str("applicationId", applicationID).
		Msg("[WS] Client unsubscribed from application")
}

func (c *Client) IsSubscribed(applicationID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.subscriptions[applicationID]
}

func (c *Client) GetSubscriptions() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	subs := make([]string, 0, len(c.subscriptions))
	for appID := range c.subscriptions {
		subs = append(subs, appID)
	}
	return subs
}

func (c *Client) ReadPump() {
	defer func() {
		c.hub.Unregister(c)
		// WritePump owns conn.Close() via its own defer
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		var msg IncomingMessage
		err := c.conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
				log.Debug().
					Str("userPublicKey", c.user.PublicKey[:20]+"...").
					Err(err).
					Msg("[WS] Read error")
			} else {
				log.Debug().
					Str("userPublicKey", c.user.PublicKey[:20]+"...").
					Msg("[WS] Client disconnected")
			}
			return
		}

		c.handleMessage(&msg)
	}
}

func (c *Client) handleMessage(msg *IncomingMessage) {
	switch msg.Type {
	case MessageTypeSubscribe:
		if msg.ApplicationID != "" {
			c.Subscribe(msg.ApplicationID)
		}

	case MessageTypeUnsubscribe:
		if msg.ApplicationID != "" {
			c.Unsubscribe(msg.ApplicationID)
		}

	case MessageTypePing:
		c.send <- &OutgoingMessage{Type: MessageTypePong}

	default:
		log.Debug().
			Str("type", string(msg.Type)).
			Msg("[WS] Unknown message type")
	}
}

func (c *Client) WritePump() {
	ticker := time.NewTicker(pingInterval)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				// Channel closed by hub, connection will be closed by defer
				return
			}
			c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))

			err := c.conn.WriteJSON(message)
			if err != nil {
				log.Debug().
					Str("userPublicKey", c.user.PublicKey[:20]+"...").
					Err(err).
					Msg("[WS] Write error")
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Debug().
					Str("userPublicKey", c.user.PublicKey[:20]+"...").
					Err(err).
					Msg("[WS] Ping error")
				return
			}
		}
	}
}
