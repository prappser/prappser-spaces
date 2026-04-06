package websocket

import "github.com/prappser/prappser-spaces/internal/event"

type MessageType string

const (
	MessageTypeEvents      MessageType = "events"
	MessageTypeConnected   MessageType = "connected"
	MessageTypeSubscribe   MessageType = "subscribe"
	MessageTypeUnsubscribe MessageType = "unsubscribe"
	MessageTypePing        MessageType = "ping"
	MessageTypePong        MessageType = "pong"
	MessageTypeError       MessageType = "error"
)

type IncomingMessage struct {
	Type          MessageType `json:"type"`
	ApplicationID string      `json:"applicationId,omitempty"`
}

type OutgoingMessage struct {
	Type   MessageType `json:"type"`
	UserID string      `json:"userId,omitempty"`
	Error  string      `json:"error,omitempty"`
}

type EventsMessage struct {
	Type   MessageType    `json:"type"`
	Events []*event.Event `json:"events"`
}

type BroadcastMessage struct {
	ApplicationID string
	Event         *event.Event
}

type UserBroadcastMessage struct {
	UserPublicKey string
	Event         *event.Event
}
