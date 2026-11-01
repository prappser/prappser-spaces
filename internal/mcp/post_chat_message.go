package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
)

const (
	chatComponentName = "Chat"
	maxChatTextLen    = 4000
)

type postChatIn struct {
	AppID       string `json:"appId" jsonschema:"the app id from list_apps"`
	ComponentID string `json:"componentId,omitempty" jsonschema:"the chat component id; needed only when the app has several chats"`
	Text        string `json:"text" jsonschema:"the message, up to 4000 characters"`
}

type postChatOut struct {
	MessageID string `json:"messageId"`
	EventID   string `json:"eventId"`
	Sequence  int64  `json:"sequence"`
}

type chatChoice struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type chatChoices struct {
	Chats []chatChoice `json:"chats"`
}

type severalChatsOut struct {
	Note      string      `json:"note"`
	Error     string      `json:"error"`
	Untrusted chatChoices `json:"untrusted"`
}

var errChatOff = fmt.Errorf("chat is off for this app")

func pickChat(app *application.Application, componentID string) (*application.Component, []application.Component, error) {
	var chats []application.Component
	for _, g := range app.ComponentGroups {
		for _, c := range g.Components {
			if c.Name == chatComponentName {
				chats = append(chats, c)
			}
		}
	}
	if componentID != "" {
		for i := range chats {
			if chats[i].ID == componentID {
				return &chats[i], nil, nil
			}
		}
		return nil, nil, fmt.Errorf("componentId is not a chat of this app")
	}
	switch len(chats) {
	case 0:
		return nil, nil, errChatOff
	case 1:
		return &chats[0], nil, nil
	}
	return nil, chats, nil
}

func addPostChatMessage(s *sdk.Server, d Deps) {
	sdk.AddTool(s, &sdk.Tool{
		Name:        "post_chat_message",
		Description: "Post a message to an app's chat as this account. Other members see it live. Maximum 4000 characters." + untrustedHint,
	}, func(ctx context.Context, req *sdk.CallToolRequest, in postChatIn) (*sdk.CallToolResult, postChatOut, error) {
		u, err := caller(req)
		if err != nil {
			return nil, postChatOut{}, err
		}
		text := strings.TrimSpace(in.Text)
		if text == "" {
			return nil, postChatOut{}, fmt.Errorf("text is required")
		}
		if utf8.RuneCountInString(text) > maxChatTextLen {
			return nil, postChatOut{}, fmt.Errorf("text is longer than %d characters", maxChatTextLen)
		}
		app, err := d.Apps.GetApplication(in.AppID, u)
		if err != nil {
			return nil, postChatOut{}, toolError(err)
		}
		chat, choices, err := pickChat(app, in.ComponentID)
		if err != nil {
			return nil, postChatOut{}, err
		}
		if chat == nil {
			out := severalChatsOut{Note: untrustedNote, Error: "several chats, pass componentId"}
			for _, c := range choices {
				out.Untrusted.Chats = append(out.Untrusted.Chats, chatChoice{ID: c.ID, Name: c.Name})
			}
			body, _ := json.Marshal(out)
			return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: string(body)}}}, postChatOut{}, nil
		}

		now := time.Now().UnixMilli()
		key := "m_" + uuid.Must(uuid.NewV7()).String()
		msg, _ := json.Marshal(map[string]any{"v": 1, "sender": u.PublicKey, "ts": now, "body": text})
		ev := event.Event{
			ID:        uuid.Must(uuid.NewV7()).String(),
			Type:      event.EventTypeComponentDataChanged,
			Version:   1,
			CreatedAt: now,
			Data: map[string]interface{}{
				"version":          float64(1),
				"applicationId":    in.AppID,
				"componentId":      chat.ID,
				"componentGroupId": chat.ComponentGroupID,
				"changedFields": map[string]interface{}{
					key: map[string]interface{}{"oldValue": nil, "newValue": string(msg)},
				},
			},
		}
		stored, err := d.Events.AcceptEvent(ctx, &ev, u)
		if err != nil {
			return nil, postChatOut{}, toolError(err)
		}
		return nil, postChatOut{MessageID: key, EventID: stored.ID, Sequence: stored.SequenceNumber}, nil
	})
}
