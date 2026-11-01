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
	"github.com/prappser/prappser-spaces/internal/user"
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

type componentChoice struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

var errChatOff = fmt.Errorf("chat is off for this app")

func pickComponent(app *application.Application, typeName, componentID string) (*application.Component, []application.Component, error) {
	var found []application.Component
	for _, g := range app.ComponentGroups {
		for _, c := range g.Components {
			if c.Name == typeName {
				found = append(found, c)
			}
		}
	}
	if componentID != "" {
		for i := range found {
			if found[i].ID == componentID {
				return &found[i], nil, nil
			}
		}
		return nil, nil, fmt.Errorf("componentId is not a %s of this app", strings.ToLower(typeName))
	}
	switch len(found) {
	case 0:
		if typeName == chatComponentName {
			return nil, nil, errChatOff
		}
		return nil, nil, fmt.Errorf("no %s in this app", strings.ToLower(typeName))
	case 1:
		return &found[0], nil, nil
	}
	return nil, found, nil
}

func severalOut(listKey, errMsg string, choices []application.Component) *sdk.CallToolResult {
	list := make([]componentChoice, 0, len(choices))
	for _, c := range choices {
		list = append(list, componentChoice{ID: c.ID, Name: c.Name})
	}
	return errorResult(map[string]any{"note": untrustedNote, "error": errMsg, "untrusted": map[string]any{listKey: list}})
}

func errorResult(body any) *sdk.CallToolResult {
	b, _ := json.Marshal(body)
	return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: string(b)}}}
}

func submitKeyChange(ctx context.Context, d Deps, u *user.User, appID string, comp *application.Component, key string, oldValue, newValue any) (*event.Event, error) {
	ev := event.Event{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Type:      event.EventTypeComponentDataChanged,
		Version:   1,
		CreatedAt: time.Now().UnixMilli(),
		Data: map[string]interface{}{
			"version":          float64(1),
			"applicationId":    appID,
			"componentId":      comp.ID,
			"componentGroupId": comp.ComponentGroupID,
			"changedFields": map[string]interface{}{
				key: map[string]interface{}{"oldValue": oldValue, "newValue": newValue},
			},
		},
	}
	return d.Events.AcceptEvent(ctx, &ev, u)
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
		chat, choices, err := pickComponent(app, chatComponentName, in.ComponentID)
		if err != nil {
			return nil, postChatOut{}, err
		}
		if chat == nil {
			return severalOut("chats", "several chats, pass componentId", choices), postChatOut{}, nil
		}

		key := "m_" + uuid.Must(uuid.NewV7()).String()
		msg, _ := json.Marshal(map[string]any{"v": 1, "sender": u.PublicKey, "ts": time.Now().UnixMilli(), "body": text})
		stored, err := submitKeyChange(ctx, d, u, in.AppID, chat, key, nil, string(msg))
		if err != nil {
			return nil, postChatOut{}, toolError(err)
		}
		return nil, postChatOut{MessageID: key, EventID: stored.ID, Sequence: stored.SequenceNumber}, nil
	})
}
