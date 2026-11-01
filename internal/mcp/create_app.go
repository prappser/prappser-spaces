package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog/log"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/component"
	"github.com/prappser/prappser-spaces/internal/event"
)

const (
	maxTemplateDocBytes = 64 * 1024
	maxAppNameUnits     = 64
)

type createAppIn struct {
	Doc map[string]any `json:"doc" jsonschema:"a TemplateDoc v1: {name, description, icon, groups: [{name, index, components: [{type, index, data}]}]}"`
}

type createAppOut struct {
	AppID   string `json:"appId"`
	Name    string `json:"name"`
	Warning string `json:"warning,omitempty"`
}

func createAppResult(app *application.Application, eventErr error) createAppOut {
	out := createAppOut{AppID: app.ID, Name: app.Name}
	if eventErr != nil {
		out.Warning = "The app was created, but announcing it to your other devices failed, so they may not see it until they resync. The app exists: do not retry create_app, a retry would create a second app."
	}
	return out
}

func newID() string {
	return uuid.Must(uuid.NewV7()).String()
}

func docSizeErrors(doc map[string]any) []component.FieldError {
	raw, err := json.Marshal(doc)
	if err != nil {
		return []component.FieldError{{Path: "", Message: "template is not valid JSON"}}
	}
	if len(raw) > maxTemplateDocBytes {
		return []component.FieldError{{Path: "", Message: fmt.Sprintf("template is %d bytes, the maximum is %d", len(raw), maxTemplateDocBytes)}}
	}
	return nil
}

func limitErrors(doc map[string]any) []component.FieldError {
	var out []component.FieldError
	name, _ := doc["name"].(string)
	if n := utf16Len(strings.TrimSpace(name)); n < 1 || n > maxAppNameUnits {
		out = append(out, component.FieldError{Path: "/name", Message: fmt.Sprintf("must be 1 to %d characters after trimming", maxAppNameUnits)})
	}
	return out
}

func isMedia(op any) bool {
	m, _ := op.(map[string]any)
	insert, _ := m["insert"].(map[string]any)
	_, image := insert["image"]
	_, video := insert["video"]
	return image || video
}

func mediaErrors(path string, ops any) []component.FieldError {
	var out []component.FieldError
	list, _ := ops.([]any)
	for i, op := range list {
		if isMedia(op) {
			out = append(out, component.FieldError{Path: fmt.Sprintf("%s/%d/insert", path, i), Message: "images and videos cannot be part of a template"})
		}
	}
	return out
}

func referenceErrors(typeName, base string, data map[string]any) []component.FieldError {
	var out []component.FieldError
	add := func(path, msg string) {
		out = append(out, component.FieldError{Path: path, Message: msg})
	}
	switch typeName {
	case checklistComponentName:
		keys := make([]string, 0, len(data))
		for k := range data {
			if strings.HasPrefix(k, itemKeyPrefix) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			item, ok := data[k].(map[string]any)
			if !ok {
				continue
			}
			p := base + "/" + k
			if s, _ := item["assignedMemberId"].(string); s != "" {
				add(p+"/assignedMemberId", "a template cannot assign items to members")
			}
			if a, _ := item["attachmentIds"].([]any); len(a) > 0 {
				add(p+"/attachmentIds", "a template cannot carry attachments")
			}
			out = append(out, mediaErrors(p+"/detailsDocument", item["detailsDocument"])...)
		}
	case "Map":
		markers, _ := data["markers"].([]any)
		for i, mk := range markers {
			m, _ := mk.(map[string]any)
			if s, _ := m["createdBy"].(string); s != "" {
				add(fmt.Sprintf("%s/markers/%d/createdBy", base, i), "a template cannot name who created a marker")
			}
		}
		if u, _ := data["otherUsers"].([]any); len(u) > 0 {
			add(base+"/otherUsers", "a template cannot carry live locations")
		}
	case "Files":
		if items, _ := data["items"].([]any); len(items) > 0 {
			add(base+"/items", "a template cannot carry files")
		}
	case "Text":
		if doc, ok := data["document"]; ok && doc != nil {
			if _, isList := doc.([]any); !isList {
				add(base+"/document", "templates must use a Quill delta list for document")
			}
		}
		out = append(out, mediaErrors(base+"/document", data["document"])...)
	}
	return out
}

func templateReferenceErrors(doc map[string]any) []component.FieldError {
	var out []component.FieldError
	groups, _ := doc["groups"].([]any)
	for gi, g := range groups {
		group, _ := g.(map[string]any)
		comps, _ := group["components"].([]any)
		for ci, c := range comps {
			comp, _ := c.(map[string]any)
			typeName, _ := comp["type"].(string)
			data, _ := comp["data"].(map[string]any)
			out = append(out, referenceErrors(typeName, fmt.Sprintf("/groups/%d/components/%d/data", gi, ci), data)...)
		}
	}
	return out
}

func buildApp(doc map[string]any, ownerKey string) *application.Application {
	appID := newID()
	name, _ := doc["name"].(string)
	app := &application.Application{
		ID:      appID,
		Name:    strings.TrimSpace(name),
		Members: []application.Member{{ID: newID(), ApplicationID: appID, Role: application.MemberRoleOwner, PublicKey: ownerKey}},
	}
	if icon, ok := doc["icon"].(string); ok {
		app.Icon = &icon
	}
	groups, _ := doc["groups"].([]any)
	for _, g := range groups {
		gm, _ := g.(map[string]any)
		group := application.ComponentGroup{ID: newID(), ApplicationID: appID, Index: jsonInt(gm["index"])}
		group.Name, _ = gm["name"].(string)
		comps, _ := gm["components"].([]any)
		for _, c := range comps {
			cm, _ := c.(map[string]any)
			comp := application.Component{ID: newID(), ComponentGroupID: group.ID, ApplicationID: appID, Index: jsonInt(cm["index"])}
			comp.Name, _ = cm["type"].(string)
			comp.Data, _ = cm["data"].(map[string]any)
			group.Components = append(group.Components, comp)
		}
		app.ComponentGroups = append(app.ComponentGroups, group)
	}
	return app
}

func jsonInt(v any) int {
	f, _ := v.(float64)
	return int(f)
}

func addCreateApp(s *sdk.Server, d Deps) {
	sdk.AddTool(s, &sdk.Tool{
		Name:        "create_app",
		Description: "Create a new app owned by this account from a TemplateDoc v1. The document is at most 64 KiB and the name 1 to 64 characters; the description is required by the schema but ignored, not stored. It cannot reference members or files: no assigned members, attachments, images, videos, map authors, live locations or files. Returns the new app's id.",
	}, func(ctx context.Context, req *sdk.CallToolRequest, in createAppIn) (*sdk.CallToolResult, createAppOut, error) {
		u, err := caller(req)
		if err != nil {
			return nil, createAppOut{}, err
		}
		if fields := docSizeErrors(in.Doc); len(fields) > 0 {
			return fieldsResult("template is too large", fields), createAppOut{}, nil
		}
		if err := d.Validator.ValidateTemplateDoc(in.Doc); err != nil {
			if res, ok := validationResult(err, "invalid template"); ok {
				return res, createAppOut{}, nil
			}
			return nil, createAppOut{}, toolError(err)
		}
		if fields := limitErrors(in.Doc); len(fields) > 0 {
			return fieldsResult("invalid template", fields), createAppOut{}, nil
		}
		if fields := templateReferenceErrors(in.Doc); len(fields) > 0 {
			return fieldsResult("invalid template", fields), createAppOut{}, nil
		}

		registered, err := d.Apps.RegisterApplication(u, buildApp(in.Doc, u.PublicKey))
		if err != nil {
			if errors.Is(err, application.ErrAppLimitReached) {
				return fieldsResult("you have reached your app limit", []component.FieldError{}), createAppOut{}, nil
			}
			return nil, createAppOut{}, toolError(err)
		}

		ev := event.Event{
			ID:        newID(),
			Type:      event.EventTypeApplicationCreated,
			Version:   1,
			CreatedAt: time.Now().UnixMilli(),
			Data: map[string]interface{}{
				"version":         float64(1),
				"userPublicKey":   u.PublicKey,
				"applicationId":   registered.ID,
				"applicationName": registered.Name,
			},
		}
		_, evErr := d.Events.AcceptEvent(ctx, &ev, u)
		if evErr != nil {
			log.Error().Err(evErr).Str("applicationId", registered.ID).Msg("[MCP] application_created event failed")
		}
		return nil, createAppResult(registered, evErr), nil
	})
}
