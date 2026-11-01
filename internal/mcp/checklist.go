package mcp

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/google/uuid"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/component"
	"github.com/prappser/prappser-spaces/internal/user"
)

const (
	checklistComponentName = "Checklist"
	itemKeyPrefix          = "item_"
	maxChecklistTitleUnits = 1000
)

type checklistItem struct {
	id    string
	order float64
	value map[string]any
}

type addChecklistItemIn struct {
	AppID       string `json:"appId" jsonschema:"the app id from list_apps"`
	ComponentID string `json:"componentId,omitempty" jsonschema:"the checklist component id; needed only when the app has several checklists"`
	Title       string `json:"title" jsonschema:"the item title, up to 1000 characters"`
}

type updateChecklistItemIn struct {
	AppID       string  `json:"appId" jsonschema:"the app id from list_apps"`
	ComponentID string  `json:"componentId,omitempty" jsonschema:"the checklist component id; needed only when the app has several checklists"`
	ItemID      string  `json:"itemId" jsonschema:"the item id from get_app (the part after item_, or the id of a legacy item)"`
	Title       *string `json:"title,omitempty" jsonschema:"the new title, up to 1000 characters"`
	Checked     *bool   `json:"checked,omitempty" jsonschema:"true to check the item, false to uncheck it"`
}

type checklistItemOut struct {
	ItemID   string `json:"itemId"`
	EventID  string `json:"eventId"`
	Sequence int64  `json:"sequence"`
}

func findItem(data map[string]any, id string) map[string]any {
	for _, it := range readChecklist(data) {
		if it.id == id {
			return it.value
		}
	}
	return nil
}

func readChecklist(data map[string]any) []checklistItem {
	byID := map[string]checklistItem{}
	if list, ok := data["items"].([]any); ok {
		for i, e := range list {
			m, ok := e.(map[string]any)
			if !ok {
				continue
			}
			id, _ := m["id"].(string)
			if id == "" {
				continue
			}
			value := maps.Clone(m)
			delete(value, "id")
			order := float64(i)
			if o, ok := m["order"].(float64); ok {
				order = o
			}
			value["order"] = order
			byID[id] = checklistItem{id: id, order: order, value: value}
		}
	}
	for k, v := range data {
		id, ok := strings.CutPrefix(k, itemKeyPrefix)
		if !ok || id == "" {
			continue
		}
		switch t := v.(type) {
		case map[string]any:
			order, _ := t["order"].(float64)
			byID[id] = checklistItem{id: id, order: order, value: maps.Clone(t)}
		case string:
			if t == "" {
				delete(byID, id)
			}
		}
	}
	items := make([]checklistItem, 0, len(byID))
	for _, it := range byID {
		items = append(items, it)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].order != items[j].order {
			return items[i].order < items[j].order
		}
		return items[i].id < items[j].id
	})
	return items
}

func nextOrder(items []checklistItem) float64 {
	if len(items) == 0 {
		return 0
	}
	maxOrder := items[0].order
	for _, it := range items[1:] {
		maxOrder = max(maxOrder, it.order)
	}
	return maxOrder + 1
}

func cleanTitle(raw string) (string, error) {
	title := strings.TrimSpace(raw)
	if title == "" {
		return "", errors.New("title is required")
	}
	if len(utf16.Encode([]rune(title))) > maxChecklistTitleUnits {
		return "", fmt.Errorf("title is longer than %d characters", maxChecklistTitleUnits)
	}
	return title, nil
}

func flagOff(data map[string]any, name string) bool {
	v, ok := data[name].(bool)
	return ok && !v
}

func validationResult(err error) (*sdk.CallToolResult, bool) {
	var ve component.ValidationErrors
	if !errors.As(err, &ve) {
		return nil, false
	}
	return errorResult(map[string]any{"note": untrustedNote, "error": "invalid data", "untrusted": map[string]any{"fields": []component.FieldError(ve)}}), true
}

type checklistTarget struct {
	comp *application.Component
	role string
	res  *sdk.CallToolResult
}

func findChecklist(d Deps, u *user.User, appID, componentID string) (checklistTarget, error) {
	app, err := d.Apps.GetApplication(appID, u)
	if err != nil {
		return checklistTarget{}, toolError(err)
	}
	role := roleOf(app, u.PublicKey)
	if role == string(application.MemberRoleViewer) {
		return checklistTarget{}, errors.New("viewers cannot edit this checklist")
	}
	comp, choices, err := pickComponent(app, checklistComponentName, componentID)
	if err != nil {
		return checklistTarget{}, err
	}
	if comp == nil {
		return checklistTarget{res: severalOut("checklists", "several checklists, pass componentId", choices)}, nil
	}
	return checklistTarget{comp: comp, role: role}, nil
}

func (t checklistTarget) privileged() bool {
	return t.role == string(application.MemberRoleOwner) || t.role == string(application.MemberRoleAdmin)
}

func writeItem(ctx context.Context, d Deps, u *user.User, appID string, t checklistTarget, itemID string, value map[string]any) (*sdk.CallToolResult, checklistItemOut, error) {
	key := itemKeyPrefix + itemID
	if err := d.Validator.ValidateComponentData(checklistComponentName, map[string]any{key: value}); err != nil {
		if res, ok := validationResult(err); ok {
			return res, checklistItemOut{}, nil
		}
		return nil, checklistItemOut{}, toolError(err)
	}
	stored, err := submitKeyChange(ctx, d, u, appID, t.comp, key, t.comp.Data[key], value)
	if err != nil {
		return nil, checklistItemOut{}, toolError(err)
	}
	return nil, checklistItemOut{ItemID: itemID, EventID: stored.ID, Sequence: stored.SequenceNumber}, nil
}

func addAddChecklistItem(s *sdk.Server, d Deps) {
	sdk.AddTool(s, &sdk.Tool{
		Name:        "add_checklist_item",
		Description: "Add an item to the end of an app's checklist as this account. Other members see it live. Title up to 1000 characters." + untrustedHint,
	}, func(ctx context.Context, req *sdk.CallToolRequest, in addChecklistItemIn) (*sdk.CallToolResult, checklistItemOut, error) {
		u, err := caller(req)
		if err != nil {
			return nil, checklistItemOut{}, err
		}
		title, err := cleanTitle(in.Title)
		if err != nil {
			return nil, checklistItemOut{}, err
		}
		t, err := findChecklist(d, u, in.AppID, in.ComponentID)
		if err != nil {
			return nil, checklistItemOut{}, err
		}
		if t.res != nil {
			return t.res, checklistItemOut{}, nil
		}
		if !t.privileged() && flagOff(t.comp.Data, "allowAddInUsage") {
			return nil, checklistItemOut{}, errors.New("this checklist does not allow adding items")
		}
		value := map[string]any{"title": title, "checked": false, "order": nextOrder(readChecklist(t.comp.Data))}
		return writeItem(ctx, d, u, in.AppID, t, uuid.Must(uuid.NewV7()).String(), value)
	})
}

func addUpdateChecklistItem(s *sdk.Server, d Deps) {
	sdk.AddTool(s, &sdk.Tool{
		Name:        "update_checklist_item",
		Description: "Rename an item in an app's checklist, check it or uncheck it, as this account. Pass title, checked or both. Other members see the change live." + untrustedHint,
	}, func(ctx context.Context, req *sdk.CallToolRequest, in updateChecklistItemIn) (*sdk.CallToolResult, checklistItemOut, error) {
		u, err := caller(req)
		if err != nil {
			return nil, checklistItemOut{}, err
		}
		if in.Title == nil && in.Checked == nil {
			return nil, checklistItemOut{}, errors.New("pass title, checked or both")
		}
		if in.ItemID == "" {
			return nil, checklistItemOut{}, errors.New("itemId is required")
		}
		var title string
		if in.Title != nil {
			if title, err = cleanTitle(*in.Title); err != nil {
				return nil, checklistItemOut{}, err
			}
		}
		t, err := findChecklist(d, u, in.AppID, in.ComponentID)
		if err != nil {
			return nil, checklistItemOut{}, err
		}
		if t.res != nil {
			return t.res, checklistItemOut{}, nil
		}
		if !t.privileged() {
			if in.Title != nil && flagOff(t.comp.Data, "allowAddInUsage") {
				return nil, checklistItemOut{}, errors.New("this checklist does not allow renaming items")
			}
			if in.Checked != nil && flagOff(t.comp.Data, "allowToggleInUsage") {
				return nil, checklistItemOut{}, errors.New("this checklist does not allow checking items")
			}
		}
		if findItem(t.comp.Data, in.ItemID) == nil {
			return nil, checklistItemOut{}, errors.New("item not found")
		}
		fresh, err := d.Apps.GetApplication(in.AppID, u)
		if err != nil {
			return nil, checklistItemOut{}, toolError(err)
		}
		freshComp, _, err := pickComponent(fresh, checklistComponentName, t.comp.ID)
		if err != nil {
			return nil, checklistItemOut{}, err
		}
		value := findItem(freshComp.Data, in.ItemID)
		if value == nil {
			return nil, checklistItemOut{}, errors.New("item was deleted")
		}
		t.comp = freshComp
		if in.Title != nil {
			value["title"] = title
		}
		if in.Checked != nil {
			value["checked"] = *in.Checked
		}
		return writeItem(ctx, d, u, in.AppID, t, in.ItemID, value)
	})
}
