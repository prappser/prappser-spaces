package mcp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
)

type appChange struct {
	Op          string         `json:"op" jsonschema:"add_group, rename_group, move_group, remove_group, add_component, move_component or remove_component"`
	GroupID     string         `json:"groupId,omitempty" jsonschema:"group id from get_app, or $N for the N-th add_group of this call (0-based)"`
	ComponentID string         `json:"componentId,omitempty"`
	Name        string         `json:"name,omitempty" jsonschema:"group name for add_group and rename_group"`
	Type        string         `json:"type,omitempty" jsonschema:"component type for add_component"`
	Index       *int           `json:"index,omitempty" jsonschema:"position; adds default to the end, moves require it"`
	Data        map[string]any `json:"data,omitempty" jsonschema:"initial data for add_component, defaults to {}"`
}

type editAppIn struct {
	AppID   string      `json:"appId" jsonschema:"the app id from list_apps"`
	Changes []appChange `json:"changes" jsonschema:"applied in order, all or none"`
}

type editAppOut struct {
	IDs []*string `json:"ids" jsonschema:"one entry per change: the new id for add_group and add_component, null otherwise"`
}

type workGroup struct {
	id    string
	index int
	comps []string
}

func structureChange(changeType, entityType, id string, data map[string]any, index any) map[string]interface{} {
	return map[string]interface{}{
		"changeType": changeType, "entityType": entityType, "entityId": id,
		"data": data, "index": index, "changedFields": nil,
	}
}

func addEditApp(s *sdk.Server, d Deps) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "edit_app",
		Description: "Change an app's structure as this account: owner or admin only. changes run in order, all or none. " +
			"ops: add_group(name, index?), rename_group(groupId, name), move_group(groupId, index), remove_group(groupId; its components go too), " +
			"add_component(groupId, type, index?, data?), move_component(componentId, index), remove_component(componentId). " +
			"groupId may be $N, the N-th add_group of this call (0-based). Returns ids, one per change: the new id for adds, null otherwise. " +
			"index defaults to the end. Components cannot move between groups. add_component data follows describe_component's schema and update_component's x-access rules.",
	}, func(ctx context.Context, req *sdk.CallToolRequest, in editAppIn) (*sdk.CallToolResult, editAppOut, error) {
		u, err := caller(req)
		if err != nil {
			return nil, editAppOut{}, err
		}
		if len(in.Changes) == 0 {
			return nil, editAppOut{}, errors.New("changes is empty")
		}
		app, err := d.Apps.GetApplication(in.AppID, u)
		if err != nil {
			return nil, editAppOut{}, toolError(err)
		}
		if role := roleOf(app, u.PublicKey); role != string(application.MemberRoleOwner) && role != string(application.MemberRoleAdmin) {
			return nil, editAppOut{}, errors.New("you are not allowed to change this app")
		}

		groups := map[string]*workGroup{}
		compGroup := map[string]*workGroup{}
		for _, g := range app.ComponentGroups {
			wg := &workGroup{id: g.ID, index: g.Index}
			for _, c := range g.Components {
				wg.comps = append(wg.comps, c.ID)
				compGroup[c.ID] = wg
			}
			groups[g.ID] = wg
		}
		var minted []string
		group := func(ref string) (*workGroup, error) {
			id := ref
			if n, ok := strings.CutPrefix(ref, "$"); ok {
				i, err := strconv.Atoi(n)
				if err != nil || i < 0 || i >= len(minted) {
					return nil, fmt.Errorf("group %s not found", ref)
				}
				id = minted[i]
			}
			g := groups[id]
			if g == nil {
				return nil, fmt.Errorf("group %s not found", ref)
			}
			return g, nil
		}
		component := func(id string) (*workGroup, error) {
			g := compGroup[id]
			if g == nil {
				return nil, fmt.Errorf("component %s not found", id)
			}
			return g, nil
		}

		ids := make([]*string, len(in.Changes))
		changes := make([]interface{}, 0, len(in.Changes))
		for i, c := range in.Changes {
			switch c.Op {
			case "add_group":
				if c.Name == "" {
					return nil, editAppOut{}, errors.New("name is required")
				}
				g := &workGroup{id: newID(), index: len(groups)}
				if c.Index != nil {
					g.index = *c.Index
				}
				groups[g.id] = g
				minted = append(minted, g.id)
				ids[i] = &g.id
				changes = append(changes, structureChange("component_group_added", "component_group", g.id,
					map[string]any{"id": g.id, "applicationId": in.AppID, "index": g.index, "name": c.Name}, nil))
			case "rename_group":
				g, err := group(c.GroupID)
				if err != nil {
					return nil, editAppOut{}, err
				}
				if c.Name == "" {
					return nil, editAppOut{}, errors.New("name is required")
				}
				changes = append(changes, structureChange("component_group_changed", "component_group", g.id,
					map[string]any{"name": c.Name, "index": g.index}, nil))
			case "move_group":
				g, err := group(c.GroupID)
				if err != nil {
					return nil, editAppOut{}, err
				}
				if c.Index == nil {
					return nil, editAppOut{}, errors.New("index is required")
				}
				g.index = *c.Index
				changes = append(changes, structureChange("component_group_reordered", "component_group", g.id, nil, g.index))
			case "remove_group":
				g, err := group(c.GroupID)
				if err != nil {
					return nil, editAppOut{}, err
				}
				delete(groups, g.id)
				changes = append(changes, structureChange("component_group_removed", "component_group", g.id, nil, nil))
				for _, cid := range g.comps {
					delete(compGroup, cid)
					changes = append(changes, structureChange("component_removed", "component", cid, nil, nil))
				}
			case "add_component":
				g, err := group(c.GroupID)
				if err != nil {
					return nil, editAppOut{}, err
				}
				if _, ok := d.Validator.Schema(c.Type); !ok {
					return nil, editAppOut{}, errors.New("unknown component type, call describe_component with no type")
				}
				data := mintKeys(c.Data)
				if _, res, err := checkWrite(d.Validator, c.Type, nil, data, u.PublicKey, true, d.Validator.ValidateComponentData); res != nil || err != nil {
					return res, editAppOut{}, err
				}
				index := len(g.comps)
				if c.Index != nil {
					index = *c.Index
				}
				id := newID()
				g.comps = append(g.comps, id)
				compGroup[id] = g
				ids[i] = &id
				changes = append(changes, structureChange("component_added", "component", id,
					map[string]any{"id": id, "componentGroupId": g.id, "applicationId": in.AppID, "index": index, "name": c.Type, "data": data}, nil))
			case "move_component":
				if _, err := component(c.ComponentID); err != nil {
					return nil, editAppOut{}, err
				}
				if c.Index == nil {
					return nil, editAppOut{}, errors.New("index is required")
				}
				changes = append(changes, structureChange("component_reordered", "component", c.ComponentID, nil, *c.Index))
			case "remove_component":
				g, err := component(c.ComponentID)
				if err != nil {
					return nil, editAppOut{}, err
				}
				delete(compGroup, c.ComponentID)
				g.comps = slices.DeleteFunc(g.comps, func(id string) bool { return id == c.ComponentID })
				changes = append(changes, structureChange("component_removed", "component", c.ComponentID, nil, nil))
			default:
				return nil, editAppOut{}, fmt.Errorf("unknown op %s", c.Op)
			}
		}

		ev := event.Event{
			ID:        newID(),
			Type:      event.EventTypeApplicationAfterEditModeChanged,
			Version:   1,
			CreatedAt: time.Now().UnixMilli(),
			Data:      map[string]interface{}{"version": float64(1), "applicationId": in.AppID, "changes": changes},
		}
		if _, err := d.Events.AcceptEvent(ctx, &ev, u); err != nil {
			return nil, editAppOut{}, toolError(err)
		}
		return nil, editAppOut{IDs: ids}, nil
	})
}
