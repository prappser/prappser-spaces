package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/component"
	"github.com/prappser/prappser-spaces/internal/event"
)

type updateComponentIn struct {
	AppID       string         `json:"appId" jsonschema:"the app id from list_apps"`
	ComponentID string         `json:"componentId" jsonschema:"the component id from get_app"`
	Set         map[string]any `json:"set" jsonschema:"data keys to write, each mapped to its whole new value; a key ending in * gets a new id; '' deletes where the schema allows"`
}

type updateComponentOut struct {
	Keys []string `json:"keys"`
}

func findComponent(app *application.Application, id string) *application.Component {
	for _, g := range app.ComponentGroups {
		for i := range g.Components {
			if g.Components[i].ID == id {
				return &g.Components[i]
			}
		}
	}
	return nil
}

func gateFlags(acc component.Access, old, val any) []*component.Flag {
	if acc.Gate == nil {
		return nil
	}
	o, oldIsObj := old.(map[string]any)
	n, newIsObj := val.(map[string]any)
	if !oldIsObj || !newIsObj {
		return []*component.Flag{acc.Gate}
	}
	var flags []*component.Flag
	seen := map[string]bool{}
	for _, m := range []map[string]any{o, n} {
		for field := range m {
			if seen[field] || reflect.DeepEqual(o[field], n[field]) {
				continue
			}
			seen[field] = true
			if f, listed := acc.Fields[field]; !listed {
				flags = append(flags, acc.Gate)
			} else if f != nil {
				flags = append(flags, f)
			}
		}
	}
	return flags
}

func isAuthor(raw any, field, publicKey string) bool {
	s, _ := raw.(string)
	var m map[string]any
	if json.Unmarshal([]byte(s), &m) != nil {
		return false
	}
	return m[field] == publicKey
}

func addUpdateComponent(s *sdk.Server, d Deps) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "update_component",
		Description: "Write keys of one component's data as this account. Call describe_component with the component's type (its name in get_app) first to see keys, value encodings and x-access. " +
			"set maps key to its whole new value (no deep merge: send the full object or encoded string); '' deletes where the schema allows. " +
			"A key ending in * (such as m_*, item_* or e_*) gets a new id, returned in keys. All keys go in one change or none do. Viewers cannot write." + untrustedHint,
	}, func(ctx context.Context, req *sdk.CallToolRequest, in updateComponentIn) (*sdk.CallToolResult, updateComponentOut, error) {
		u, err := caller(req)
		if err != nil {
			return nil, updateComponentOut{}, err
		}
		if len(in.Set) == 0 {
			return nil, updateComponentOut{}, errors.New("set is empty")
		}
		app, err := d.Apps.GetApplication(in.AppID, u)
		if err != nil {
			return nil, updateComponentOut{}, toolError(err)
		}
		role := roleOf(app, u.PublicKey)
		if role == string(application.MemberRoleViewer) {
			return nil, updateComponentOut{}, errors.New("viewers cannot change this app")
		}
		privileged := role == string(application.MemberRoleOwner) || role == string(application.MemberRoleAdmin)
		comp := findComponent(app, in.ComponentID)
		if comp == nil {
			return nil, updateComponentOut{}, errors.New("component not found")
		}

		data := make(map[string]any, len(in.Set))
		for k, val := range in.Set {
			if base, minted := strings.CutSuffix(k, "*"); minted {
				k = base + newID()
			}
			data[k] = val
		}
		keys := make([]string, 0, len(data))
		access := make(map[string]component.Access, len(data))
		for k := range data {
			acc, ok := d.Validator.Access(comp.Name, k)
			if !ok {
				return nil, updateComponentOut{}, fmt.Errorf("key %s: not a key of %s", k, comp.Name)
			}
			access[k] = acc
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if err := d.Validator.ValidateComponentKeys(comp.Name, data); err != nil {
			if res, ok := validationResult(err, "invalid data"); ok {
				return res, updateComponentOut{}, nil
			}
			return nil, updateComponentOut{}, toolError(err)
		}

		changed := make(map[string]any, len(keys))
		for _, k := range keys {
			acc, old, val := access[k], comp.Data[k], data[k]
			fail := func(format string, a ...any) (*sdk.CallToolResult, updateComponentOut, error) {
				return nil, updateComponentOut{}, errors.New("key " + k + ": " + fmt.Sprintf(format, a...))
			}
			switch {
			case acc.Level == component.AccessNone:
				return fail("not writable by agents")
			case acc.Level == component.AccessManage && !privileged:
				return fail("owner or admin only")
			case !acc.OwnKey(k, u.PublicKey):
				return fail("you can only write your own cell")
			}
			if acc.Unless != nil && acc.Unless.On(comp.Data) {
				return fail("turned off by %s", acc.Unless.Name)
			}
			if !privileged {
				for _, f := range gateFlags(acc, old, val) {
					if !f.On(comp.Data) {
						return fail("turned off by %s", f.Name)
					}
				}
			}
			str, isStr := val.(string)
			if acc.Append {
				if _, exists := comp.Data[k]; exists {
					return fail("already exists")
				}
				if val == "" {
					return fail("cannot be deleted")
				}
			}
			if acc.Content != "" && isStr && str != "" {
				if err := d.Validator.ValidateContent(comp.Name, acc.Content, str); err != nil {
					if res, ok := validationResult(err, "key "+k+": invalid value"); ok {
						return res, updateComponentOut{}, nil
					}
					return nil, updateComponentOut{}, toolError(err)
				}
			}
			if acc.Author != "" {
				oldStr, _ := old.(string)
				if (isStr && str != "" && !isAuthor(str, acc.Author, u.PublicKey)) || (oldStr != "" && !isAuthor(oldStr, acc.Author, u.PublicKey)) {
					return fail("%s must be your publicKey", acc.Author)
				}
			}
			changed[k] = map[string]any{"oldValue": old, "newValue": val}
		}

		ev := event.Event{
			ID:        newID(),
			Type:      event.EventTypeComponentDataChanged,
			Version:   1,
			CreatedAt: time.Now().UnixMilli(),
			Data: map[string]interface{}{
				"version":          float64(1),
				"applicationId":    in.AppID,
				"componentId":      comp.ID,
				"componentGroupId": comp.ComponentGroupID,
				"changedFields":    changed,
			},
		}
		if _, err := d.Events.AcceptEvent(ctx, &ev, u); err != nil {
			return nil, updateComponentOut{}, toolError(err)
		}
		return nil, updateComponentOut{Keys: keys}, nil
	})
}
