package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
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

// A missing field and a zero value count as unchanged, so creating an item with checked:false needs no toggle flag.
func orZero(v any) any {
	switch v {
	case false, "", 0.0:
		return nil
	}
	return v
}

func gateFlags(acc component.Access, old, val any) []*component.Flag {
	if acc.Gate == nil && len(acc.Fields) == 0 {
		return nil
	}
	o, oldIsObj := old.(map[string]any)
	n, _ := val.(map[string]any)
	var flags []*component.Flag
	add := func(f *component.Flag) {
		if f != nil && !slices.Contains(flags, f) {
			flags = append(flags, f)
		}
	}
	if !oldIsObj {
		add(acc.Gate)
	}
	for _, m := range []map[string]any{o, n} {
		for field := range m {
			if reflect.DeepEqual(orZero(o[field]), orZero(n[field])) {
				continue
			}
			if f, listed := acc.Fields[field]; listed {
				add(f)
			} else {
				add(acc.Gate)
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

func mintKeys(set map[string]any) map[string]any {
	data := make(map[string]any, len(set))
	for k, val := range set {
		if base, minted := strings.CutSuffix(k, "*"); minted {
			k = base + newID()
		}
		data[k] = val
	}
	return data
}

func checkWrite(v *component.Validator, typ string, old, data map[string]any, publicKey string, privileged bool, validate func(string, map[string]any) error) ([]string, *sdk.CallToolResult, error) {
	keys := make([]string, 0, len(data))
	access := make(map[string]component.Access, len(data))
	for k := range data {
		acc, ok := v.Access(typ, k)
		if !ok {
			return nil, nil, fmt.Errorf("key %s: not a key of %s", k, typ)
		}
		access[k] = acc
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		acc, oldVal, val := access[k], old[k], data[k]
		fail := func(format string, a ...any) ([]string, *sdk.CallToolResult, error) {
			return nil, nil, errors.New("key " + k + ": " + fmt.Sprintf(format, a...))
		}
		switch {
		case acc.Level == component.AccessNone:
			return fail("not writable by agents")
		case acc.Level == component.AccessManage && !privileged:
			return fail("owner or admin only")
		case !acc.OwnKey(k, publicKey):
			return fail("you can only write your own cell")
		}
		if acc.Unless != nil && acc.Unless.On(old) {
			return fail("turned off by %s", acc.Unless.Name)
		}
		if !privileged {
			for _, f := range gateFlags(acc, oldVal, val) {
				if !f.On(old) {
					return fail("turned off by %s", f.Name)
				}
			}
		}
		str, isStr := val.(string)
		if acc.Append {
			if _, exists := old[k]; exists {
				return fail("already exists")
			}
			if val == "" {
				return fail("cannot be deleted")
			}
		}
		if acc.Author != "" {
			oldStr, _ := oldVal.(string)
			if (isStr && str != "" && !isAuthor(str, acc.Author, publicKey)) || (oldStr != "" && !isAuthor(oldStr, acc.Author, publicKey)) {
				return fail("%s must be your publicKey", acc.Author)
			}
		}
	}
	if err := validate(typ, data); err != nil {
		if res, ok := validationResult(err, "invalid data"); ok {
			return nil, res, nil
		}
		return nil, nil, toolError(err)
	}

	for _, k := range keys {
		acc := access[k]
		if str, ok := data[k].(string); acc.Content != "" && ok && str != "" {
			if err := v.ValidateContent(typ, acc.Content, str); err != nil {
				if res, ok := validationResult(err, "key "+k+": invalid value"); ok {
					return nil, res, nil
				}
				return nil, nil, toolError(err)
			}
		}
	}
	return keys, nil, nil
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

		data := mintKeys(in.Set)
		keys, res, err := checkWrite(d.Validator, comp.Name, comp.Data, data, u.PublicKey, privileged, d.Validator.ValidateComponentKeys)
		if res != nil || err != nil {
			return res, updateComponentOut{}, err
		}
		changed := make(map[string]any, len(keys))
		for _, k := range keys {
			changed[k] = map[string]any{"oldValue": comp.Data[k], "newValue": data[k]}
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
