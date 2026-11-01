package mcp

import (
	"context"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type getAppIn struct {
	AppID string `json:"appId" jsonschema:"the app id from list_apps"`
}

type componentView struct {
	ID   string         `json:"id"`
	Name string         `json:"name"`
	Data map[string]any `json:"data"`
}

type groupView struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Components []componentView `json:"components"`
}

type memberView struct {
	DisplayName string `json:"displayName"`
	Role        string `json:"role"`
}

type appContent struct {
	Name            string       `json:"name"`
	ComponentGroups []groupView  `json:"componentGroups"`
	Members         []memberView `json:"members"`
}

type getAppOut struct {
	ID        string     `json:"id"`
	Role      string     `json:"role"`
	Note      string     `json:"note"`
	Untrusted appContent `json:"untrusted"`
}

func addGetApp(s *sdk.Server, d Deps) {
	sdk.AddTool(s, &sdk.Tool{
		Name:        "get_app",
		Description: "Get one app with its component groups, components (including chat messages) and members." + untrustedHint,
	}, func(_ context.Context, req *sdk.CallToolRequest, in getAppIn) (*sdk.CallToolResult, getAppOut, error) {
		u, err := caller(req)
		if err != nil {
			return nil, getAppOut{}, err
		}
		app, err := d.Apps.GetApplication(in.AppID, u)
		if err != nil {
			return nil, getAppOut{}, toolError(err)
		}
		content := appContent{Name: app.Name, ComponentGroups: make([]groupView, 0, len(app.ComponentGroups)), Members: make([]memberView, 0, len(app.Members))}
		for _, g := range app.ComponentGroups {
			gv := groupView{ID: g.ID, Name: g.Name, Components: make([]componentView, 0, len(g.Components))}
			for _, c := range g.Components {
				data := c.Data
				if data == nil {
					data = map[string]any{}
				}
				gv.Components = append(gv.Components, componentView{ID: c.ID, Name: c.Name, Data: data})
			}
			content.ComponentGroups = append(content.ComponentGroups, gv)
		}
		for _, m := range app.Members {
			name := ""
			if m.UserDisplayName != nil {
				name = *m.UserDisplayName
			}
			content.Members = append(content.Members, memberView{DisplayName: name, Role: string(m.Role)})
		}
		return nil, getAppOut{ID: app.ID, Role: roleOf(app, u.PublicKey), Note: untrustedNote, Untrusted: content}, nil
	})
}
