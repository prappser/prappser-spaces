package mcp

import (
	"context"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type listAppsIn struct{}

type appName struct {
	Name string `json:"name"`
}

type listedApp struct {
	ID        string  `json:"id"`
	Role      string  `json:"role"`
	Untrusted appName `json:"untrusted"`
}

type listAppsOut struct {
	Note string      `json:"note"`
	Apps []listedApp `json:"apps"`
}

func addListApps(s *sdk.Server, d Deps) {
	sdk.AddTool(s, &sdk.Tool{
		Name:        "list_apps",
		Description: "List the apps this account is a member of and that are open to agents." + untrustedHint,
	}, func(_ context.Context, req *sdk.CallToolRequest, _ listAppsIn) (*sdk.CallToolResult, listAppsOut, error) {
		u, err := caller(req)
		if err != nil {
			return nil, listAppsOut{}, err
		}
		apps, err := d.Apps.ListApplications(u)
		if err != nil {
			return nil, listAppsOut{}, toolError(err)
		}
		out := listAppsOut{Note: untrustedNote, Apps: make([]listedApp, 0, len(apps))}
		for _, a := range apps {
			out.Apps = append(out.Apps, listedApp{ID: a.ID, Role: roleOf(a, u.PublicKey), Untrusted: appName{Name: a.Name}})
		}
		return nil, out, nil
	})
}
