package mcp

import (
	"context"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/prappser/prappser-spaces/internal/invitation"
)

type createInviteIn struct {
	AppID          string `json:"appId" jsonschema:"the app id from list_apps"`
	Role           string `json:"role,omitempty" jsonschema:"admin, member or viewer; defaults to member"`
	ExpiresInHours *int   `json:"expiresInHours,omitempty" jsonschema:"hours until the link expires"`
	MaxUses        *int   `json:"maxUses,omitempty" jsonschema:"how many people may use the link"`
}

type createInviteOut struct {
	URL       string `json:"url"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

func addCreateInvite(s *sdk.Server, d Deps) {
	sdk.AddTool(s, &sdk.Tool{
		Name:        "create_invite",
		Description: "Create an invite link to an app. Only the app owner or an admin can do this.",
	}, func(_ context.Context, req *sdk.CallToolRequest, in createInviteIn) (*sdk.CallToolResult, createInviteOut, error) {
		u, err := caller(req)
		if err != nil {
			return nil, createInviteOut{}, err
		}
		inv, err := d.Invitations.CreateInvitation(u, invitation.CreateInvitationOptions{
			ApplicationID:  in.AppID,
			Role:           in.Role,
			ExpiresInHours: in.ExpiresInHours,
			MaxUses:        in.MaxUses,
		})
		if err != nil {
			return nil, createInviteOut{}, toolError(err)
		}
		out := createInviteOut{URL: inv.URL}
		if inv.ExpiresAt != nil {
			out.ExpiresAt = time.Unix(*inv.ExpiresAt, 0).UTC().Format(time.RFC3339)
		}
		return nil, out, nil
	})
}
