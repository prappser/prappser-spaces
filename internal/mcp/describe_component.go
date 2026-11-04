package mcp

import (
	"context"
	"errors"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/prappser/prappser-spaces/internal/component"
)

type describeComponentIn struct {
	Type string `json:"type,omitempty" jsonschema:"a component type from get_app, such as Checklist; omit to list all types"`
}

type describeComponentOut struct {
	Types  []component.TypeInfo `json:"types,omitempty"`
	Type   string               `json:"type,omitempty"`
	Schema any                  `json:"schema,omitempty"`
}

func addDescribeComponent(s *sdk.Server, d Deps) {
	sdk.AddTool(s, &sdk.Tool{
		Name:        "describe_component",
		Description: "Describe a component type: with no type, list all types; with a type, return its JSON Schema. The schema's x-access annotations and descriptions say who may write which key and how values are encoded. Use it before update_component.",
	}, func(_ context.Context, req *sdk.CallToolRequest, in describeComponentIn) (*sdk.CallToolResult, describeComponentOut, error) {
		if _, err := caller(req); err != nil {
			return nil, describeComponentOut{}, err
		}
		if in.Type == "" {
			return nil, describeComponentOut{Types: d.Validator.Types()}, nil
		}
		raw, ok := d.Validator.Schema(in.Type)
		if !ok {
			return nil, describeComponentOut{}, errors.New("unknown component type, call describe_component with no type")
		}
		return nil, describeComponentOut{Type: in.Type, Schema: raw}, nil
	})
}
