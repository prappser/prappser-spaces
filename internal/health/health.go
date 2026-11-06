package health

import (
	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/schemas"
	"github.com/valyala/fasthttp"
)

type HealthEndpoints struct {
	version          string
	registrationOpen func() bool
	mcpEnabled       bool
	bundles          *schemas.Service
}

func NewEndpoints(version string, registrationOpen func() bool, mcpEnabled bool, bundles *schemas.Service) *HealthEndpoints {
	return &HealthEndpoints{
		version:          version,
		registrationOpen: registrationOpen,
		mcpEnabled:       mcpEnabled,
		bundles:          bundles,
	}
}

type HealthResponse struct {
	Status           string `json:"status"`
	Version          string `json:"version"`
	RegistrationOpen bool   `json:"registrationOpen"`
	MCPEnabled       bool   `json:"mcpEnabled"`
	Bundle           int    `json:"bundle,omitempty"`
}

func (h *HealthEndpoints) Health(ctx *fasthttp.RequestCtx) {
	response := HealthResponse{
		Status:           "ok",
		Version:          h.version,
		RegistrationOpen: h.registrationOpen(),
		MCPEnabled:       h.mcpEnabled,
	}
	if cur := h.bundles.Current(); cur != nil {
		response.Bundle = cur.Bundle
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)

	responseJSON, err := json.Marshal(response)
	if err != nil {
		ctx.Error("Internal Server Error", fasthttp.StatusInternalServerError)
		return
	}

	ctx.SetBody(responseJSON)
}

func (h *HealthEndpoints) Schemas(ctx *fasthttp.RequestCtx) {
	if !ctx.IsGet() && !ctx.IsHead() {
		ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
		ctx.Response.Header.Set("Allow", "GET, HEAD")
		return
	}
	cur := h.bundles.Current()
	if cur == nil {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		return
	}
	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(cur.Container)
}
