package health

import (
	"github.com/goccy/go-json"
	"github.com/valyala/fasthttp"
)

type HealthEndpoints struct {
	version          string
	registrationOpen func() bool
	mcpEnabled       bool
}

func NewEndpoints(version string, registrationOpen func() bool, mcpEnabled bool) *HealthEndpoints {
	return &HealthEndpoints{
		version:          version,
		registrationOpen: registrationOpen,
		mcpEnabled:       mcpEnabled,
	}
}

type HealthResponse struct {
	Status           string `json:"status"`
	Version          string `json:"version"`
	RegistrationOpen bool   `json:"registrationOpen"`
	MCPEnabled       bool   `json:"mcpEnabled"`
}

func (h *HealthEndpoints) Health(ctx *fasthttp.RequestCtx) {
	response := HealthResponse{
		Status:           "ok",
		Version:          h.version,
		RegistrationOpen: h.registrationOpen(),
		MCPEnabled:       h.mcpEnabled,
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
