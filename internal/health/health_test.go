package health

import (
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

func healthBody(t *testing.T, open bool, mcpEnabled bool) HealthResponse {
	t.Helper()
	ctx := &fasthttp.RequestCtx{}

	NewEndpoints("1.0.0", func() bool { return open }, mcpEnabled).Health(ctx)

	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
	var body HealthResponse
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &body))
	return body
}

func TestHealth_RegistrationOpen_ShouldReportTrue(t *testing.T) {
	// given / when
	body := healthBody(t, true, false)

	// then
	assert.True(t, body.RegistrationOpen)
	assert.Equal(t, "ok", body.Status)
}

func TestHealth_RegistrationClosed_ShouldReportFalse(t *testing.T) {
	// given / when
	body := healthBody(t, false, false)

	// then
	assert.False(t, body.RegistrationOpen)
}

func TestHealth_MCPEnabled_ShouldReportTrue(t *testing.T) {
	// given / when
	body := healthBody(t, false, true)

	// then
	assert.True(t, body.MCPEnabled)
}

func TestHealth_MCPDisabled_ShouldReportFalse(t *testing.T) {
	// given / when
	body := healthBody(t, false, false)

	// then
	assert.False(t, body.MCPEnabled)
}
