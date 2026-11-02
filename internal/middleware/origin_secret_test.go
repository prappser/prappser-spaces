package middleware

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

func TestRequireOriginSecret(t *testing.T) {
	tests := []struct {
		name, secret, method, path, header string
		want                               int
	}{
		{"no secret configured", "", "GET", "/users", "", 200},
		{"match", "s3", "GET", "/users", "s3", 200},
		{"mismatch", "s3", "GET", "/users", "nope", 403},
		{"longer mismatch", "s3", "GET", "/users", "s3s3s3s3", 403},
		{"missing", "s3", "GET", "/users", "", 403},
		{"health exempt", "s3", "GET", "/health", "", 200},
		{"health HEAD exempt", "s3", "HEAD", "/health", "", 200},
		{"health query exempt", "s3", "GET", "/health?x=1", "", 200},
		{"health POST needs secret", "s3", "POST", "/health", "", 403},
		{"health POST with secret", "s3", "POST", "/health", "s3", 200},
		{"double slash health", "s3", "GET", "//health", "", 403},
		{"health trailing slash", "s3", "GET", "/health/", "", 403},
		{"health upper case", "s3", "GET", "/HEALTH", "", 403},
		{"ws not exempt", "s3", "GET", "/ws", "", 403},
		{"mcp not exempt", "s3", "POST", "/mcp", "", 403},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := RequireOriginSecret(tt.secret, func(ctx *fasthttp.RequestCtx) { ctx.SetStatusCode(200) })
			ctx := &fasthttp.RequestCtx{}
			ctx.Request.Header.SetMethod(tt.method)
			ctx.Request.SetRequestURI(tt.path)
			if tt.header != "" {
				ctx.Request.Header.Set(OriginSecretHeader, tt.header)
			}
			h(ctx)
			assert.Equal(t, tt.want, ctx.Response.StatusCode())
		})
	}
}
