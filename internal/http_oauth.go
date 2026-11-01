package internal

import (
	"strings"
	"time"

	"github.com/prappser/prappser-spaces/internal/middleware"
	"github.com/prappser/prappser-spaces/internal/oauth"
	"github.com/valyala/fasthttp"
)

const oauthRateLimitPerMinute = 20

func isOAuthPath(path string) bool {
	return path == "/.well-known/oauth-authorization-server" ||
		path == "/oauth/authorize" ||
		path == "/oauth/token" ||
		strings.HasPrefix(path, "/oauth/requests/")
}

func newOAuthRouter(config *Config, endpoints *oauth.Endpoints, authMiddleware *middleware.AuthMiddleware, ipRateLimiter *middleware.RateLimiter) fasthttp.RequestHandler {
	oauthRateLimiter := middleware.NewRateLimiter(oauthRateLimitPerMinute, time.Minute, config.TrustProxyHeaders)

	notFound := func(ctx *fasthttp.RequestCtx) {
		ctx.Error("Not Found", fasthttp.StatusNotFound)
	}
	methodNotAllowed := func(ctx *fasthttp.RequestCtx) {
		ctx.Error("Method Not Allowed", fasthttp.StatusMethodNotAllowed)
	}

	return func(ctx *fasthttp.RequestCtx) {
		if !config.MCPEnabled {
			notFound(ctx)
			return
		}
		path := string(ctx.Path())
		method := string(ctx.Method())

		switch path {
		case "/.well-known/oauth-authorization-server":
			if method != "GET" {
				methodNotAllowed(ctx)
				return
			}
			ipRateLimiter.LimitByIP(endpoints.Metadata)(ctx)
			return
		case "/oauth/authorize":
			if method != "GET" {
				methodNotAllowed(ctx)
				return
			}
			oauthRateLimiter.LimitByIP(endpoints.Authorize)(ctx)
			return
		case "/oauth/token":
			if method != "POST" {
				methodNotAllowed(ctx)
				return
			}
			oauthRateLimiter.LimitByIP(endpoints.Token)(ctx)
			return
		}

		parts := strings.Split(path, "/")
		if len(parts) < 4 || len(parts) > 5 || parts[3] == "" {
			notFound(ctx)
			return
		}
		ctx.SetUserValue("requestID", parts[3])
		switch {
		case len(parts) == 4:
			if method != "GET" {
				methodNotAllowed(ctx)
				return
			}
			ipRateLimiter.LimitByIP(authMiddleware.RequireAuth(endpoints.GetRequest))(ctx)
		case parts[4] == "approve":
			if method != "POST" {
				methodNotAllowed(ctx)
				return
			}
			ipRateLimiter.LimitByIP(authMiddleware.RequireAuth(endpoints.Approve))(ctx)
		case parts[4] == "deny":
			if method != "POST" {
				methodNotAllowed(ctx)
				return
			}
			ipRateLimiter.LimitByIP(authMiddleware.RequireAuth(endpoints.Deny))(ctx)
		default:
			notFound(ctx)
		}
	}
}
