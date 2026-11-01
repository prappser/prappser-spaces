package mcp

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"

	"github.com/prappser/prappser-spaces/internal/middleware"
	"github.com/prappser/prappser-spaces/internal/user"
)

const (
	pathMCP      = "/mcp"
	pathMetadata = "/.well-known/oauth-protected-resource"
	scopeMCP     = "mcp"

	ipLimitPerMinute     = 120
	deviceLimitPerMinute = 60
	maxBodyBytes         = 128 * 1024
)

func limitByDevice(rl *middleware.RateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if info := auth.TokenInfoFromContext(r.Context()); info != nil {
			key := info.UserID
			if u, ok := info.Extra["user"].(*user.User); ok && u.DevicePublicKey != "" {
				key = u.DevicePublicKey
			}
			if allowed, retryAfter := rl.Allow(key); !allowed {
				w.Header().Set("Retry-After", strconv.Itoa(max(1, int(retryAfter.Seconds()))))
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func Mount(next fasthttp.RequestHandler, d Deps) fasthttp.RequestHandler {
	base := strings.TrimRight(d.ExternalURL, "/")
	server := newServer(d)
	ipLimiter := middleware.NewRateLimiter(ipLimitPerMinute, time.Minute, d.TrustProxyHeaders)
	deviceLimiter := middleware.NewRateLimiter(deviceLimitPerMinute, time.Minute, d.TrustProxyHeaders)

	verifier := func(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		u, err := d.Agents.ValidateAccessToken(token)
		if err != nil {
			// no detail: a 401 must not say why the token failed
			return nil, fmt.Errorf("%w", auth.ErrInvalidToken)
		}
		return &auth.TokenInfo{Scopes: []string{scopeMCP}, UserID: u.PublicKey, Extra: map[string]any{"user": u}}, nil
	}
	// JSONResponse because the fasthttp adaptor cannot stream SSE.
	// AllowMissingExpiration because ValidateAccessToken already requires exp and the verifier does not surface it.
	adapted := fasthttpadaptor.NewFastHTTPHandler(
		auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{
			ResourceMetadataURL:    base + pathMetadata + pathMCP,
			Scopes:                 []string{scopeMCP},
			AllowMissingExpiration: true,
		})(limitByDevice(deviceLimiter, sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, &sdk.StreamableHTTPOptions{
			Stateless:    true,
			JSONResponse: true,
		}))))
	mcpHandler := ipLimiter.LimitByIP(func(ctx *fasthttp.RequestCtx) {
		if ctx.Request.Header.ContentLength() > maxBodyBytes || len(ctx.Request.Body()) > maxBodyBytes {
			ctx.Error("Request Entity Too Large", fasthttp.StatusRequestEntityTooLarge)
			return
		}
		adapted(ctx)
	})
	metadataHandler := fasthttpadaptor.NewFastHTTPHandler(auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               base + pathMCP,
		AuthorizationServers:   []string{base},
		ScopesSupported:        []string{scopeMCP},
		BearerMethodsSupported: []string{"header"},
	}))

	return func(ctx *fasthttp.RequestCtx) {
		switch string(ctx.Path()) {
		case pathMCP:
			mcpHandler(ctx)
		case pathMetadata, pathMetadata + pathMCP:
			metadataHandler(ctx)
		default:
			next(ctx)
		}
	}
}
