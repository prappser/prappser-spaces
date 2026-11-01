package mcp

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/auth"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
)

const (
	pathMCP      = "/mcp"
	pathMetadata = "/.well-known/oauth-protected-resource"
	scopeMCP     = "mcp"
)

func Mount(next fasthttp.RequestHandler, d Deps) fasthttp.RequestHandler {
	base := strings.TrimRight(d.ExternalURL, "/")
	server := newServer(d)

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
	mcpHandler := fasthttpadaptor.NewFastHTTPHandler(
		auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{
			ResourceMetadataURL:    base + pathMetadata + pathMCP,
			Scopes:                 []string{scopeMCP},
			AllowMissingExpiration: true,
		})(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, &sdk.StreamableHTTPOptions{
			Stateless:    true,
			JSONResponse: true,
		})))
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
