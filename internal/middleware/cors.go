package middleware

import (
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

type CORSMiddleware struct {
	allowedOrigins []string
	localhostRegex *regexp.Regexp
}

func NewCORSMiddleware(allowedOrigins []string) *CORSMiddleware {
	if len(allowedOrigins) == 0 {
		// Default: allow prappser.app and localhost for development
		allowedOrigins = []string{"https://prappser.app", "http://localhost:*", "https://localhost:*"}
	}
	// Compile regex for localhost with any port
	localhostRegex := regexp.MustCompile(`^https?://localhost:\d+$`)
	return &CORSMiddleware{
		allowedOrigins: allowedOrigins,
		localhostRegex: localhostRegex,
	}
}

func (cm *CORSMiddleware) Handle(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		origin := string(ctx.Request.Header.Peek("Origin"))
		referer := string(ctx.Request.Header.Peek("Referer"))
		auth := string(ctx.Request.Header.Peek("Authorization"))

		// Fallback: extract origin from Referer if Origin is empty
		if origin == "" && referer != "" {
			origin = extractOriginFromURL(referer)
		}
		origin = strings.TrimSpace(origin)

		isAllowed := cm.isOriginAllowed(origin)

		log.Debug().
			Str("origin", origin).
			Str("referer", referer).
			Bool("hasAuth", auth != "").
			Str("method", string(ctx.Method())).
			Str("path", string(ctx.Path())).
			Bool("isAllowed", isAllowed).
			Msg("CORS check")

		if string(ctx.Method()) == "OPTIONS" {
			cm.setCORSHeaders(ctx, origin, isAllowed)
			ctx.SetStatusCode(fasthttp.StatusNoContent)
			return
		}

		next(ctx)

		cm.setCORSHeaders(ctx, origin, isAllowed)
	}
}

func (cm *CORSMiddleware) setCORSHeaders(ctx *fasthttp.RequestCtx, origin string, isAllowed bool) {
	if isAllowed && origin != "" {
		ctx.Response.Header.Set("Access-Control-Allow-Origin", origin)
		ctx.Response.Header.Set("Access-Control-Allow-Credentials", "true")
	} else if len(cm.allowedOrigins) == 1 && cm.allowedOrigins[0] == "*" {
		ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	}

	ctx.Response.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	ctx.Response.Header.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	ctx.Response.Header.Set("Access-Control-Expose-Headers", "Authorization, Content-Type")
	ctx.Response.Header.Set("Access-Control-Max-Age", "86400")
}

func extractOriginFromURL(url string) string {
	// Extract origin (scheme + host) from URL like "https://prappser.app/some/path"
	if idx := strings.Index(url, "://"); idx != -1 {
		rest := url[idx+3:]
		if slashIdx := strings.Index(rest, "/"); slashIdx != -1 {
			return url[:idx+3+slashIdx]
		}
		return url
	}
	return ""
}

func (cm *CORSMiddleware) isOriginAllowed(origin string) bool {
	// Wildcard allows all origins
	if len(cm.allowedOrigins) == 1 && cm.allowedOrigins[0] == "*" {
		return true
	}

	// Check exact match or localhost pattern
	for _, allowed := range cm.allowedOrigins {
		if allowed == origin {
			return true
		}
		// Check if allowed origin is a localhost pattern
		if allowed == "http://localhost:*" || allowed == "https://localhost:*" {
			if cm.localhostRegex.MatchString(origin) {
				return true
			}
		}
	}
	return false
}
