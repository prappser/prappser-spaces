package httputil

import "github.com/valyala/fasthttp"

// PublicURL trusts X-Forwarded-Proto and X-Forwarded-Host. Deploy behind a proxy
// that strips client-supplied values, or use override on direct-exposure setups.
func PublicURL(ctx *fasthttp.RequestCtx, override string) string {
	if override != "" {
		return override
	}
	scheme := string(ctx.Request.Header.Peek("X-Forwarded-Proto"))
	if scheme == "" {
		if ctx.IsTLS() {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := string(ctx.Request.Header.Peek("X-Forwarded-Host"))
	if host == "" {
		host = string(ctx.Host())
	}
	return scheme + "://" + host
}
