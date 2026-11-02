package middleware

import (
	"crypto/sha256"
	"crypto/subtle"

	"github.com/valyala/fasthttp"
)

// OriginSecretHeader carries the shared secret a fronting proxy adds to every
// request it forwards.
const OriginSecretHeader = "X-Prappser-Origin-Secret"

// RequireOriginSecret rejects with 403 any request whose OriginSecretHeader
// does not match secret, except GET and HEAD /health (platform health checks
// hit the origin directly). An empty secret disables the check.
func RequireOriginSecret(secret string, next fasthttp.RequestHandler) fasthttp.RequestHandler {
	if secret == "" {
		return next
	}
	want := sha256.Sum256([]byte(secret))
	return func(ctx *fasthttp.RequestCtx) {
		if !(ctx.IsGet() || ctx.IsHead()) || string(ctx.Path()) != "/health" {
			// Hash both sides so the compare is constant-time regardless of length.
			got := sha256.Sum256(ctx.Request.Header.Peek(OriginSecretHeader))
			if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
				ctx.Error("Forbidden", fasthttp.StatusForbidden)
				return
			}
		}
		next(ctx)
	}
}
