package middleware

import (
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

type AuthMiddleware struct {
	userService *user.UserService
}

func NewAuthMiddleware(userService *user.UserService) *AuthMiddleware {
	return &AuthMiddleware{
		userService: userService,
	}
}

func (am *AuthMiddleware) RequireAuth(handler fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		authenticatedUser, err := am.userService.ValidateJWTFromRequest(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Authentication failed")
			ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
			return
		}

		ctx.SetUserValue("user", authenticatedUser)

		handler(ctx)
	}
}

func (am *AuthMiddleware) RequireRole(role string, handler fasthttp.RequestHandler) fasthttp.RequestHandler {
	return am.RequireAuth(func(ctx *fasthttp.RequestCtx) {
		authenticatedUser, ok := ctx.UserValue("user").(*user.User)
		if !ok || authenticatedUser.Role != role {
			log.Error().Msg("Insufficient permissions")
			ctx.Error("Forbidden", fasthttp.StatusForbidden)
			return
		}

		handler(ctx)
	})
}