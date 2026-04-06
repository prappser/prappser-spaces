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

func (am *AuthMiddleware) RequireRole(handler fasthttp.RequestHandler, roles ...string) fasthttp.RequestHandler {
	return am.RequireAuth(func(ctx *fasthttp.RequestCtx) {
		authenticatedUser, ok := ctx.UserValue("user").(*user.User)
		if !ok {
			log.Error().Msg("Insufficient permissions")
			ctx.Error("Forbidden", fasthttp.StatusForbidden)
			return
		}

		for _, role := range roles {
			if authenticatedUser.Role == role {
				handler(ctx)
				return
			}
		}

		log.Error().Str("role", authenticatedUser.Role).Msg("Insufficient permissions")
		ctx.Error("Forbidden", fasthttp.StatusForbidden)
	})
}