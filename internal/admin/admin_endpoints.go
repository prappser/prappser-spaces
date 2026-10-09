package admin

import (
	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

type AdminEndpoints struct {
	repo   *Repository
	limits Limits
}

func NewAdminEndpoints(repo *Repository, limits Limits) *AdminEndpoints {
	return &AdminEndpoints{repo: repo, limits: limits}
}

func (e *AdminEndpoints) ListAccounts(ctx *fasthttp.RequestCtx) {
	u, ok := ctx.UserValue("user").(*user.User)
	if !ok || u == nil {
		log.Error().Msg("[ADMIN] ListAccounts without authenticated user")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}
	if u.Role != user.RoleOwner {
		log.Error().Str("role", u.Role).Msg("[ADMIN] ListAccounts by non-owner")
		ctx.Error("Forbidden", fasthttp.StatusForbidden)
		return
	}

	accounts, err := e.repo.ListAccounts()
	if err != nil {
		log.Error().Err(err).Msg("[ADMIN] Failed to list accounts")
		ctx.Error("Failed to load accounts", fasthttp.StatusInternalServerError)
		return
	}

	body, err := json.Marshal(Overview{
		Limits:   e.limits,
		Accounts: accounts,
	})
	if err != nil {
		log.Error().Err(err).Msg("[ADMIN] Failed to encode accounts")
		ctx.Error("Failed to load accounts", fasthttp.StatusInternalServerError)
		return
	}
	ctx.SetContentType("application/json")
	ctx.SetBody(body)
}
