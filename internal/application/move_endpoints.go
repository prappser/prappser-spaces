package application

import (
	"errors"

	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

type MoveEndpoints struct {
	moveService *MoveService
}

func NewMoveEndpoints(moveService *MoveService) *MoveEndpoints {
	return &MoveEndpoints{moveService: moveService}
}

type moveRequest struct {
	TargetSpaceURL string `json:"targetSpaceUrl"`
	InviteToken    string `json:"inviteToken"`
}

func (me *MoveEndpoints) StartMove(ctx *fasthttp.RequestCtx) {
	authenticatedUser, appID, ok := me.caller(ctx)
	if !ok {
		return
	}
	var req moveRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		log.Error().Err(err).Msg("Invalid start move request body")
		ctx.Error("targetSpaceUrl is required", fasthttp.StatusBadRequest)
		return
	}
	if err := me.moveService.StartMove(appID, authenticatedUser.PublicKey, req.TargetSpaceURL); err != nil {
		if errors.Is(err, ErrInvalidMoveRequest) {
			log.Error().Err(err).Msg("Invalid start move request body")
			ctx.Error("targetSpaceUrl is required", fasthttp.StatusBadRequest)
			return
		}
		me.writeError(ctx, err, "Failed to start move")
		return
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
}

func (me *MoveEndpoints) AbortMove(ctx *fasthttp.RequestCtx) {
	authenticatedUser, appID, ok := me.caller(ctx)
	if !ok {
		return
	}
	if err := me.moveService.AbortMove(appID, authenticatedUser.PublicKey); err != nil {
		me.writeError(ctx, err, "Failed to abort move")
		return
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
}

func (me *MoveEndpoints) CompleteMove(ctx *fasthttp.RequestCtx) {
	authenticatedUser, appID, ok := me.caller(ctx)
	if !ok {
		return
	}
	var req moveRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		log.Error().Err(err).Msg("Invalid complete move request body")
		ctx.Error("targetSpaceUrl and inviteToken are required", fasthttp.StatusBadRequest)
		return
	}
	if err := me.moveService.CompleteMove(ctx, appID, authenticatedUser.PublicKey, req.TargetSpaceURL, req.InviteToken); err != nil {
		if errors.Is(err, ErrInvalidMoveRequest) {
			log.Error().Err(err).Msg("Invalid complete move request body")
			ctx.Error("targetSpaceUrl and inviteToken are required", fasthttp.StatusBadRequest)
			return
		}
		me.writeError(ctx, err, "Failed to complete move")
		return
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
}

func (me *MoveEndpoints) caller(ctx *fasthttp.RequestCtx) (*user.User, string, bool) {
	authenticatedUser, ok := ctx.UserValue("user").(*user.User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return nil, "", false
	}
	appID, _ := ctx.UserValue("appID").(string)
	if appID == "" {
		ctx.Error("Application ID is required", fasthttp.StatusBadRequest)
		return nil, "", false
	}
	return authenticatedUser, appID, true
}

func (me *MoveEndpoints) writeError(ctx *fasthttp.RequestCtx, err error, msg string) {
	if WriteMoveError(ctx, err) {
		return
	}
	if errors.Is(err, ErrNotApplicationOwner) {
		log.Error().Err(err).Msg(msg)
		ctx.Error("Forbidden", fasthttp.StatusForbidden)
		return
	}
	if err.Error() == "application not found" {
		log.Error().Err(err).Msg(msg)
		ctx.Error("Application not found", fasthttp.StatusNotFound)
		return
	}
	log.Error().Err(err).Msg(msg)
	ctx.Error(msg, fasthttp.StatusInternalServerError)
}
