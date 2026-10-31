package application

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

var (
	ErrApplicationMoving    = errors.New("application is moving")
	ErrApplicationNotMoving = errors.New("application is not moving")
	ErrNotApplicationOwner  = errors.New("not the application owner")
	ErrInvalidMoveRequest   = errors.New("invalid move request")
)

type MovedError struct {
	TargetSpaceURL string
	InviteToken    string
}

func (e *MovedError) Error() string {
	return "application moved"
}

func WriteMoveError(ctx *fasthttp.RequestCtx, err error) bool {
	var moved *MovedError
	var status int
	var payload map[string]string
	switch {
	case errors.Is(err, ErrApplicationMoving):
		status = fasthttp.StatusConflict
		payload = map[string]string{"error": err.Error(), "code": "application_moving"}
	case errors.Is(err, ErrApplicationNotMoving):
		status = fasthttp.StatusConflict
		payload = map[string]string{"error": err.Error(), "code": "application_not_moving"}
	case errors.As(err, &moved):
		status = fasthttp.StatusGone
		payload = map[string]string{
			"error":          moved.Error(),
			"code":           "application_moved",
			"targetSpaceUrl": moved.TargetSpaceURL,
			"inviteToken":    moved.InviteToken,
		}
	default:
		return false
	}
	log.Error().Err(err).Int("status", status).Msg("Application move state rejected request")
	body, _ := json.Marshal(payload)
	ctx.SetStatusCode(status)
	ctx.SetContentType("application/json")
	ctx.SetBody(body)
	return true
}

type movedEventProducer interface {
	ProduceApplicationMoved(ctx context.Context, appID, creatorPublicKey, targetSpaceURL, inviteToken string) error
}

type storageCleaner interface {
	CleanupApplicationStorage(ctx context.Context, appID string) error
}

type MoveService struct {
	repo   *Repository
	events movedEventProducer
	files  storageCleaner
}

func NewMoveService(repo *Repository, events movedEventProducer, files storageCleaner) *MoveService {
	return &MoveService{repo: repo, events: events, files: files}
}

func (ms *MoveService) authorizeOwner(appID, callerPK string) error {
	if err := ms.repo.MoveGuard(appID, callerPK, false); err != nil {
		return err
	}
	member, err := ms.repo.GetMemberByPublicKey(appID, callerPK)
	if err != nil {
		if err.Error() == "member not found" {
			return ErrNotApplicationOwner
		}
		return fmt.Errorf("failed to get member: %w", err)
	}
	if member.Role != MemberRoleOwner {
		return ErrNotApplicationOwner
	}
	return nil
}

func validTargetURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func (ms *MoveService) StartMove(appID, callerPK, targetURL string) error {
	if !validTargetURL(targetURL) {
		return ErrInvalidMoveRequest
	}
	if err := ms.authorizeOwner(appID, callerPK); err != nil {
		return err
	}
	rows, err := ms.repo.StartMove(appID, targetURL)
	if err != nil {
		return fmt.Errorf("failed to start move: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("application not found")
	}
	return nil
}

func (ms *MoveService) AbortMove(appID, callerPK string) error {
	if err := ms.authorizeOwner(appID, callerPK); err != nil {
		return err
	}
	if err := ms.repo.AbortMove(appID); err != nil {
		return fmt.Errorf("failed to abort move: %w", err)
	}
	return nil
}

func (ms *MoveService) CompleteMove(ctx context.Context, appID, callerPK, targetURL, inviteToken string) error {
	if !validTargetURL(targetURL) || inviteToken == "" {
		return ErrInvalidMoveRequest
	}
	if err := ms.authorizeOwner(appID, callerPK); err != nil {
		return err
	}
	if err := ms.repo.CompleteMove(appID, targetURL, inviteToken, time.Now().Unix()); err != nil {
		if errors.Is(err, ErrApplicationNotMoving) {
			return err
		}
		return fmt.Errorf("failed to complete move: %w", err)
	}

	if err := ms.events.ProduceApplicationMoved(ctx, appID, callerPK, targetURL, inviteToken); err != nil {
		log.Error().Err(err).Str("applicationId", appID).Msg("Failed to produce application_moved event")
	}
	if err := ms.files.CleanupApplicationStorage(ctx, appID); err != nil {
		log.Error().Err(err).Str("applicationId", appID).Msg("Failed to clean up moved application storage")
	}
	return nil
}
