package profile

import (
	"context"
	"database/sql"
	"time"

	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/application"
	"github.com/prappser/prappser-spaces/internal/event"
	"github.com/prappser/prappser-spaces/internal/user"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

// blobDeleter is the narrow interface AccountEndpoints needs from *storage.Service.
type blobDeleter interface {
	DeletePersonalBlobs(ctx context.Context, publicKey string) error
}

type AccountEndpoints struct {
	db           *sql.DB
	appRepo      appLister
	eventService EventService
	blobs        blobDeleter
}

func NewAccountEndpoints(db *sql.DB, appRepo appLister, eventService EventService, blobs blobDeleter) *AccountEndpoints {
	return &AccountEndpoints{db: db, appRepo: appRepo, eventService: eventService, blobs: blobs}
}

// DeleteAccount handles DELETE /users/me: it leaves or deletes every app of the
// caller, then erases the account. The space owner cannot delete itself.
func (e *AccountEndpoints) DeleteAccount(ctx *fasthttp.RequestCtx) {
	u, ok := ctx.UserValue("user").(*user.User)
	if !ok || u == nil {
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}
	pk := u.PublicKey

	if u.Role == user.RoleOwner {
		body, _ := json.Marshal(map[string]string{"error": "the space owner cannot delete the account", "code": "space_owner"})
		ctx.SetStatusCode(fasthttp.StatusConflict)
		ctx.SetContentType("application/json")
		ctx.SetBody(body)
		return
	}

	if _, err := e.db.Exec(`UPDATE users SET avatar_storage_id = NULL WHERE public_key = $1`, pk); err != nil {
		log.Error().Err(err).Str("publicKey", pk).Msg("[PROFILE] Failed to clear avatar pointer")
		ctx.Error("Failed to delete account", fasthttp.StatusInternalServerError)
		return
	}

	if err := e.blobs.DeletePersonalBlobs(ctx, pk); err != nil {
		log.Error().Err(err).Str("publicKey", pk).Msg("[PROFILE] Failed to delete personal blobs")
		ctx.Error("Failed to delete account", fasthttp.StatusInternalServerError)
		return
	}

	apps, err := e.appRepo.GetApplicationsByMemberPublicKey(pk)
	if err != nil {
		log.Error().Err(err).Str("publicKey", pk).Msg("[PROFILE] Failed to look up member apps")
		ctx.Error("Failed to delete account", fasthttp.StatusInternalServerError)
		return
	}

	// ponytail: a concurrent CreateApplication upsert can clear deleted_at and
	// revive an app deleted below, and two co-owners deleting concurrently can
	// each emit member_removed and leave an ownerless app; accepted, the window
	// is one request.
	var soleOwned []string
	for _, app := range apps {
		evt := &event.Event{
			ID:               newEventID(),
			CreatorPublicKey: pk,
			ApplicationID:    app.ID,
		}
		if app.SpaceID != nil {
			evt.SpaceID = *app.SpaceID
		}
		if soleOwner(app, pk) {
			soleOwned = append(soleOwned, app.ID)
			evt.Type = event.EventTypeApplicationDeleted
			evt.Data = map[string]interface{}{
				"version":       1,
				"applicationId": app.ID,
				"deletedAt":     time.Now().UnixMilli(),
			}
		} else {
			evt.Type = event.EventTypeMemberRemoved
			evt.Data = map[string]interface{}{
				"version":         1,
				"applicationId":   app.ID,
				"memberPublicKey": pk,
				"reason":          "account_deleted",
			}
		}
		if _, err := e.eventService.ProduceEvent(ctx, evt); err != nil {
			log.Error().Err(err).Str("applicationId", app.ID).Msg("[PROFILE] Failed to produce account deletion event")
			ctx.Error("Failed to delete account", fasthttp.StatusInternalServerError)
			return
		}
	}

	if err := e.eraseAccount(pk, soleOwned); err != nil {
		log.Error().Err(err).Str("publicKey", pk).Msg("[PROFILE] Failed to erase account rows")
		ctx.Error("Failed to delete account", fasthttp.StatusInternalServerError)
		return
	}

	log.Info().Str("publicKey", pk).Int("applications", len(apps)).Msg("[PROFILE] Account deleted")
	ctx.SetStatusCode(fasthttp.StatusNoContent)
}

// soleOwner reports whether pk is an owner of app and no other active member is.
func soleOwner(app *application.Application, pk string) bool {
	isOwner := false
	for _, m := range app.Members {
		if m.Role != application.MemberRoleOwner {
			continue
		}
		if m.PublicKey != pk {
			return false
		}
		isOwner = true
	}
	return isOwner
}

func (e *AccountEndpoints) eraseAccount(pk string, soleOwned []string) error {
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	// ProduceEvent swallows execution errors, so soft-delete explicitly.
	for _, id := range soleOwned {
		if _, err := tx.Exec(`UPDATE applications SET deleted_at = $1 WHERE id = $2 AND deleted_at IS NULL`, time.Now().Unix(), id); err != nil {
			return err
		}
	}

	// spaces.user_public_key has no ON DELETE action; null it so the user row can go.
	stmts := []string{
		`DELETE FROM storage WHERE uploader_public_key = $1 AND application_id IS NULL`,
		`DELETE FROM events WHERE application_id IS NULL AND creator_public_key = $1`,
		`DELETE FROM members WHERE public_key = $1`,
		`UPDATE spaces SET user_public_key = NULL WHERE user_public_key = $1`,
		`DELETE FROM users WHERE public_key = $1`,
	}
	for _, q := range stmts {
		if _, err := tx.Exec(q, pk); err != nil {
			return err
		}
	}
	return tx.Commit()
}
