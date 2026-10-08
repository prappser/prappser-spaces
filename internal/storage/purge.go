package storage

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	deletedAppRetention       = 30 * 24 * time.Hour
	deletedAppPurgeBatch      = 100
	deletedAppPurgeEvery      = time.Hour
	deletedAppPurgeRunTimeout = 10 * time.Minute
)

type deletedAppPurger interface {
	GetPurgeableApplicationIDs(cutoff int64, limit int) ([]string, error)
	PurgeApplication(id string, cutoff int64) error
}

type appStorageCleaner interface {
	CleanupApplicationStorage(ctx context.Context, appID string) error
}

// DeletedAppPurgeScheduler hard-deletes applications soft-deleted longer ago
// than deletedAppRetention, along with their storage.
type DeletedAppPurgeScheduler struct {
	apps    deletedAppPurger
	storage appStorageCleaner
}

func NewDeletedAppPurgeScheduler(apps deletedAppPurger, storage appStorageCleaner) *DeletedAppPurgeScheduler {
	return &DeletedAppPurgeScheduler{apps: apps, storage: storage}
}

// Start runs once immediately (deploys would otherwise keep resetting the
// ticker) and then hourly.
func (d *DeletedAppPurgeScheduler) Start() {
	log.Info().Dur("interval", deletedAppPurgeEvery).Msg("[STORAGE] Deleted application purge scheduler started")
	go func() {
		d.runOnce()
		ticker := time.NewTicker(deletedAppPurgeEvery)
		defer ticker.Stop()
		for range ticker.C {
			d.runOnce()
		}
	}()
}

func (d *DeletedAppPurgeScheduler) runOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), deletedAppPurgeRunTimeout)
	defer cancel()
	d.PurgeDeletedApps(ctx)
}

func (d *DeletedAppPurgeScheduler) PurgeDeletedApps(ctx context.Context) {
	cutoff := time.Now().Add(-deletedAppRetention).Unix()
	ids, err := d.apps.GetPurgeableApplicationIDs(cutoff, deletedAppPurgeBatch)
	if err != nil {
		log.Error().Err(err).Msg("[STORAGE] Failed to list purgeable applications")
		return
	}

	purged := 0
	for _, id := range ids {
		if err := d.storage.CleanupApplicationStorage(ctx, id); err != nil {
			log.Error().Err(err).Str("applicationId", id).Msg("[STORAGE] Failed to clean up storage of deleted application")
			continue
		}
		if err := d.apps.PurgeApplication(id, cutoff); err != nil {
			log.Error().Err(err).Str("applicationId", id).Msg("[STORAGE] Failed to purge deleted application")
			continue
		}
		purged++
	}
	log.Info().Int("purgedCount", purged).Int("candidates", len(ids)).Msg("[STORAGE] Deleted application purge completed")
}
