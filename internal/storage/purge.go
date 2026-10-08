package storage

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	deletedAppRetention   = 30 * 24 * time.Hour
	unreferencedBlobGrace = 90 * 24 * time.Hour
	purgeBatch            = 100
	purgeEvery            = time.Hour
	purgeRunTimeout       = 10 * time.Minute
)

type deletedAppPurger interface {
	GetPurgeableApplicationIDs(cutoff int64, limit int) ([]string, error)
	PurgeApplication(id string, cutoff int64) error
}

type storagePurger interface {
	CleanupApplicationStorage(ctx context.Context, appID string) error
	PurgeUnreferenced(ctx context.Context, cutoff int64, limit int) error
}

// StoragePurgeScheduler hard-deletes applications soft-deleted longer ago
// than deletedAppRetention, along with their storage, and deletes blobs that
// nothing has referenced for unreferencedBlobGrace.
type StoragePurgeScheduler struct {
	apps    deletedAppPurger
	storage storagePurger
}

func NewStoragePurgeScheduler(apps deletedAppPurger, storage storagePurger) *StoragePurgeScheduler {
	return &StoragePurgeScheduler{apps: apps, storage: storage}
}

// Start runs once immediately (deploys would otherwise keep resetting the
// ticker) and then hourly.
func (d *StoragePurgeScheduler) Start() {
	log.Info().Dur("interval", purgeEvery).Msg("[STORAGE] Storage purge scheduler started")
	go func() {
		d.runOnce()
		ticker := time.NewTicker(purgeEvery)
		defer ticker.Stop()
		for range ticker.C {
			d.runOnce()
		}
	}()
}

func (d *StoragePurgeScheduler) runOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), purgeRunTimeout)
	defer cancel()
	d.PurgeDeletedApps(ctx)
	d.PurgeUnreferencedBlobs(ctx)
}

func (d *StoragePurgeScheduler) PurgeUnreferencedBlobs(ctx context.Context) {
	cutoff := time.Now().Add(-unreferencedBlobGrace).Unix()
	if err := d.storage.PurgeUnreferenced(ctx, cutoff, purgeBatch); err != nil {
		log.Error().Err(err).Msg("[STORAGE] Failed to purge unreferenced blobs")
	}
}

func (d *StoragePurgeScheduler) PurgeDeletedApps(ctx context.Context) {
	cutoff := time.Now().Add(-deletedAppRetention).Unix()
	ids, err := d.apps.GetPurgeableApplicationIDs(cutoff, purgeBatch)
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
