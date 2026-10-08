package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type mockPurger struct {
	ids    []string
	purged []string
}

func (m *mockPurger) GetPurgeableApplicationIDs(_ int64, _ int) ([]string, error) {
	return m.ids, nil
}

func (m *mockPurger) PurgeApplication(id string, _ int64) error {
	m.purged = append(m.purged, id)
	return nil
}

type mockCleaner struct {
	failFor string
	cutoff  int64
	limit   int
}

func (m *mockCleaner) PurgeUnreferenced(_ context.Context, cutoff int64, limit int) error {
	m.cutoff = cutoff
	m.limit = limit
	return nil
}

func (m *mockCleaner) CleanupApplicationStorage(_ context.Context, appID string) error {
	if appID == m.failFor {
		return errors.New("backend down")
	}
	return nil
}

func TestPurgeDeletedApps_ShouldPurgeAppsWhoseStorageCleanupSucceeds(t *testing.T) {
	// given
	purger := &mockPurger{ids: []string{"app-1", "app-2"}}
	sched := NewStoragePurgeScheduler(purger, &mockCleaner{})

	// when
	sched.PurgeDeletedApps(context.Background())

	// then
	assert.Equal(t, []string{"app-1", "app-2"}, purger.purged)
}

func TestPurgeDeletedApps_ShouldSkipAppWhoseStorageCleanupFails(t *testing.T) {
	// given
	purger := &mockPurger{ids: []string{"app-1", "app-2", "app-3"}}
	sched := NewStoragePurgeScheduler(purger, &mockCleaner{failFor: "app-2"})

	// when
	sched.PurgeDeletedApps(context.Background())

	// then
	assert.Equal(t, []string{"app-1", "app-3"}, purger.purged)
}

func TestPurgeUnreferencedBlobs_ShouldPassNinetyDayCutoffAndBatchLimit(t *testing.T) {
	// given
	cleaner := &mockCleaner{}
	sched := NewStoragePurgeScheduler(&mockPurger{}, cleaner)

	// when
	sched.PurgeUnreferencedBlobs(context.Background())

	// then
	want := time.Now().Add(-90 * 24 * time.Hour).Unix()
	assert.InDelta(t, want, cleaner.cutoff, 60)
	assert.Equal(t, purgeBatch, cleaner.limit)
}
