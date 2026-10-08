package storage

import (
	"context"
	"errors"
	"testing"

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
	sched := NewDeletedAppPurgeScheduler(purger, &mockCleaner{})

	// when
	sched.PurgeDeletedApps(context.Background())

	// then
	assert.Equal(t, []string{"app-1", "app-2"}, purger.purged)
}

func TestPurgeDeletedApps_ShouldSkipAppWhoseStorageCleanupFails(t *testing.T) {
	// given
	purger := &mockPurger{ids: []string{"app-1", "app-2", "app-3"}}
	sched := NewDeletedAppPurgeScheduler(purger, &mockCleaner{failFor: "app-2"})

	// when
	sched.PurgeDeletedApps(context.Background())

	// then
	assert.Equal(t, []string{"app-1", "app-3"}, purger.purged)
}
