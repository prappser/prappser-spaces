package push

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSpaceVapidService_Initialize_ShouldGenerateOnFirstCall(t *testing.T) {
	// given
	repo := newMockPushRepository()
	svc := NewSpaceVapidService(repo)

	// when
	err := svc.Initialize(context.Background())

	// then: keys generated and cached
	assert.NoError(t, err)
	assert.NotEmpty(t, svc.PublicKey())
	assert.NotEmpty(t, svc.PrivateKey())

	// and: persisted to repo
	repo.mu.Lock()
	stored := repo.spaceVapid
	repo.mu.Unlock()
	assert.NotNil(t, stored)
	assert.Equal(t, svc.PublicKey(), stored.VapidPublicKey)
	assert.Equal(t, svc.PrivateKey(), stored.VapidPrivateKey)
}

func TestSpaceVapidService_Initialize_ShouldBeIdempotentOnSecondCall(t *testing.T) {
	// given
	repo := newMockPushRepository()
	svc := NewSpaceVapidService(repo)
	assert.NoError(t, svc.Initialize(context.Background()))
	firstPub := svc.PublicKey()
	firstPriv := svc.PrivateKey()

	// when: initialize again with same repo (already has a row)
	svc2 := NewSpaceVapidService(repo)
	err := svc2.Initialize(context.Background())

	// then: same keys loaded, no new generation
	assert.NoError(t, err)
	assert.Equal(t, firstPub, svc2.PublicKey())
	assert.Equal(t, firstPriv, svc2.PrivateKey())
}

func TestSpaceVapidService_Initialize_ShouldLoadExisting(t *testing.T) {
	// given
	repo := newMockPushRepository()
	now := time.Now().Unix()
	repo.spaceVapid = &SpaceVapid{
		VapidPublicKey:  "seeded-pub",
		VapidPrivateKey: "seeded-priv",
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	svc := NewSpaceVapidService(repo)

	// when
	err := svc.Initialize(context.Background())

	// then: cached keys match seeded values
	assert.NoError(t, err)
	assert.Equal(t, "seeded-pub", svc.PublicKey())
	assert.Equal(t, "seeded-priv", svc.PrivateKey())
}
