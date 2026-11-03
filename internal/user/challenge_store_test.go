package user

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func liveChallenge(key string) challengeInfo {
	return challengeInfo{publicKey: key, expiresAt: time.Now().Add(time.Minute)}
}

// Run with -race: guards against challenges regressing to an unguarded map.
func TestChallengeStore_ConcurrentAccess(t *testing.T) {
	store := newChallengeStore()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		challenge := fmt.Sprintf("challenge-%d", i%10)

		wg.Add(2)
		go func() {
			defer wg.Done()
			store.store(challenge, liveChallenge("pk"))
		}()
		go func() {
			defer wg.Done()
			_ = store.consume(challenge, "pk")
		}()
	}
	wg.Wait()
}

func TestChallengeStore_ConsumeIsAtomicAcrossConcurrentCallers(t *testing.T) {
	// given
	store := newChallengeStore()
	store.store("c", liveChallenge("pk"))

	const attempts = 50
	var wg sync.WaitGroup
	var successCount int32
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if store.consume("c", "pk") == nil {
				atomic.AddInt32(&successCount, 1)
			}
		}()
	}
	wg.Wait()

	// then
	assert.Equal(t, int32(1), successCount)
}

func TestChallengeStore_ShouldConsumeTwoChallengesOfOneDevice(t *testing.T) {
	// given
	store := newChallengeStore()
	var wg sync.WaitGroup
	for _, c := range []string{"c1", "c2"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.store(c, liveChallenge("pk"))
		}()
	}
	wg.Wait()

	// when
	errs := make([]error, 2)
	for i, c := range []string{"c1", "c2"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = store.consume(c, "pk")
		}()
	}
	wg.Wait()

	// then
	assert.NoError(t, errs[0])
	assert.NoError(t, errs[1])
}

func TestChallengeStore_ShouldFailAndBurnOnKeyMismatch(t *testing.T) {
	// given
	store := newChallengeStore()
	store.store("c", liveChallenge("pk"))

	// when
	errWrong := store.consume("c", "other")
	errRetry := store.consume("c", "pk")

	// then
	assert.Error(t, errWrong)
	assert.Error(t, errRetry)
}

func TestChallengeStore_ShouldFailOnExpiredOrUnknownChallenge(t *testing.T) {
	// given
	store := newChallengeStore()
	store.store("old", challengeInfo{publicKey: "pk", expiresAt: time.Now().Add(-time.Minute)})

	// when / then
	assert.Error(t, store.consume("old", "pk"))
	assert.Error(t, store.consume("never-issued", "pk"))
}

func TestChallengeStore_ShouldSweepExpiredBeforeEvictingWhenFull(t *testing.T) {
	// given
	store := newChallengeStore()
	store.max = 3
	store.store("expired", challengeInfo{publicKey: "pk", expiresAt: time.Now().Add(-time.Minute)})
	store.store("live1", liveChallenge("pk"))
	store.store("live2", liveChallenge("pk"))

	// when
	store.store("new", liveChallenge("pk"))

	// then
	assert.Len(t, store.data, 3)
	assert.NoError(t, store.consume("live1", "pk"))
	assert.NoError(t, store.consume("live2", "pk"))
	assert.NoError(t, store.consume("new", "pk"))
}

func TestChallengeStore_ShouldEvictOneEntryWhenFullOfLiveChallenges(t *testing.T) {
	// given
	store := newChallengeStore()
	store.max = 3
	for _, c := range []string{"a", "b", "c"} {
		store.store(c, liveChallenge("pk"))
	}

	// when
	store.store("d", liveChallenge("pk"))

	// then
	assert.Len(t, store.data, 3)
	assert.NoError(t, store.consume("d", "pk"))
}
