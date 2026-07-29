package user

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestChallengeStore_ConcurrentAccess exercises store/get/delete/consume from
// many goroutines at once. UserEndpoints methods use value receivers, so
// challenges must be held behind a pointer to a mutex-guarded struct rather
// than a plain map field - this test is the guard against that regressing.
// Run with -race to catch data races on the underlying map.
func TestChallengeStore_ConcurrentAccess(t *testing.T) {
	store := newChallengeStore()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		key := fmt.Sprintf("public-key-%d", i%10)

		wg.Add(4)
		go func() {
			defer wg.Done()
			store.store(key, challengeInfo{challenge: "c", expiresAt: time.Now().Add(time.Minute)})
		}()
		go func() {
			defer wg.Done()
			store.get(key)
		}()
		go func() {
			defer wg.Done()
			store.delete(key)
		}()
		go func() {
			defer wg.Done()
			store.consume(key)
		}()
	}
	wg.Wait()
}

// TestChallengeStore_ConsumeIsAtomicAcrossConcurrentCallers guards against
// the TOCTOU that a separate get()-then-delete() would have: many goroutines
// race to consume the exact same challenge, and exactly one of them must
// observe it as present. A get()+delete() pair (two lock acquisitions) would
// let every concurrent caller see the challenge as present, allowing a signed
// JWS to be replayed to mint more than one JWT from a single challenge.
func TestChallengeStore_ConsumeIsAtomicAcrossConcurrentCallers(t *testing.T) {
	// given
	store := newChallengeStore()
	store.store("pk", challengeInfo{challenge: "c", expiresAt: time.Now().Add(time.Minute)})

	const attempts = 50
	var wg sync.WaitGroup
	var successCount int32
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, exists, _ := store.consume("pk"); exists {
				atomic.AddInt32(&successCount, 1)
			}
		}()
	}
	wg.Wait()

	// then - exactly one goroutine redeemed the challenge, the rest found it
	// already gone
	assert.Equal(t, int32(1), successCount)
	_, stillExists := store.get("pk")
	assert.False(t, stillExists)
}

func TestChallengeStore_StorePrunesExpiredEntries(t *testing.T) {
	// given
	store := newChallengeStore()
	store.store("expired", challengeInfo{challenge: "old", expiresAt: time.Now().Add(-time.Minute)})

	// when - storing a new entry triggers the opportunistic prune sweep
	store.store("fresh", challengeInfo{challenge: "new", expiresAt: time.Now().Add(time.Minute)})

	// then
	_, expiredExists := store.get("expired")
	fresh, freshExists := store.get("fresh")
	assert.False(t, expiredExists)
	assert.True(t, freshExists)
	assert.Equal(t, "new", fresh.challenge)
}
