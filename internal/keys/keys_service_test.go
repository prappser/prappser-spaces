package keys

import (
	"context"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

// countingKeyRepo is a keyRepository stub that counts TouchLastSeen calls
// and signals each one on touched, letting tests observe TouchLastSeen's
// fire-and-forget goroutine (see KeyService.TouchLastSeen) without a
// database.
type countingKeyRepo struct {
	mu      sync.Mutex
	touches int
	touched chan struct{}
}

func newCountingKeyRepo() *countingKeyRepo {
	return &countingKeyRepo{touched: make(chan struct{}, 8)}
}

func (r *countingKeyRepo) GetSpaceKey(ctx context.Context) (*EncryptedKey, error) { return nil, nil }
func (r *countingKeyRepo) SaveSpaceKey(ctx context.Context, enc *EncryptedKey) error {
	return nil
}

func (r *countingKeyRepo) TouchLastSeen(ctx context.Context, ts int64) error {
	r.mu.Lock()
	r.touches++
	r.mu.Unlock()
	r.touched <- struct{}{}
	return nil
}

func (r *countingKeyRepo) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.touches
}

// waitForTouch blocks until a TouchLastSeen write lands, failing the test if
// none arrives - the write happens in a goroutine, so callers can't just
// check the counter immediately after calling TouchLastSeen.
func waitForTouch(t *testing.T, repo *countingKeyRepo) {
	t.Helper()
	select {
	case <-repo.touched:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for TouchLastSeen write")
	}
}

// assertNoTouch fails the test if a TouchLastSeen write lands within a short
// window - used to prove the throttle skipped a write.
func assertNoTouch(t *testing.T, repo *countingKeyRepo) {
	t.Helper()
	select {
	case <-repo.touched:
		t.Fatal("unexpected TouchLastSeen write within throttle window")
	case <-time.After(50 * time.Millisecond):
	}
}

// newThrottleTestService builds a KeyService with only the fields
// TouchLastSeen touches - no DB, no keypair - with an overridable throttle
// window (see KeyService.touchThrottle) so tests don't wait on the real
// 5-minute lastSeenTouchThrottle.
func newThrottleTestService(repo *countingKeyRepo, throttle time.Duration) *KeyService {
	return &KeyService{repo: repo, touchThrottle: throttle}
}

// TestTouchLastSeen_ShouldSkipWriteOnSecondCallWithinThrottleWindow covers
// the throttle's main job: a second call arriving before touchThrottle has
// elapsed must not hit the repo again.
func TestTouchLastSeen_ShouldSkipWriteOnSecondCallWithinThrottleWindow(t *testing.T) {
	// given
	repo := newCountingKeyRepo()
	svc := newThrottleTestService(repo, time.Hour)

	// when
	svc.TouchLastSeen()
	waitForTouch(t, repo)
	svc.TouchLastSeen()

	// then
	assertNoTouch(t, repo)
	assert.Equal(t, 1, repo.count())
}

// TestTouchLastSeen_ShouldWriteAgainAfterThrottleWindowElapses covers the
// other half: once touchThrottle has elapsed, the next call must write.
func TestTouchLastSeen_ShouldWriteAgainAfterThrottleWindowElapses(t *testing.T) {
	// given
	repo := newCountingKeyRepo()
	svc := newThrottleTestService(repo, 20*time.Millisecond)

	// when
	svc.TouchLastSeen()
	waitForTouch(t, repo)
	time.Sleep(30 * time.Millisecond)
	svc.TouchLastSeen()

	// then
	waitForTouch(t, repo)
	assert.Equal(t, 2, repo.count())
}

// newImportTestService builds a KeyService wired for the importIdentity path
// only - no NewKeyService, since that constructor takes a concrete
// *KeyRepository and this test needs a DB-less stub (see countingKeyRepo).
// Mirrors newThrottleTestService's struct-literal approach above.
func newImportTestService(repo keyRepository, masterPassword, importBlob, importPassphrase string) *KeyService {
	return &KeyService{
		repo:             repo,
		masterPassword:   masterPassword,
		importBlob:       importBlob,
		importPassphrase: importPassphrase,
		touchThrottle:    lastSeenTouchThrottle,
	}
}

// tamperIdentityBlobPub rebuilds blob with its "pub" field replaced by a
// different, still valid-length public key - simulating a corrupted export
// that decodes and decrypts cleanly but was assembled inconsistently (see
// KeyService.importIdentity's corruption check).
func tamperIdentityBlobPub(t *testing.T, blob string, otherPub []byte) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(blob, identityBlobPrefix))
	assert.NoError(t, err)

	var payload identityBlobPayload
	assert.NoError(t, json.Unmarshal(raw, &payload))
	payload.Pub = base64.StdEncoding.EncodeToString(otherPub)

	tampered, err := json.Marshal(payload)
	assert.NoError(t, err)
	return identityBlobPrefix + base64.RawURLEncoding.EncodeToString(tampered)
}

// TestImportIdentity_ShouldErrorWhenBlobPubDoesNotMatchDecryptedKey covers
// the corruption check in importIdentity: a blob whose "pub" field was
// swapped for a different (but still valid-length) public key decrypts fine
// under AES-GCM, yet must still be rejected because the decrypted private
// key no longer derives the claimed public key.
func TestImportIdentity_ShouldErrorWhenBlobPubDoesNotMatchDecryptedKey(t *testing.T) {
	// given - a legitimate export ...
	priv, _, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	enc, err := EncryptPrivateKey(priv, "import-passphrase-1234")
	assert.NoError(t, err)
	blob, err := EncodeIdentityBlob(enc)
	assert.NoError(t, err)

	// ... whose "pub" field is swapped for a different valid-length key
	_, otherPub, err := GenerateEd25519KeyPair()
	assert.NoError(t, err)
	tamperedBlob := tamperIdentityBlobPub(t, blob, otherPub)

	repo := newCountingKeyRepo()
	svc := newImportTestService(repo, "master-password", tamperedBlob, "import-passphrase-1234")

	// when - no existing row, so Initialize takes the fresh-import branch
	err = svc.Initialize(context.Background())

	// then
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SPACE_IDENTITY_IMPORT is corrupted")
}
