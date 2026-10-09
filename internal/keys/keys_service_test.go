package keys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingKeyRepo is a keyRepository stub that counts TouchLastSeen calls
// and signals each one on touched, letting tests observe TouchLastSeen's
// fire-and-forget goroutine (see KeyService.TouchLastSeen) without a
// database.
type countingKeyRepo struct {
	mu      sync.Mutex
	touches int
	touched chan struct{}

	row      *EncryptedKey
	hasUsers bool
	rowErr   error
	usersErr error
}

func newCountingKeyRepo() *countingKeyRepo {
	return &countingKeyRepo{touched: make(chan struct{}, 8)}
}

func (r *countingKeyRepo) GetSpaceKey(ctx context.Context) (*EncryptedKey, error) {
	return r.row, r.rowErr
}
func (r *countingKeyRepo) HasUsers(ctx context.Context) (bool, error) { return r.hasUsers, r.usersErr }

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

const (
	testMP         = "master-password"
	testPassphrase = "import-passphrase-1234"
)

func keyPath(dir string) string { return filepath.Join(dir, ".space", "identity.key") }

func newKeyTestService(repo keyRepository, dir, mp, blob, pass string) *KeyService {
	return &KeyService{
		repo:             repo,
		masterPassword:   mp,
		importBlob:       blob,
		importPassphrase: pass,
		keyFilePath:      keyPath(dir),
		touchThrottle:    lastSeenTouchThrottle,
	}
}

func newTestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	priv, _, err := GenerateEd25519KeyPair()
	require.NoError(t, err)
	return priv
}

func legacyRow(t *testing.T, priv ed25519.PrivateKey, mp string) *EncryptedKey {
	t.Helper()
	enc, err := EncryptPrivateKey(priv, mp)
	require.NoError(t, err)
	return enc
}

func exportBlob(t *testing.T, priv ed25519.PrivateKey, pass string) string {
	t.Helper()
	blob, err := EncodeIdentityBlob(legacyRow(t, priv, pass))
	require.NoError(t, err)
	return blob
}

func seedKeyFile(t *testing.T, dir string, priv ed25519.PrivateKey) {
	t.Helper()
	require.NoError(t, writeKeyFile(keyPath(dir), priv))
}

func assertNoKeyFile(t *testing.T, dir string) {
	t.Helper()
	_, err := os.Stat(keyPath(dir))
	assert.True(t, os.IsNotExist(err), "no key file must be written")
}

func assertSeed(t *testing.T, want ed25519.PrivateKey, svc *KeyService) {
	t.Helper()
	assert.Equal(t, want.Seed(), svc.PrivateKey().Seed())
	assert.Equal(t, want.Public(), svc.PublicKey())
}

func TestInitialize_FreshSpace_ShouldGenerateKeyFileAndReloadSameKey(t *testing.T) {
	// given
	dir := t.TempDir()
	svc := newKeyTestService(newCountingKeyRepo(), dir, "", "", "")

	// when
	err := svc.Initialize(context.Background())

	// then
	require.NoError(t, err)
	onDisk, err := loadKeyFile(keyPath(dir))
	require.NoError(t, err)
	assertSeed(t, onDisk, svc)

	again := newKeyTestService(newCountingKeyRepo(), dir, "", "", "")
	require.NoError(t, again.Initialize(context.Background()))
	assert.Equal(t, svc.PublicKey(), again.PublicKey())
}

func TestInitialize_FreshSpace_ShouldWriteFile0600InDir0700(t *testing.T) {
	// given
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".space"), 0o755))
	svc := newKeyTestService(newCountingKeyRepo(), dir, "", "", "")

	// when
	err := svc.Initialize(context.Background())

	// then
	require.NoError(t, err)
	fi, err := os.Stat(keyPath(dir))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	di, err := os.Stat(filepath.Join(dir, ".space"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), di.Mode().Perm())
}

func TestInitialize_LegacyRowWithMasterPassword_ShouldMigrateSameSeedToFile(t *testing.T) {
	// given
	dir := t.TempDir()
	priv := newTestKey(t)
	repo := newCountingKeyRepo()
	repo.row = legacyRow(t, priv, testMP)
	svc := newKeyTestService(repo, dir, testMP, "", "")

	// when
	err := svc.Initialize(context.Background())

	// then
	require.NoError(t, err)
	assertSeed(t, priv, svc)
	onDisk, err := loadKeyFile(keyPath(dir))
	require.NoError(t, err)
	assert.Equal(t, priv.Seed(), onDisk.Seed())
}

func TestInitialize_AlreadyMigratedAndMasterPasswordUnset_ShouldLoadFile(t *testing.T) {
	// given
	dir := t.TempDir()
	priv := newTestKey(t)
	seedKeyFile(t, dir, priv)
	repo := newCountingKeyRepo()
	repo.row = legacyRow(t, priv, testMP)
	svc := newKeyTestService(repo, dir, "", "", "")

	// when
	err := svc.Initialize(context.Background())

	// then
	require.NoError(t, err)
	assertSeed(t, priv, svc)
}

func TestInitialize_FilePubDiffersFromRow_ShouldRefuse(t *testing.T) {
	// given
	dir := t.TempDir()
	seedKeyFile(t, dir, newTestKey(t))
	repo := newCountingKeyRepo()
	repo.row = legacyRow(t, newTestKey(t), testMP)
	svc := newKeyTestService(repo, dir, testMP, "", "")

	// when
	err := svc.Initialize(context.Background())

	// then
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match the space_keys row")
}

func TestInitialize_RowButNoFileAndNoMasterPassword_ShouldRefuseWithoutWriting(t *testing.T) {
	// given
	dir := t.TempDir()
	repo := newCountingKeyRepo()
	repo.row = legacyRow(t, newTestKey(t), testMP)
	svc := newKeyTestService(repo, dir, "", "", "")

	// when
	err := svc.Initialize(context.Background())

	// then
	require.Error(t, err)
	assert.Contains(t, err.Error(), keyPath(dir))
	assert.Contains(t, err.Error(), "set MASTER_PASSWORD once")
	assertNoKeyFile(t, dir)
}

func TestInitialize_RowWithWrongMasterPasswordAndNoImport_ShouldRefuseWithoutWriting(t *testing.T) {
	// given
	dir := t.TempDir()
	repo := newCountingKeyRepo()
	repo.row = legacyRow(t, newTestKey(t), testMP)
	svc := newKeyTestService(repo, dir, "wrong", "", "")

	// when
	err := svc.Initialize(context.Background())

	// then
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot decrypt the space_keys row")
	assert.Contains(t, err.Error(), keyPath(dir))
	assertNoKeyFile(t, dir)
}

func TestInitialize_UsersExistButNoFileAndNoRow_ShouldRefuseWithoutWriting(t *testing.T) {
	// given
	dir := t.TempDir()
	repo := newCountingKeyRepo()
	repo.hasUsers = true
	svc := newKeyTestService(repo, dir, "", "", "")

	// when
	err := svc.Initialize(context.Background())

	// then
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has accounts")
	assert.Contains(t, err.Error(), keyPath(dir))
	assertNoKeyFile(t, dir)
}

func TestInitialize_ImportOnFreshSpace_ShouldWriteImportedKey(t *testing.T) {
	// given
	dir := t.TempDir()
	priv := newTestKey(t)
	svc := newKeyTestService(newCountingKeyRepo(), dir, "", exportBlob(t, priv, testPassphrase), testPassphrase)

	// when
	err := svc.Initialize(context.Background())

	// then
	require.NoError(t, err)
	assertSeed(t, priv, svc)
	onDisk, err := loadKeyFile(keyPath(dir))
	require.NoError(t, err)
	assert.Equal(t, priv.Seed(), onDisk.Seed())
}

func TestInitialize_ImportWithRowAndMasterPasswordUnset_ShouldWriteFile(t *testing.T) {
	// given
	dir := t.TempDir()
	priv := newTestKey(t)
	repo := newCountingKeyRepo()
	repo.row = legacyRow(t, priv, "old-host-password")
	svc := newKeyTestService(repo, dir, "", exportBlob(t, priv, testPassphrase), testPassphrase)

	// when
	err := svc.Initialize(context.Background())

	// then
	require.NoError(t, err)
	assertSeed(t, priv, svc)
	_, err = os.Stat(keyPath(dir))
	assert.NoError(t, err)
}

func TestInitialize_ImportBlobPubDiffersFromRow_ShouldRefuseWithoutWriting(t *testing.T) {
	// given
	dir := t.TempDir()
	repo := newCountingKeyRepo()
	repo.row = legacyRow(t, newTestKey(t), testMP)
	svc := newKeyTestService(repo, dir, "", exportBlob(t, newTestKey(t), testPassphrase), testPassphrase)

	// when
	err := svc.Initialize(context.Background())

	// then
	require.Error(t, err)
	assert.Contains(t, err.Error(), "public key mismatch")
	assertNoKeyFile(t, dir)
}

func TestInitialize_ImportBlobPubDiffersFromFile_ShouldRefuse(t *testing.T) {
	// given
	dir := t.TempDir()
	seedKeyFile(t, dir, newTestKey(t))
	svc := newKeyTestService(newCountingKeyRepo(), dir, "", exportBlob(t, newTestKey(t), testPassphrase), testPassphrase)

	// when
	err := svc.Initialize(context.Background())

	// then
	require.Error(t, err)
	assert.Contains(t, err.Error(), "public key mismatch")
}

func TestInitialize_ImportLeftSetWithWrongPassphraseWhileFileExists_ShouldBootWithoutWriting(t *testing.T) {
	// given
	dir := t.TempDir()
	priv := newTestKey(t)
	seedKeyFile(t, dir, priv)
	before, err := os.ReadFile(keyPath(dir))
	require.NoError(t, err)
	svc := newKeyTestService(newCountingKeyRepo(), dir, "", exportBlob(t, priv, testPassphrase), "not-the-passphrase")

	// when
	err = svc.Initialize(context.Background())

	// then
	require.NoError(t, err)
	assertSeed(t, priv, svc)
	after, err := os.ReadFile(keyPath(dir))
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

func TestInitialize_ImportBlobWithTamperedPub_ShouldRefuse(t *testing.T) {
	// given
	priv := newTestKey(t)
	tampered := tamperIdentityBlobPub(t, exportBlob(t, priv, testPassphrase), newTestKey(t).Public().(ed25519.PublicKey))
	dir := t.TempDir()
	svc := newKeyTestService(newCountingKeyRepo(), dir, "", tampered, testPassphrase)

	// when
	err := svc.Initialize(context.Background())

	// then
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SPACE_IDENTITY_IMPORT is corrupted")
	assertNoKeyFile(t, dir)
}

func pemFile(t *testing.T, typ string, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func corruptFileVariants(t *testing.T) map[string][]byte {
	t.Helper()
	priv := newTestKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	good := pemFile(t, "PRIVATE KEY", der)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)

	return map[string][]byte{
		"truncated":     good[:len(good)/2],
		"wrong type":    pemFile(t, "EC PRIVATE KEY", der),
		"rsa key":       pemFile(t, "PRIVATE KEY", rsaDER),
		"trailing junk": append(append([]byte{}, good...), []byte("junk")...),
		"second block":  append(append([]byte{}, good...), good...),
	}
}

func TestInitialize_CorruptKeyFile_ShouldRefuseAndLeaveFileUnchanged(t *testing.T) {
	for name, content := range corruptFileVariants(t) {
		t.Run(name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			require.NoError(t, os.MkdirAll(filepath.Dir(keyPath(dir)), 0o700))
			require.NoError(t, os.WriteFile(keyPath(dir), content, 0o600))
			svc := newKeyTestService(newCountingKeyRepo(), dir, "", "", "")

			// when
			err := svc.Initialize(context.Background())

			// then
			require.Error(t, err)
			after, readErr := os.ReadFile(keyPath(dir))
			require.NoError(t, readErr)
			assert.Equal(t, content, after)
		})
	}
}

func TestInitialize_UnreadableKeyFile_ShouldRefuseAndLeaveFileUnchanged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file modes")
	}
	// given
	dir := t.TempDir()
	seedKeyFile(t, dir, newTestKey(t))
	require.NoError(t, os.Chmod(keyPath(dir), 0o000))
	t.Cleanup(func() { _ = os.Chmod(keyPath(dir), 0o600) })
	svc := newKeyTestService(newCountingKeyRepo(), dir, "", "", "")

	// when
	err := svc.Initialize(context.Background())

	// then
	require.Error(t, err)
	require.NoError(t, os.Chmod(keyPath(dir), 0o600))
	loaded, loadErr := loadKeyFile(keyPath(dir))
	require.NoError(t, loadErr)
	assert.NotNil(t, loaded)
}

func TestInitialize_ConcurrentFreshBoots_ShouldConvergeOnOneKey(t *testing.T) {
	// given
	dir := t.TempDir()
	a := newKeyTestService(newCountingKeyRepo(), dir, "", "", "")
	b := newKeyTestService(newCountingKeyRepo(), dir, "", "", "")
	errs := make(chan error, 2)

	// when
	for _, svc := range []*KeyService{a, b} {
		go func(svc *KeyService) { errs <- svc.Initialize(context.Background()) }(svc)
	}

	// then
	require.NoError(t, <-errs)
	require.NoError(t, <-errs)
	assert.Equal(t, a.PublicKey(), b.PublicKey())
	onDisk, err := loadKeyFile(keyPath(dir))
	require.NoError(t, err)
	assert.Equal(t, onDisk.Public(), a.PublicKey())
	entries, err := os.ReadDir(filepath.Dir(keyPath(dir)))
	require.NoError(t, err)
	assert.Len(t, entries, 1, "temp files must be cleaned up")
}

func TestInitialize_EphemeralKeyDirOnFreshSpace_ShouldRefuseWithoutWriting(t *testing.T) {
	// given
	dir := t.TempDir()
	svc := newKeyTestService(newCountingKeyRepo(), dir, "", "", "")
	svc.keyDirEphemeral = true

	// when
	err := svc.Initialize(context.Background())

	// then
	require.Error(t, err)
	assert.Contains(t, err.Error(), "STORAGE_PATH")
	assertNoKeyFile(t, dir)
}

func TestInitialize_EphemeralKeyDirOnMigration_ShouldRefuseWithoutWriting(t *testing.T) {
	// given
	dir := t.TempDir()
	repo := newCountingKeyRepo()
	repo.row = legacyRow(t, newTestKey(t), testMP)
	svc := newKeyTestService(repo, dir, testMP, "", "")
	svc.keyDirEphemeral = true

	// when
	err := svc.Initialize(context.Background())

	// then
	require.Error(t, err)
	assertNoKeyFile(t, dir)
}

func TestInitialize_EphemeralKeyDirWithExistingFile_ShouldStillLoad(t *testing.T) {
	// given
	dir := t.TempDir()
	priv := newTestKey(t)
	seedKeyFile(t, dir, priv)
	svc := newKeyTestService(newCountingKeyRepo(), dir, "", "", "")
	svc.keyDirEphemeral = true

	// when
	err := svc.Initialize(context.Background())

	// then
	require.NoError(t, err)
	assertSeed(t, priv, svc)
}

// tamperIdentityBlobPub rebuilds blob with its "pub" field replaced by a
// different, valid-length public key, simulating a blob assembled
// inconsistently but still decryptable.
func tamperIdentityBlobPub(t *testing.T, blob string, otherPub []byte) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(blob, identityBlobPrefix))
	require.NoError(t, err)

	var payload identityBlobPayload
	require.NoError(t, json.Unmarshal(raw, &payload))
	payload.Pub = base64.StdEncoding.EncodeToString(otherPub)

	tampered, err := json.Marshal(payload)
	require.NoError(t, err)
	return identityBlobPrefix + base64.RawURLEncoding.EncodeToString(tampered)
}

func TestInitialize_RowDecryptsButImportPubDiffers_ShouldRefuseWithoutWriting(t *testing.T) {
	// given
	dir := t.TempDir()
	repo := newCountingKeyRepo()
	repo.row = legacyRow(t, newTestKey(t), testMP)
	svc := newKeyTestService(repo, dir, testMP, exportBlob(t, newTestKey(t), testPassphrase), testPassphrase)

	// when
	err := svc.Initialize(context.Background())

	// then
	require.ErrorIs(t, err, errImportMismatch)
	assertNoKeyFile(t, dir)
}

func TestInitialize_RowPubDiffersFromDecryptedSeed_ShouldRefuseWithoutWriting(t *testing.T) {
	// given
	dir := t.TempDir()
	row := legacyRow(t, newTestKey(t), testMP)
	row.PublicKey = newTestKey(t).Public().(ed25519.PublicKey)
	repo := newCountingKeyRepo()
	repo.row = row
	svc := newKeyTestService(repo, dir, testMP, "", "")

	// when
	err := svc.Initialize(context.Background())

	// then
	require.Error(t, err)
	assert.Contains(t, err.Error(), "space_keys row is corrupt")
	assertNoKeyFile(t, dir)
}

func TestInitialize_GetSpaceKeyFails_ShouldRefuseWithoutWriting(t *testing.T) {
	// given
	dir := t.TempDir()
	repo := newCountingKeyRepo()
	repo.rowErr = errors.New("db down")
	svc := newKeyTestService(repo, dir, "", "", "")

	// when
	err := svc.Initialize(context.Background())

	// then
	require.Error(t, err)
	assertNoKeyFile(t, dir)
}

func TestInitialize_HasUsersFails_ShouldRefuseWithoutWriting(t *testing.T) {
	// given
	dir := t.TempDir()
	repo := newCountingKeyRepo()
	repo.usersErr = errors.New("db down")
	svc := newKeyTestService(repo, dir, "", "", "")

	// when
	err := svc.Initialize(context.Background())

	// then
	require.Error(t, err)
	assertNoKeyFile(t, dir)
}

func TestInitialize_ImportWithUsersButNoFileAndNoRow_ShouldImport(t *testing.T) {
	// given
	dir := t.TempDir()
	priv := newTestKey(t)
	repo := newCountingKeyRepo()
	repo.hasUsers = true
	svc := newKeyTestService(repo, dir, "", exportBlob(t, priv, testPassphrase), testPassphrase)

	// when
	err := svc.Initialize(context.Background())

	// then
	require.NoError(t, err)
	assertSeed(t, priv, svc)
}

func TestLoadKeyFile_GroupReadableFile_ShouldTightenTo0600(t *testing.T) {
	// given
	dir := t.TempDir()
	seedKeyFile(t, dir, newTestKey(t))
	require.NoError(t, os.Chmod(keyPath(dir), 0o644))

	// when
	priv, err := loadKeyFile(keyPath(dir))

	// then
	require.NoError(t, err)
	require.NotNil(t, priv)
	fi, err := os.Stat(keyPath(dir))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}
