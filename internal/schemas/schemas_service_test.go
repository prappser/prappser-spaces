package schemas

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/prappser/prappser-spaces/internal/schemabundle"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

func signedContainer(t *testing.T, priv ed25519.PrivateKey, bundle int) []byte {
	t.Helper()
	schema := "{\"a\": 1}\n"
	sum := sha256.Sum256([]byte(schema))
	manifest := fmt.Sprintf(`{"bundle":%d,"types":{"A":{"min":1,"current":1}},"files":[{"path":"component/a.v1.schema.json","sha256":%q}]}`+"\n",
		bundle, hex.EncodeToString(sum[:]))
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "component"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "component", "a.v1.schema.json"), []byte(schema), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bundle.json"), []byte(manifest), 0o644))
	out, err := schemabundle.Build(dir, priv)
	require.NoError(t, err)
	return out
}

type fakeStore struct {
	row     *Stored
	getErr  error
	saveErr error
	saves   []Stored
}

func (f *fakeStore) Get() (*Stored, error) { return f.row, f.getErr }

func (f *fakeStore) Save(bundle int, container []byte) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.saves = append(f.saves, Stored{Bundle: bundle, Container: container})
	return nil
}

func serve(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = prev })
	return &buf
}

func TestFetch_HigherBundle_ShouldAcceptAndStore(t *testing.T) {
	// given
	pub, priv := newKey(t)
	container := signedContainer(t, priv, 2)
	store := &fakeStore{}
	svc := NewService(store, pub, serve(t, container).URL)
	svc.Load(signedContainer(t, priv, 1))

	// when
	svc.Fetch(context.Background())

	// then
	require.NotNil(t, svc.Current())
	assert.Equal(t, 2, svc.Current().Bundle)
	assert.Equal(t, container, svc.Current().Container)
	require.Len(t, store.saves, 1)
	assert.Equal(t, container, store.saves[0].Container)
	assert.Equal(t, 2, store.saves[0].Bundle)
}

func TestFetch_EqualBundle_ShouldBeNoOp(t *testing.T) {
	// given
	pub, priv := newKey(t)
	store := &fakeStore{}
	svc := NewService(store, pub, serve(t, signedContainer(t, priv, 2)).URL)
	svc.Load(signedContainer(t, priv, 2))

	// when
	svc.Fetch(context.Background())

	// then
	assert.Empty(t, store.saves)
	assert.Equal(t, 2, svc.Current().Bundle)
}

func TestFetch_LowerBundle_ShouldRefuse(t *testing.T) {
	// given
	pub, priv := newKey(t)
	store := &fakeStore{}
	svc := NewService(store, pub, serve(t, signedContainer(t, priv, 1)).URL)
	embedded := signedContainer(t, priv, 3)
	svc.Load(embedded)

	// when
	svc.Fetch(context.Background())

	// then
	assert.Empty(t, store.saves)
	assert.Equal(t, 3, svc.Current().Bundle)
	assert.Equal(t, embedded, svc.Current().Container)
}

func TestFetch_ServedNumberShouldNeverGoDown(t *testing.T) {
	// given
	pub, priv := newKey(t)
	var body atomic.Pointer[[]byte]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(*body.Load())
	}))
	t.Cleanup(srv.Close)
	svc := NewService(&fakeStore{}, pub, srv.URL)
	step := func(n int) int {
		b := signedContainer(t, priv, n)
		body.Store(&b)
		svc.Fetch(context.Background())
		return svc.Current().Bundle
	}

	// when / then
	assert.Equal(t, 5, step(5))
	assert.Equal(t, 5, step(2))
	assert.Equal(t, 5, step(5))
	assert.Equal(t, 6, step(6))
}

func TestFetch_BadSignature_ShouldReject(t *testing.T) {
	// given
	pub, priv := newKey(t)
	_, other := newKey(t)
	store := &fakeStore{}
	svc := NewService(store, pub, serve(t, signedContainer(t, other, 2)).URL)
	svc.Load(signedContainer(t, priv, 1))

	// when
	svc.Fetch(context.Background())

	// then
	assert.Empty(t, store.saves)
	assert.Equal(t, 1, svc.Current().Bundle)
}

func lowerCap(t *testing.T, n int) {
	t.Helper()
	prev := maxContainerBytes
	maxContainerBytes = int64(n)
	t.Cleanup(func() { maxContainerBytes = prev })
}

func servers(t *testing.T, body []byte) map[string]string {
	t.Helper()
	withLength := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}))
	chunked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.(http.Flusher).Flush()
		_, _ = w.Write(body)
	}))
	t.Cleanup(withLength.Close)
	t.Cleanup(chunked.Close)
	return map[string]string{"content-length": withLength.URL, "chunked": chunked.URL}
}

func TestFetch_OversizedBody_ShouldReject(t *testing.T) {
	// given
	pub, priv := newKey(t)
	container := signedContainer(t, priv, 2)
	lowerCap(t, len(container)-1)

	for name, url := range servers(t, container) {
		store := &fakeStore{}
		svc := NewService(store, pub, url)

		// when
		svc.Fetch(context.Background())

		// then
		assert.Nil(t, svc.Current(), name)
		assert.Empty(t, store.saves, name)
	}
}

func TestFetch_ValidBodyAtCap_ShouldAccept(t *testing.T) {
	// given
	pub, priv := newKey(t)
	container := signedContainer(t, priv, 2)
	lowerCap(t, len(container))

	for name, url := range servers(t, container) {
		svc := NewService(&fakeStore{}, pub, url)

		// when
		svc.Fetch(context.Background())

		// then
		require.NotNil(t, svc.Current(), name)
		assert.Equal(t, 2, svc.Current().Bundle, name)
	}
}

func TestFetch_Non200_ShouldReject(t *testing.T) {
	// given
	pub, priv := newKey(t)
	store := &fakeStore{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(signedContainer(t, priv, 9))
	}))
	t.Cleanup(srv.Close)
	svc := NewService(store, pub, srv.URL)

	// when
	svc.Fetch(context.Background())

	// then
	assert.Nil(t, svc.Current())
	assert.Empty(t, store.saves)
}

func TestFetch_WrongContent_ShouldReject(t *testing.T) {
	// given
	pub, _ := newKey(t)
	store := &fakeStore{}

	for _, body := range []string{"not json at all", `{"manifest":1,"signature":[],"files":"x"}`} {
		svc := NewService(store, pub, serve(t, []byte(body)).URL)

		// when
		svc.Fetch(context.Background())

		// then
		assert.Nil(t, svc.Current())
	}
	assert.Empty(t, store.saves)
}

func TestFetch_SaveFails_ShouldNotSwap(t *testing.T) {
	// given
	pub, priv := newKey(t)
	store := &fakeStore{saveErr: errors.New("db down")}
	svc := NewService(store, pub, serve(t, signedContainer(t, priv, 2)).URL)
	svc.Load(signedContainer(t, priv, 1))
	logs := captureLog(t)

	// when
	svc.Fetch(context.Background())

	// then
	assert.Equal(t, 1, svc.Current().Bundle)
	assert.Contains(t, logs.String(), "[SCHEMAS]")
	assert.Contains(t, logs.String(), "db down")
}

func TestFetch_FollowsRedirect(t *testing.T) {
	// given
	pub, priv := newKey(t)
	target := serve(t, signedContainer(t, priv, 4))
	redirector := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusFound))
	t.Cleanup(redirector.Close)
	svc := NewService(&fakeStore{}, pub, redirector.URL)

	// when
	svc.Fetch(context.Background())

	// then
	require.NotNil(t, svc.Current())
	assert.Equal(t, 4, svc.Current().Bundle)
}

func TestFetch_URLEmpty_ShouldMakeNoRequest(t *testing.T) {
	// given
	pub, _ := newKey(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(srv.Close)
	svc := NewService(&fakeStore{}, pub, "")

	// when
	svc.Fetch(context.Background())

	// then
	assert.Zero(t, hits.Load())
	assert.Nil(t, svc.Current())
}

func TestLoad_ShouldPickHighestOfEmbeddedAndStored(t *testing.T) {
	// given
	pub, priv := newKey(t)
	low, high := signedContainer(t, priv, 1), signedContainer(t, priv, 3)

	// when
	a := NewService(&fakeStore{row: &Stored{Bundle: 3, Container: high}}, pub, "")
	a.Load(low)
	b := NewService(&fakeStore{row: &Stored{Bundle: 1, Container: low}}, pub, "")
	b.Load(high)

	// then
	assert.Equal(t, 3, a.Current().Bundle)
	assert.Equal(t, high, a.Current().Container)
	assert.Equal(t, 3, b.Current().Bundle)
	assert.Equal(t, high, b.Current().Container)
}

func TestLoad_EmbeddedNilOrEmpty_CurrentStaysNilUntilStoredOrFetch(t *testing.T) {
	// given
	pub, priv := newKey(t)
	stored := signedContainer(t, priv, 2)
	fetched := signedContainer(t, priv, 3)
	store := &fakeStore{}
	svc := NewService(store, pub, serve(t, fetched).URL)

	// when / then
	svc.Load(nil)
	assert.Nil(t, svc.Current())
	svc.Load([]byte{})
	assert.Nil(t, svc.Current())

	store.row = &Stored{Bundle: 2, Container: stored}
	svc.Load(nil)
	assert.Equal(t, 2, svc.Current().Bundle)

	svc.Fetch(context.Background())
	assert.Equal(t, 3, svc.Current().Bundle)
}

func TestLoad_StoreGetError_ShouldWarnAndUseEmbedded(t *testing.T) {
	// given
	pub, priv := newKey(t)
	svc := NewService(&fakeStore{getErr: errors.New("conn reset")}, pub, "")
	logs := captureLog(t)

	// when
	svc.Load(signedContainer(t, priv, 1))

	// then
	assert.Equal(t, 1, svc.Current().Bundle)
	assert.True(t, strings.Contains(logs.String(), `"level":"warn"`) && strings.Contains(logs.String(), "[SCHEMAS]"))
}

func TestLoad_InvalidStoredRow_ShouldWarnAndNotDelete(t *testing.T) {
	// given
	pub, priv := newKey(t)
	_, other := newKey(t)
	embedded := signedContainer(t, priv, 1)
	rows := []*Stored{
		{Bundle: 5, Container: signedContainer(t, other, 5)},
		{Bundle: 7, Container: signedContainer(t, priv, 5)},
	}
	logs := captureLog(t)

	for _, row := range rows {
		store := &fakeStore{row: row}
		svc := NewService(store, pub, "")

		// when
		svc.Load(embedded)

		// then
		assert.Equal(t, 1, svc.Current().Bundle)
		assert.Empty(t, store.saves)
		assert.NotNil(t, store.row)
	}
	assert.Contains(t, logs.String(), "[SCHEMAS] Stored schema bundle ignored")
}

func TestLoad_AfterHigherFetch_ShouldNotLowerCurrent(t *testing.T) {
	// given
	pub, priv := newKey(t)
	svc := NewService(&fakeStore{getErr: errors.New("conn reset")}, pub, serve(t, signedContainer(t, priv, 9)).URL)
	svc.Fetch(context.Background())

	// when
	svc.Load(signedContainer(t, priv, 4))

	// then
	assert.Equal(t, 9, svc.Current().Bundle)
}

func TestLoad_NilStore_ShouldUseEmbedded(t *testing.T) {
	// given
	pub, priv := newKey(t)
	svc := NewService(nil, pub, "")

	// when
	svc.Load(signedContainer(t, priv, 2))

	// then
	assert.Equal(t, 2, svc.Current().Bundle)
}

func TestFetch_NilStore_ShouldSwapWithoutPersisting(t *testing.T) {
	// given
	pub, priv := newKey(t)
	svc := NewService(nil, pub, serve(t, signedContainer(t, priv, 3)).URL)

	// when
	svc.Fetch(context.Background())

	// then
	require.NotNil(t, svc.Current())
	assert.Equal(t, 3, svc.Current().Bundle)
}

func TestRun_NonPositiveInterval_ShouldWarnAndReturn(t *testing.T) {
	// given
	pub, _ := newKey(t)
	svc := NewService(&fakeStore{}, pub, "")
	logs := captureLog(t)

	// when
	svc.Run(context.Background(), 0)

	// then
	assert.Contains(t, logs.String(), "[SCHEMAS]")
	assert.Contains(t, logs.String(), `"level":"warn"`)
}

func TestCurrent_NilService_ShouldReturnNil(t *testing.T) {
	// given
	var svc *Service

	// when / then
	assert.Nil(t, svc.Current())
}
