package storage

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var badPaths = []string{
	"../x",
	"a/../../b",
	".space/identity.key",
	"_user/2026/10/../../../.space/identity",
	"/etc/passwd",
	"",
}

func newTestStorage(t *testing.T) (*LocalStorage, string) {
	t.Helper()
	root := t.TempDir()
	base := filepath.Join(root, "storage")
	s, err := NewLocalStorage(&BackendConfig{LocalPath: base})
	assert.NoError(t, err)
	return s, root
}

func TestLocalStorage_Store_ShouldRejectTraversalPaths(t *testing.T) {
	// given
	s, root := newTestStorage(t)

	for _, p := range badPaths {
		// when
		err := s.Store(context.Background(), p, strings.NewReader("x"))

		// then
		assert.ErrorIs(t, err, ErrInvalidPath, p)
	}
	_, statErr := os.Stat(filepath.Join(root, "x"))
	assert.True(t, os.IsNotExist(statErr))
	_, statErr = os.Stat(filepath.Join(root, "b"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestLocalStorage_GetDeleteExists_ShouldRejectTraversalPaths(t *testing.T) {
	// given
	s, root := newTestStorage(t)
	outside := filepath.Join(root, "x")
	assert.NoError(t, os.WriteFile(outside, []byte("keep"), 0644))

	for _, p := range badPaths {
		// when
		_, getErr := s.Get(context.Background(), p)
		delErr := s.Delete(context.Background(), p)
		_, existsErr := s.Exists(context.Background(), p)

		// then
		assert.ErrorIs(t, getErr, ErrInvalidPath, p)
		assert.ErrorIs(t, delErr, ErrInvalidPath, p)
		assert.ErrorIs(t, existsErr, ErrInvalidPath, p)
	}
	_, statErr := os.Stat(outside)
	assert.NoError(t, statErr)
}

func TestLocalStorage_ShouldRoundTripLegitimatePaths(t *testing.T) {
	// given
	s, _ := newTestStorage(t)
	ctx := context.Background()
	paths := []string{
		"app-1/2026/10/abc.png",
		"_user/2026/10/abc.png.chunk.0",
		"_user/2026/10/abc_thumb.jpg",
	}

	for _, p := range paths {
		// when
		assert.NoError(t, s.Store(ctx, p, strings.NewReader("data")))
		exists, existsErr := s.Exists(ctx, p)
		r, getErr := s.Get(ctx, p)
		assert.NoError(t, getErr)
		got, _ := io.ReadAll(r)
		r.Close()
		delErr := s.Delete(ctx, p)
		existsAfter, _ := s.Exists(ctx, p)

		// then
		assert.NoError(t, existsErr)
		assert.True(t, exists, p)
		assert.Equal(t, "data", string(got))
		assert.NoError(t, delErr)
		assert.False(t, existsAfter, p)
	}
}
