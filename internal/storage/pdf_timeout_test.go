//go:build !race

// Kill's unlocked write in go-pdfium trips the race detector.

package storage

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderPDFThumbnail_ShouldFailOnCancelledContextAndRecoverPool(t *testing.T) {
	// given
	data, err := os.ReadFile("testdata/one-page.pdf")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// when
	_, err = renderPDFThumbnail(ctx, data)

	// then
	assert.Error(t, err)
	out, err := renderPDFThumbnail(context.Background(), data)
	assert.NoError(t, err)
	assert.NotEmpty(t, out)
}
