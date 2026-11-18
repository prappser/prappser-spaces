package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/klippa-app/go-pdfium"
	"github.com/klippa-app/go-pdfium/requests"
	"github.com/klippa-app/go-pdfium/webassembly"
	"github.com/tetratelabs/wazero"
)

const (
	pdfBorrowTimeout    = 30 * time.Second
	pdfRenderTimeout    = 10 * time.Second
	pdfMemoryLimitPages = 4096
)

// ponytail: MaxTotal 1 serialises PDF renders; raise it if PDF uploads queue.
// The empty FSConfig matters: the default mounts the host root into PDFium.
var pdfPool = sync.OnceValues(func() (pdfium.Pool, error) {
	return webassembly.Init(webassembly.Config{
		MaxIdle:  1,
		MaxTotal: 1,
		FSConfig: wazero.NewFSConfig(),
		RuntimeConfig: wazero.NewRuntimeConfig().
			WithCloseOnContextDone(true).
			WithMemoryLimitPages(pdfMemoryLimitPages),
		Stdout: io.Discard,
		Stderr: io.Discard,
	})
})

func renderPDFThumbnail(ctx context.Context, data []byte) ([]byte, error) {
	pool, err := pdfPool()
	if err != nil {
		return nil, fmt.Errorf("failed to init pdf renderer: %w", err)
	}

	inst, err := pool.GetInstance(pdfBorrowTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to get pdf renderer instance: %w", err)
	}
	defer inst.Close()

	renderCtx, cancel := context.WithTimeout(ctx, pdfRenderTimeout)
	defer cancel()

	done := make(chan struct{})
	// go-pdfium's Kill is deliberately unlocked and writes the instance's closed flag
	// while an in-flight call reads it; a timeout race is accepted (library limitation).
	stop := context.AfterFunc(renderCtx, func() {
		inst.Kill()
		close(done)
	})
	defer func() {
		if !stop() {
			<-done
		}
	}()

	doc, err := inst.OpenDocument(&requests.OpenDocument{
		FileReader:     bytes.NewReader(data),
		FileReaderSize: int64(len(data)),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open pdf: %w", err)
	}
	defer inst.FPDF_CloseDocument(&requests.FPDF_CloseDocument{Document: doc.Document})

	resp, err := inst.RenderToFile(&requests.RenderToFile{
		RenderPageInPixels: &requests.RenderPageInPixels{
			Page:   requests.Page{ByIndex: &requests.PageByIndex{Document: doc.Document, Index: 0}},
			Width:  maxThumbnailWidth,
			Height: maxThumbnailHeight,
		},
		OutputFormat:  requests.RenderToFileOutputFormatJPG,
		OutputTarget:  requests.RenderToFileOutputTargetBytes,
		OutputQuality: thumbnailJPEGQuality,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to render pdf page: %w", err)
	}
	if resp == nil || resp.ImageBytes == nil {
		return nil, errors.New("pdf renderer returned no image")
	}
	return *resp.ImageBytes, nil
}
