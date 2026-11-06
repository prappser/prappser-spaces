package schemas

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prappser/prappser-spaces/internal/schemabundle"
	"github.com/rs/zerolog/log"
)

// var so tests can lower the cap.
var maxContainerBytes int64 = 4 << 20

type Service struct {
	store   Store
	pub     ed25519.PublicKey
	url     string
	client  *http.Client
	mu      sync.Mutex
	current atomic.Pointer[Current]
}

func NewService(store Store, pub ed25519.PublicKey, url string) *Service {
	return &Service{store: store, pub: pub, url: url, client: &http.Client{Timeout: 30 * time.Second}}
}

// Current is nil-safe so callers can hold a nil *Service when the feature is unwired.
func (s *Service) Current() *Current {
	if s == nil {
		return nil
	}
	return s.current.Load()
}

func (s *Service) verify(container []byte) (*Current, error) {
	v, err := schemabundle.Verify(container, s.pub)
	if err != nil {
		return nil, err
	}
	return &Current{Bundle: v.Manifest.Bundle, Container: container}, nil
}

// Load picks the highest valid of the embedded and stored bundles. It never fails startup.
func (s *Service) Load(embedded []byte) {
	var best *Current
	source := ""
	if len(embedded) > 0 {
		if c, err := s.verify(embedded); err != nil {
			log.Warn().Err(err).Msg("[SCHEMAS] Embedded schema bundle failed verification")
		} else {
			best, source = c, "image"
		}
	}

	var row *Stored
	var err error
	if s.store != nil {
		row, err = s.store.Get()
	}
	switch {
	case err != nil:
		log.Warn().Err(err).Msg("[SCHEMAS] Could not read stored schema bundle")
	case row != nil:
		c, err := s.verify(row.Container)
		if err == nil && row.Bundle != c.Bundle {
			err = fmt.Errorf("row bundle %d does not match container bundle %d", row.Bundle, c.Bundle)
		}
		if err != nil {
			log.Warn().Err(err).Msg("[SCHEMAS] Stored schema bundle ignored")
		} else if best == nil || c.Bundle > best.Bundle {
			best, source = c, "stored"
		}
	}

	if best == nil {
		log.Info().Msg("[SCHEMAS] No schema bundle available")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur := s.current.Load(); cur != nil && best.Bundle <= cur.Bundle {
		log.Debug().Int("bundle", cur.Bundle).Msg("[SCHEMAS] Load kept the higher current schema bundle")
		return
	}
	s.current.Store(best)
	log.Info().Int("bundle", best.Bundle).Str("source", source).Msg("[SCHEMAS] Schema bundle loaded")
}

func (s *Service) Fetch(ctx context.Context) {
	if s.url == "" {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		log.Warn().Err(err).Msg("[SCHEMAS] Invalid schema bundle URL")
		return
	}
	resp, err := s.client.Do(req)
	if err != nil {
		log.Warn().Err(err).Msg("[SCHEMAS] Schema bundle fetch failed")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Warn().Int("status", resp.StatusCode).Msg("[SCHEMAS] Schema bundle fetch returned non-200")
		return
	}
	if resp.ContentLength > maxContainerBytes {
		log.Warn().Int64("length", resp.ContentLength).Msg("[SCHEMAS] Schema bundle too large")
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxContainerBytes+1))
	if err != nil {
		log.Warn().Err(err).Msg("[SCHEMAS] Schema bundle read failed")
		return
	}
	if int64(len(body)) > maxContainerBytes {
		log.Warn().Msg("[SCHEMAS] Schema bundle too large")
		return
	}
	next, err := s.verify(body)
	if err != nil {
		log.Warn().Err(err).Msg("[SCHEMAS] Fetched schema bundle failed verification")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.current.Load()
	if cur != nil && next.Bundle == cur.Bundle {
		log.Debug().Int("bundle", next.Bundle).Msg("[SCHEMAS] Schema bundle unchanged")
		return
	}
	if cur != nil && next.Bundle < cur.Bundle {
		log.Warn().Int("fetched", next.Bundle).Int("current", cur.Bundle).Msg("[SCHEMAS] Refused lower schema bundle")
		return
	}
	if s.store != nil {
		if err := s.store.Save(next.Bundle, next.Container); err != nil {
			log.Error().Err(err).Int("bundle", next.Bundle).Msg("[SCHEMAS] Failed to store schema bundle")
			return
		}
	}
	s.current.Store(next)
	log.Info().Int("bundle", next.Bundle).Msg("[SCHEMAS] Schema bundle updated")
}

func (s *Service) Run(ctx context.Context, every time.Duration) {
	if every <= 0 {
		log.Warn().Dur("every", every).Msg("[SCHEMAS] Non-positive refresh interval, schema bundle refresh disabled")
		return
	}
	s.Fetch(ctx)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Fetch(ctx)
		}
	}
}
