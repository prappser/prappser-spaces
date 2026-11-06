package netguard

import (
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testTimeout = 5 * time.Second

func allowAll(netip.Addr) bool { return true }

func poolFor(srv *httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return pool
}

func TestIsPublic_ShouldRejectNonGlobalRanges(t *testing.T) {
	// given
	blocked := []string{
		"127.0.0.1", "::1", "10.0.0.1", "172.16.5.4", "192.168.1.1", "fd00::1", "169.254.169.254",
		"fe80::1", "224.0.0.1", "ff02::1", "0.0.0.0", "::", "0.1.2.3", "100.64.0.1", "192.0.0.8",
		"192.0.2.1", "198.18.0.1", "198.51.100.7", "203.0.113.9", "240.0.0.1", "255.255.255.255",
		"64:ff9b::808:808", "64:ff9b:1::1", "2002:808:808::1", "2001:db8::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "ff01::1",
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "::ffff:8.8.8.8"}

	// when / then
	for _, s := range blocked {
		assert.False(t, IsPublic(netip.MustParseAddr(s)), s)
	}
	for _, s := range allowed {
		assert.True(t, IsPublic(netip.MustParseAddr(s)), s)
	}
}

func TestNewClient_ShouldCheckResolvedIPNotHostname(t *testing.T) {
	// given
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	u.Host = "localhost:" + u.Port()
	var mu sync.Mutex
	var seen netip.Addr
	client := NewClient(func(a netip.Addr) bool { mu.Lock(); seen = a; mu.Unlock(); return false }, poolFor(srv), testTimeout, false)

	// when
	resp, err := client.Get(u.String())
	if resp != nil {
		resp.Body.Close()
	}

	// then
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAddressNotAllowed))
	mu.Lock()
	defer mu.Unlock()
	assert.True(t, seen.IsLoopback(), seen.String())
}

func TestNewClient_ShouldRefuseLoopbackWithIsPublic(t *testing.T) {
	// given
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(srv.Close)
	client := NewClient(IsPublic, poolFor(srv), testTimeout, false)

	// when
	resp, err := client.Get(srv.URL)
	if resp != nil {
		resp.Body.Close()
	}

	// then
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAddressNotAllowed))
	assert.Zero(t, hits.Load())
}

func TestNewClient_ShouldNotFollowRedirect(t *testing.T) {
	// given
	var bHits atomic.Int32
	b := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { bHits.Add(1) }))
	t.Cleanup(b.Close)
	a := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, b.URL, http.StatusFound)
	}))
	t.Cleanup(a.Close)
	pool := poolFor(a)
	pool.AddCert(b.Certificate())
	client := NewClient(allowAll, pool, testTimeout, false)

	// when
	resp, err := client.Get(a.URL)

	// then
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Zero(t, bHits.Load())
}

func dialsForTwoRequests(t *testing.T, keepAlives bool) int32 {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	var dials atomic.Int32
	client := NewClient(func(netip.Addr) bool { dials.Add(1); return true }, poolFor(srv), testTimeout, keepAlives)
	for range 2 {
		resp, err := client.Get(srv.URL)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	return dials.Load()
}

func TestNewClient_KeepAlivesOn_ShouldReuseConnection(t *testing.T) {
	// when
	on := dialsForTwoRequests(t, true)
	off := dialsForTwoRequests(t, false)

	// then
	assert.Equal(t, int32(1), on)
	assert.Equal(t, int32(2), off)
}
