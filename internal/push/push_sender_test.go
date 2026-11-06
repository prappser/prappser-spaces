package push

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/prappser/prappser-spaces/internal/netguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestSubscription(t *testing.T, endpoint string) *Subscription {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	auth := make([]byte, 16)
	_, err = rand.Read(auth)
	require.NoError(t, err)
	return &Subscription{
		ID:              "sub-1",
		DevicePublicKey: "user-pk-1",
		Endpoint:        endpoint,
		P256dh:          base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
		Auth:            base64.RawURLEncoding.EncodeToString(auth),
	}
}

func newTestVapid(t *testing.T) *SpaceVapid {
	t.Helper()
	priv, pub, err := webpush.GenerateVAPIDKeys()
	require.NoError(t, err)
	return &SpaceVapid{VapidPublicKey: pub, VapidPrivateKey: priv}
}

func newTLSServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, pool
}

func TestHTTPWebpushSender_Default_ShouldRefuseLoopback(t *testing.T) {
	// given
	var hits atomic.Int32
	srv, _ := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusCreated)
	})
	sender := NewHTTPWebpushSender(false)

	// when
	result := sender.Send(newTestSubscription(t, srv.URL), newTestVapid(t), []byte(`{}`), SendOptions{})

	// then
	assert.True(t, errors.Is(result.Err, netguard.ErrAddressNotAllowed))
	assert.Zero(t, hits.Load())
}

func TestHTTPWebpushSender_AllowPrivate_ShouldDeliverToLoopback(t *testing.T) {
	// given
	var hits atomic.Int32
	srv, pool := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusCreated)
	})
	sender := newHTTPWebpushSender(true, pool)

	// when
	result := sender.Send(newTestSubscription(t, srv.URL), newTestVapid(t), []byte(`{}`), SendOptions{})

	// then
	assert.NoError(t, result.Err)
	assert.Equal(t, http.StatusCreated, result.StatusCode)
	assert.Equal(t, int32(1), hits.Load())
}

func TestHTTPWebpushSender_ShouldNotFollowRedirect(t *testing.T) {
	// given
	var bHits atomic.Int32
	b, pool := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) {
		bHits.Add(1)
		w.WriteHeader(http.StatusCreated)
	})
	a, _ := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, b.URL, http.StatusFound)
	})
	pool.AddCert(a.Certificate())
	sender := newHTTPWebpushSender(true, pool)

	// when
	result := sender.Send(newTestSubscription(t, a.URL), newTestVapid(t), []byte(`{}`), SendOptions{})

	// then
	assert.NoError(t, result.Err)
	assert.Equal(t, http.StatusFound, result.StatusCode)
	assert.Zero(t, bHits.Load())
}

func TestHTTPWebpushSender_ShouldFailSendForStoredHTTPEndpoint(t *testing.T) {
	// given
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	t.Cleanup(srv.Close)
	sender := newHTTPWebpushSender(true, nil)

	// when
	result := sender.Send(newTestSubscription(t, srv.URL), newTestVapid(t), []byte(`{}`), SendOptions{})

	// then
	assert.Error(t, result.Err)
	assert.Zero(t, hits.Load())
}

func TestDeliver_BlockedEndpoint_ShouldIncrementFailureAndKeepSubscription(t *testing.T) {
	// given
	srv, _ := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) {})
	repo := newMockPushRepository()
	svc := &PushService{repo: repo, sender: NewHTTPWebpushSender(false)}
	sub := newTestSubscription(t, srv.URL)
	repo.subscriptions[sub.ID] = sub

	// when
	svc.deliver(sub, newTestVapid(t), []byte(`{}`), SendOptions{})

	// then
	assert.Equal(t, []string{sub.ID}, repo.incrementFailureCalls)
	assert.Empty(t, repo.deleteSubscriptionCalls)
	assert.Contains(t, repo.subscriptions, sub.ID)
}
