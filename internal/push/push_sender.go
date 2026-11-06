package push

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/prappser/prappser-spaces/internal/netguard"
)

const sendTimeout = 10 * time.Second

// HTTPWebpushSender delivers push notifications using webpush-go's VAPID signing.
// It is the production implementation of WebpushSender.
type HTTPWebpushSender struct {
	client *http.Client
}

// NewHTTPWebpushSender creates a production WebpushSender backed by webpush-go.
func NewHTTPWebpushSender(allowPrivate bool) *HTTPWebpushSender {
	return newHTTPWebpushSender(allowPrivate, nil)
}

func newHTTPWebpushSender(allowPrivate bool, rootCAs *x509.CertPool) *HTTPWebpushSender {
	policy := netguard.IsPublic
	if allowPrivate {
		policy = allowPrivateAddr
	}
	return &HTTPWebpushSender{client: netguard.NewClient(policy, rootCAs, sendTimeout, true)}
}

// Send delivers payloadJSON to the given subscription using VAPID authentication.
// A per-call send-timeout context is applied automatically.
// The response body is drained and closed before returning.
func (s *HTTPWebpushSender) Send(sub *Subscription, vapid *SpaceVapid, payloadJSON []byte, opts SendOptions) SendResult {
	if err := validateEndpoint(sub.Endpoint); err != nil {
		return SendResult{Err: err}
	}

	sendCtx, cancel := context.WithTimeout(context.Background(), sendTimeout)
	defer cancel()

	wpSub := &webpush.Subscription{
		Endpoint: sub.Endpoint,
		Keys: webpush.Keys{
			Auth:   sub.Auth,
			P256dh: sub.P256dh,
		},
	}

	resp, err := webpush.SendNotificationWithContext(sendCtx, payloadJSON, wpSub, &webpush.Options{
		VAPIDPublicKey:  vapid.VapidPublicKey,
		VAPIDPrivateKey: vapid.VapidPrivateKey,
		TTL:             opts.TTL,
		Urgency:         opts.Urgency,
		Topic:           opts.Topic,
		HTTPClient:      s.client,
	})
	if err != nil {
		return SendResult{Err: err}
	}

	// Drain and close so the underlying connection can be reused.
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()

	if resp.StatusCode == 0 {
		resp.StatusCode = http.StatusOK
	}

	return SendResult{StatusCode: resp.StatusCode}
}
