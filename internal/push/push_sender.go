package push

import (
	"context"
	"io"
	"net/http"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
)

// HTTPWebpushSender delivers push notifications using webpush-go's VAPID signing.
// It is the production implementation of WebpushSender.
type HTTPWebpushSender struct{}

// NewHTTPWebpushSender creates a production WebpushSender backed by webpush-go.
func NewHTTPWebpushSender() *HTTPWebpushSender {
	return &HTTPWebpushSender{}
}

// Send delivers payloadJSON to the given subscription using VAPID authentication.
// A 10-second per-call context timeout is applied automatically.
// The response body is drained and closed before returning.
func (s *HTTPWebpushSender) Send(sub *Subscription, vapid *SpaceVapid, payloadJSON []byte) SendResult {
	sendCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
		TTL:             60,
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
