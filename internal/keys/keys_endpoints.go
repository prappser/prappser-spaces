package keys

import (
	"fmt"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

// minExportPassphraseLen guards against a caller picking an export
// passphrase weak enough that Argon2id (see EncryptPrivateKey) wouldn't
// meaningfully protect the blob.
const minExportPassphraseLen = 12

// KeyEndpoints exposes POST /space/identity/export (owner-only, wired via
// authMiddleware.RequireRole in internal/http.go) and the request-touch
// hook that keeps GET /status's lastSeenAt fresh.
type KeyEndpoints struct {
	keyService *KeyService
}

func NewKeyEndpoints(keyService *KeyService) *KeyEndpoints {
	return &KeyEndpoints{keyService: keyService}
}

// TouchLastSeen delegates to KeyService.TouchLastSeen; nil-safe so
// internal/http.go can call it unconditionally even where keyEndpoints is
// nil (e.g. in tests that don't wire this dependency).
func (ke *KeyEndpoints) TouchLastSeen() {
	if ke == nil || ke.keyService == nil {
		return
	}
	ke.keyService.TouchLastSeen()
}

// exportIdentityRequest is the request body for POST /space/identity/export.
type exportIdentityRequest struct {
	Passphrase string `json:"passphrase"`
}

// exportIdentityResponse is the response body for POST
// /space/identity/export. Blob is the PRAPSPACE1... export produced by
// KeyService.ExportIdentity - NEVER logged (see ExportIdentity).
type exportIdentityResponse struct {
	Blob       string `json:"blob"`
	PublicKey  string `json:"publicKey"`
	ExportedAt int64  `json:"exportedAt"`
}

// ExportIdentity handles POST /space/identity/export. Owner-only by
// routing (see internal/http.go): this blob plus its passphrase lets
// whoever holds it re-derive the space's private key, so only the account
// already trusted with the space itself may mint one.
func (ke *KeyEndpoints) ExportIdentity(ctx *fasthttp.RequestCtx) {
	var req exportIdentityRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		log.Error().Err(err).Msg("[KEYS] Failed to parse export request body")
		ctx.Error("invalid request body", fasthttp.StatusBadRequest)
		return
	}

	if len(req.Passphrase) < minExportPassphraseLen {
		log.Debug().Msg("[KEYS] Export passphrase missing or too short")
		ctx.Error(fmt.Sprintf("passphrase must be at least %d characters", minExportPassphraseLen), fasthttp.StatusBadRequest)
		return
	}

	blob, err := ke.keyService.ExportIdentity(req.Passphrase)
	if err != nil {
		log.Error().Err(err).Msg("[KEYS] Failed to export identity")
		ctx.Error("internal server error", fasthttp.StatusInternalServerError)
		return
	}

	publicKey := ke.keyService.PublicKeyBase64()
	log.Info().Str("publicKey", publicKey[:min(8, len(publicKey))]).Msg("[KEYS] identity export requested")

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(exportIdentityResponse{
		Blob:       blob,
		PublicKey:  publicKey,
		ExportedAt: time.Now().Unix(),
	})
}
