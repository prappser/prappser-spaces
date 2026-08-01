package user

import (
	"crypto/ed25519"
	"encoding/base64"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

// AssertionEndpoints exposes the HTTP handler for minting cross-space
// identity assertions (#111).
type AssertionEndpoints struct {
	// userRepository is currently unused by IssueAssertion (the
	// authenticated user already comes from ctx via RequireAuth) - kept for
	// a future per-account mint budget (#110).
	userRepository UserRepository
	privateKey     ed25519.PrivateKey
	spacePublicKey string
}

// NewAssertionEndpoints creates a new AssertionEndpoints. spacePublicKey is
// this space's own base64-encoded Ed25519 public key (see main.go's
// spacePublicKeyString) - it becomes every minted assertion's iss claim.
func NewAssertionEndpoints(userRepository UserRepository, privateKey ed25519.PrivateKey, spacePublicKey string) *AssertionEndpoints {
	return &AssertionEndpoints{userRepository: userRepository, privateKey: privateKey, spacePublicKey: spacePublicKey}
}

// issueAssertionRequest is the request body for POST /identity/assertion.
type issueAssertionRequest struct {
	Audience string `json:"audience"`
}

// issueAssertionResponse is the response body for POST /identity/assertion.
type issueAssertionResponse struct {
	Assertion string `json:"assertion"`
	ExpiresAt int64  `json:"expiresAt"`
}

// IssueAssertion handles POST /identity/assertion. Requires auth: it mints
// an assertion vouching for the authenticated account, addressed to the
// relying space named by the request's audience, bound to the device that
// authenticated the current request (PoP, D3). Mints for any authenticated
// account, including one that is itself only self-asserted here - gating
// which accounts may mint at all is #110, out of scope.
// ponytail: no per-account mint budget; add if #110 lands.
func (ae *AssertionEndpoints) IssueAssertion(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("[ASSERTION] Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	var req issueAssertionRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		log.Error().Err(err).Msg("[ASSERTION] Failed to parse issue assertion request body")
		ctx.Error("invalid request body", fasthttp.StatusBadRequest)
		return
	}

	if req.Audience == "" {
		log.Debug().Msg("[ASSERTION] Missing audience")
		ctx.Error("audience is required", fasthttp.StatusBadRequest)
		return
	}
	audienceBytes, err := base64.StdEncoding.DecodeString(req.Audience)
	if err != nil || len(audienceBytes) != ed25519.PublicKeySize {
		log.Debug().Msg("[ASSERTION] Malformed audience")
		ctx.Error("audience must be 32 std-base64-encoded bytes", fasthttp.StatusBadRequest)
		return
	}
	if req.Audience == ae.spacePublicKey {
		log.Debug().Msg("[ASSERTION] Audience equals this space's own key")
		ctx.Error("audience must not be this space's own key", fasthttp.StatusBadRequest)
		return
	}

	assertion, expiresAt, err := mintAssertion(ae.privateKey, ae.spacePublicKey, authenticatedUser.PublicKey, req.Audience, authenticatedUser.Username, authenticatedUser.DevicePublicKey, time.Now())
	if err != nil {
		log.Error().Err(err).Msg("[ASSERTION] Failed to mint assertion")
		ctx.Error("internal server error", fasthttp.StatusInternalServerError)
		return
	}

	log.Debug().Str("publicKey", authenticatedUser.PublicKey).Str("audience", req.Audience).Msg("[ASSERTION] Assertion issued")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(issueAssertionResponse{Assertion: assertion, ExpiresAt: expiresAt})
}
