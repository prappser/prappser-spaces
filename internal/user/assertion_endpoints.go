package user

import (
	"crypto/ed25519"
	"encoding/base64"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

// AssertionEndpoints exposes the HTTP handlers for minting cross-space
// identity assertions (#111) and rebinding an account's issuer (#116 Phase
// 5).
type AssertionEndpoints struct {
	// userRepository is unused by IssueAssertion (the authenticated user
	// already comes from ctx via RequireAuth), but RebindIssuer writes
	// through it via SetUserIssuer.
	userRepository UserRepository
	privateKey     ed25519.PrivateKey
	spacePublicKey string
	// usedJTIs provides jti replay protection for RebindIssuer, the same
	// jtiStore mechanism DeviceEndpoints.usedJTIs uses for delegation JWSs
	// (device_endpoints.go) - a rebind JWS is single-use.
	usedJTIs *jtiStore
}

// NewAssertionEndpoints creates a new AssertionEndpoints. spacePublicKey is
// this space's own base64-encoded Ed25519 public key (see main.go's
// spacePublicKeyString) - it becomes every minted assertion's iss claim, and
// is the expected aud on an incoming rebind.
func NewAssertionEndpoints(userRepository UserRepository, privateKey ed25519.PrivateKey, spacePublicKey string) *AssertionEndpoints {
	return &AssertionEndpoints{userRepository: userRepository, privateKey: privateKey, spacePublicKey: spacePublicKey, usedJTIs: newJTIStore()}
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

// rebindIssuerRequest is the request body for POST /identity/rebind.
type rebindIssuerRequest struct {
	Rebind string `json:"rebind"`
}

// RebindIssuer handles POST /identity/rebind. Requires auth: the caller must
// be authenticated as the very account named by the rebind JWS's user_id
// claim - VerifyRebind is passed the authenticated user's public key as
// expectedUserID and enforces the match itself, before consuming the jti, so
// a valid JWS submitted under the wrong session doesn't burn its jti. users.
// issuer is provenance-only (see UserRepository's doc comment), so any
// transition the account key signs for is accepted, including
// vouched->self. Idempotent: when the account is already pinned to the
// requested issuer, this is a 204 no-op with no repository write.
func (ae *AssertionEndpoints) RebindIssuer(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("[REBIND] Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	var req rebindIssuerRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		log.Error().Err(err).Msg("[REBIND] Failed to parse rebind request body")
		ctx.Error("invalid request body", fasthttp.StatusBadRequest)
		return
	}

	claims, err := VerifyRebind(req.Rebind, ae.spacePublicKey, authenticatedUser.PublicKey, ae.usedJTIs, time.Now())
	if err != nil {
		log.Debug().Err(err).Msg("[REBIND] Rebind verification failed")
		ctx.Error("invalid rebind", fasthttp.StatusUnauthorized)
		return
	}

	if authenticatedUser.Issuer == claims.NewIssuer {
		log.Debug().Str("publicKey", claims.UserID).Msg("[REBIND] Already pinned to requested issuer, no-op")
		ctx.SetStatusCode(fasthttp.StatusNoContent)
		return
	}

	if err := ae.userRepository.SetUserIssuer(claims.UserID, claims.NewIssuer); err != nil {
		log.Error().Err(err).Msg("[REBIND] Failed to set user issuer")
		ctx.Error("internal server error", fasthttp.StatusInternalServerError)
		return
	}

	log.Debug().Str("publicKey", claims.UserID).Str("newIssuer", claims.NewIssuer).Msg("[REBIND] Issuer rebound")
	ctx.SetStatusCode(fasthttp.StatusNoContent)
}
