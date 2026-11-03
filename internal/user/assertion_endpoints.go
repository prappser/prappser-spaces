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
type AssertionEndpoints struct {
	userRepository UserRepository
	privateKey     ed25519.PrivateKey
	spacePublicKey string
	bindings       *Bindings
}

// NewAssertionEndpoints creates a new AssertionEndpoints. spacePublicKey is
// this space's own base64-encoded Ed25519 public key (see main.go's
func NewAssertionEndpoints(userRepository UserRepository, privateKey ed25519.PrivateKey, spacePublicKey string, bindings *Bindings) *AssertionEndpoints {
	return &AssertionEndpoints{userRepository: userRepository, privateKey: privateKey, spacePublicKey: spacePublicKey, bindings: bindings}
}

type bindingResponse struct {
	Code    string `json:"code,omitempty"`
	Binding string `json:"binding,omitempty"`
}

func writeJSON(ctx *fasthttp.RequestCtx, status int, body any) {
	ctx.SetStatusCode(status)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(body)
}

// issueAssertionRequest is the request body for POST /identity/assertion.
type issueAssertionRequest struct {
	Audience string `json:"audience"`
}

// issueAssertionResponse is the response body for POST /identity/assertion.
type issueAssertionResponse struct {
	Assertion string `json:"assertion"`
	ExpiresAt int64  `json:"expiresAt"`
	Binding   string `json:"binding,omitempty"`
}

// IssueAssertion handles POST /identity/assertion. Requires auth: it mints
// an assertion vouching for the authenticated account, addressed to the
// relying space named by the request's audience, bound to the device that
// authenticated the current request (PoP, D3). Only an account whose identity
// space is this one may mint (Bindings.IsIdentitySpace), else 409 not_identity_space.
// ponytail: no per-account mint budget; add one if minting gets abused.
func (ae *AssertionEndpoints) IssueAssertion(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("[ASSERTION] Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	identity, err := ae.bindings.IsIdentitySpace(authenticatedUser)
	if err != nil {
		log.Error().Err(err).Msg("[ASSERTION] Failed to check identity space")
		ctx.Error("internal server error", fasthttp.StatusInternalServerError)
		return
	}
	if !identity {
		log.Debug().Msg("[ASSERTION] This space is not the account's identity space")
		writeJSON(ctx, fasthttp.StatusConflict, bindingResponse{Code: "not_identity_space", Binding: authenticatedUser.StoredBinding})
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
	writeJSON(ctx, fasthttp.StatusOK, issueAssertionResponse{Assertion: assertion, ExpiresAt: expiresAt, Binding: authenticatedUser.StoredBinding})
}

type putBindingRequest struct {
	Binding string `json:"binding"`
}

func (ae *AssertionEndpoints) PutBinding(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("[BINDING] Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	var req putBindingRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		log.Error().Err(err).Msg("[BINDING] Failed to parse binding request body")
		ctx.Error("invalid request body", fasthttp.StatusBadRequest)
		return
	}
	claims, err := verifyBinding(req.Binding, authenticatedUser.PublicKey, time.Now())
	if err != nil {
		log.Error().Err(err).Msg("[BINDING] Binding verification failed")
		ctx.Error("invalid binding", fasthttp.StatusBadRequest)
		return
	}

	if claims.Subject == ae.spacePublicKey {
		blob, _, err := ae.userRepository.GetEscrow(authenticatedUser.PublicKey)
		if err != nil {
			log.Error().Err(err).Msg("[BINDING] Failed to look up escrow")
			ctx.Error("internal server error", fasthttp.StatusInternalServerError)
			return
		}
		if blob == "" {
			log.Error().Msg("[BINDING] Binding names this space but the account has no escrow here")
			writeJSON(ctx, fasthttp.StatusConflict, bindingResponse{Code: "no_escrow"})
			return
		}
	}

	stored, _, err := ae.bindings.Accept(authenticatedUser.PublicKey, req.Binding, claims)
	if err != nil {
		log.Error().Err(err).Msg("[BINDING] Failed to accept binding")
		ctx.Error("internal server error", fasthttp.StatusInternalServerError)
		return
	}

	log.Debug().Str("publicKey", authenticatedUser.PublicKey).Msg("[BINDING] Binding processed")
	writeJSON(ctx, fasthttp.StatusOK, bindingResponse{Binding: stored})
}
