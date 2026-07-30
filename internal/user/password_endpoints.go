package user

import (
	"encoding/base64"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

// PasswordEndpoints exposes HTTP handlers for password-based login: salt
// retrieval and setting an account's password credentials.
type PasswordEndpoints struct {
	userRepository UserRepository
	saltSecret     []byte
	verifierKey    []byte
}

// NewPasswordEndpoints creates a new PasswordEndpoints. saltSecret and
// verifierKey come from derivePasswordSecrets (see password.go) - both are
// derived from the space keypair, not stored independently.
func NewPasswordEndpoints(userRepository UserRepository, saltSecret, verifierKey []byte) *PasswordEndpoints {
	return &PasswordEndpoints{userRepository: userRepository, saltSecret: saltSecret, verifierKey: verifierKey}
}

// saltResponse is the response body for GET /users/salt.
type saltResponse struct {
	Salt string `json:"salt"`
}

// GetSalt handles GET /users/salt?identifier=.... UNauthenticated and
// deliberately does NOT touch the database: the salt is a pure function of
// the identifier and the server-side saltSecret, so a real and an unknown
// identifier produce byte-identical response shapes - there is no
// database round trip whose timing or presence/absence could leak whether
// an identifier is registered. The only 400 case is a shape-invalid
// identifier, which is state-independent (true or false regardless of
// what's in the database).
func (pe *PasswordEndpoints) GetSalt(ctx *fasthttp.RequestCtx) {
	identifier, err := NormalizeIdentifier(string(ctx.QueryArgs().Peek("identifier")))
	if err != nil {
		log.Debug().Err(err).Msg("[PASSWORD] Invalid identifier for salt request")
		ctx.Error("identifier is required and must be valid", fasthttp.StatusBadRequest)
		return
	}

	salt := deterministicSalt(pe.saltSecret, identifier)

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(saltResponse{Salt: base64.StdEncoding.EncodeToString(salt)})
}

// setPasswordRequest is the request body for POST /users/password.
type setPasswordRequest struct {
	Identifier string `json:"identifier"`
	AuthSecret string `json:"authSecret"`
}

// SetPassword handles POST /users/password. Requires auth: the account
// setting its own password credentials must already be authenticated via
// the existing device-key flow.
func (pe *PasswordEndpoints) SetPassword(ctx *fasthttp.RequestCtx) {
	authenticatedUser, ok := ctx.UserValue("user").(*User)
	if !ok || authenticatedUser == nil {
		log.Error().Msg("[PASSWORD] Failed to get authenticated user from context")
		ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
		return
	}

	var req setPasswordRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		log.Error().Err(err).Msg("[PASSWORD] Failed to parse set password request body")
		ctx.Error("invalid request body", fasthttp.StatusBadRequest)
		return
	}

	identifier, err := NormalizeIdentifier(req.Identifier)
	if err != nil {
		log.Debug().Err(err).Msg("[PASSWORD] Invalid identifier for set password request")
		ctx.Error("identifier is invalid", fasthttp.StatusBadRequest)
		return
	}

	verifier, err := hashAuthSecret(pe.verifierKey, req.AuthSecret)
	if err != nil {
		log.Debug().Err(err).Msg("[PASSWORD] Invalid authSecret for set password request")
		ctx.Error("authSecret is invalid", fasthttp.StatusBadRequest)
		return
	}

	if err := pe.userRepository.SetPasswordCredentials(authenticatedUser.PublicKey, identifier, verifier); err != nil {
		if err == ErrIdentifierTaken {
			// Residual enumeration oracle, accepted deliberately: this 409
			// only fires for an AUTHENTICATED account choosing an identifier,
			// so it can only ever confirm "someone else already claimed the
			// identifier I just tried" - a much narrower leak than an
			// unauthenticated probe, and one an attacker already needs a
			// live account to exploit.
			log.Debug().Msg("[PASSWORD] Identifier already taken")
			ctx.Error("identifier already taken", fasthttp.StatusConflict)
			return
		}
		log.Error().Err(err).Msg("[PASSWORD] Failed to set password credentials")
		ctx.Error("internal server error", fasthttp.StatusInternalServerError)
		return
	}

	log.Debug().Str("publicKey", authenticatedUser.PublicKey).Msg("[PASSWORD] Password credentials set")
	ctx.SetStatusCode(fasthttp.StatusNoContent)
}
