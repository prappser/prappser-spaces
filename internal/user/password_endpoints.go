package user

import (
	"encoding/base64"
	"strings"

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

// GetSalt handles GET /users/salt?username=.... UNauthenticated. Unlike the
// pre-#126 pure-function design, this now runs ONE constant-shape DB query
// (GetPasswordHandle) for every request, known or unknown username alike - a
// deliberate trade for rename-safety: once a password-enabled account is
// renamed, the string a client's salt must be derived from is the ORIGINAL
// handle (== the username at set-password time), not the current username,
// so a pure function of the current username alone can no longer answer
// correctly on its own.
//
// Storing the HANDLE rather than a derived salt blob is what makes this
// migration-safe: a handle is plain text a backfill UPDATE can compute
// (lower(old identifier)), so every pre-existing password-enabled account
// keeps producing the exact same salt it always has, with zero client
// changes required.
//
// Anti-enumeration is still preserved: both branches - a real,
// password-enabled username and an unknown one - run the exact same
// GetPasswordHandle query and compute the exact same HMAC exactly once, so
// the response is byte-indistinguishable regardless of whether the username
// is registered; only which string fed the HMAC differs, and that never
// surfaces to the caller. The only 400 case is a shape-invalid username,
// which is state-independent (true or false regardless of what's in the
// database).
func (pe *PasswordEndpoints) GetSalt(ctx *fasthttp.RequestCtx) {
	username, err := NormalizeUsername(string(ctx.QueryArgs().Peek("username")))
	if err != nil {
		log.Debug().Err(err).Msg("[PASSWORD] Invalid username for salt request")
		ctx.Error("username is required and must be valid", fasthttp.StatusBadRequest)
		return
	}

	handle, err := pe.userRepository.GetPasswordHandle(username)
	if err != nil {
		log.Debug().Err(err).Msg("[PASSWORD] Failed to look up password handle for salt request")
	}
	input := strings.ToLower(username)
	if handle != "" {
		input = handle
	}
	salt := base64.StdEncoding.EncodeToString(deterministicSalt(pe.saltSecret, input))

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(saltResponse{Salt: salt})
}

// setPasswordRequest is the request body for POST /users/password. There is
// no username field: the username is the authenticated caller's OWN
// username (authenticatedUser.Username), never a client-supplied value - see
// SetPassword. AccountKeyBlob and UserState are the encrypted escrow blobs
// (see escrow.go on the client) - both optional, and omitting either clears
// it (see SetPasswordCredentials).
type setPasswordRequest struct {
	AuthSecret     string `json:"authSecret"`
	AccountKeyBlob string `json:"accountKeyBlob,omitempty"`
	UserState      string `json:"userState,omitempty"`
}

// SetPassword handles POST /users/password. Requires auth: the account
// setting its own password credentials must already be authenticated via
// the existing device-key flow. The password-login handle is always
// authenticatedUser.Username - there is no separate identifier to submit
// (see setPasswordRequest).
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

	verifier, err := hashAuthSecret(pe.verifierKey, req.AuthSecret)
	if err != nil {
		log.Debug().Err(err).Msg("[PASSWORD] Invalid authSecret for set password request")
		ctx.Error("authSecret is invalid", fasthttp.StatusBadRequest)
		return
	}

	if err := validateEscrowBlob(req.AccountKeyBlob, maxAccountKeyBlobLen); err != nil {
		log.Debug().Err(err).Msg("[PASSWORD] Invalid accountKeyBlob for set password request")
		ctx.Error("accountKeyBlob is invalid", fasthttp.StatusBadRequest)
		return
	}

	if err := validateEscrowBlob(req.UserState, maxUserStateBlobLen); err != nil {
		log.Debug().Err(err).Msg("[PASSWORD] Invalid userState for set password request")
		ctx.Error("userState is invalid", fasthttp.StatusBadRequest)
		return
	}

	handle := strings.ToLower(authenticatedUser.Username)

	if err := pe.userRepository.SetPasswordCredentials(authenticatedUser.PublicKey, verifier, handle, req.AccountKeyBlob, req.UserState); err != nil {
		if err == ErrUsernameTaken {
			// Residual enumeration oracle, accepted deliberately: this 409
			// only fires for an AUTHENTICATED account whose OWN username
			// collides with another password-enabled account, so it can
			// only ever confirm "someone else already claimed my username
			// for password login" - a much narrower leak than an
			// unauthenticated probe, and one an attacker already needs a
			// live account to exploit.
			log.Debug().Msg("[PASSWORD] Username already used for password login")
			ctx.Error("username already used for password login on this space", fasthttp.StatusConflict)
			return
		}
		log.Error().Err(err).Msg("[PASSWORD] Failed to set password credentials")
		ctx.Error("internal server error", fasthttp.StatusInternalServerError)
		return
	}

	log.Debug().Str("publicKey", authenticatedUser.PublicKey).Msg("[PASSWORD] Password credentials set")
	ctx.SetStatusCode(fasthttp.StatusNoContent)
}
