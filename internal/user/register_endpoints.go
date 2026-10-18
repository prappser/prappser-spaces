package user

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

// RegisterEndpoints exposes the public POST /users/register endpoint that
// creates a 'user'-role account with username and password, gated by
// OPEN_REGISTRATION and MAX_ACCOUNTS.
type RegisterEndpoints struct {
	userRepository   UserRepository
	verifierKey      []byte
	openRegistration bool
	maxAccounts      int
}

// NewRegisterEndpoints creates a new RegisterEndpoints. verifierKey is the
// same DerivePasswordSecrets key OwnerClaimEndpoints and PasswordEndpoints
// use; maxAccounts 0 means unlimited.
func NewRegisterEndpoints(userRepository UserRepository, verifierKey []byte, openRegistration bool, maxAccounts int) *RegisterEndpoints {
	return &RegisterEndpoints{userRepository: userRepository, verifierKey: verifierKey, openRegistration: openRegistration, maxAccounts: maxAccounts}
}

// Above the 64 KiB userState max; public route on a server that accepts 50 MiB bodies.
const maxRegisterBodyLen = 128 * 1024

// registerRequest is the request body for POST /users/register. Unlike a
// claim, devicePublicKey, authSecret, and accountKeyBlob are all required.
type registerRequest struct {
	Username        string `json:"username"`
	PublicKey       string `json:"publicKey"`
	DevicePublicKey string `json:"devicePublicKey"`
	DeviceName      string `json:"deviceName,omitempty"`
	AuthSecret      string `json:"authSecret"`
	AccountKeyBlob  string `json:"accountKeyBlob"`
	UserState       string `json:"userState,omitempty"`
}

// Register handles POST /users/register. Like Claim it mints no token: the
// client authenticates with its device key via GetChallenge + UserAuth.
//
// The handle stored is lower(username), the same string GetSalt hashes for an
// unknown username, so the salt the client derived its authSecret with before
// registering stays the salt it gets afterwards.
func (re *RegisterEndpoints) Register(ctx *fasthttp.RequestCtx) {
	if !re.openRegistration {
		log.Debug().Msg("[REGISTER] Registration is closed")
		writeCodedError(ctx, fasthttp.StatusForbidden, "registration is closed on this space", "registration_closed")
		return
	}

	if len(ctx.PostBody()) > maxRegisterBodyLen {
		log.Debug().Msg("[REGISTER] Request body too large")
		ctx.Error("request body too large", fasthttp.StatusBadRequest)
		return
	}

	var req registerRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		log.Error().Msg("[REGISTER] Failed to parse register request body")
		ctx.Error("invalid request body", fasthttp.StatusBadRequest)
		return
	}

	username, err := NormalizeUsername(req.Username)
	if err != nil {
		log.Debug().Err(err).Msg("[REGISTER] Invalid username")
		ctx.Error("username is invalid", fasthttp.StatusBadRequest)
		return
	}

	if !isValidPublicKey(req.PublicKey) {
		log.Debug().Msg("[REGISTER] Invalid publicKey")
		ctx.Error("publicKey must be 32 std-base64-encoded bytes", fasthttp.StatusBadRequest)
		return
	}

	if !isValidPublicKey(req.DevicePublicKey) {
		log.Debug().Msg("[REGISTER] Invalid devicePublicKey")
		ctx.Error("devicePublicKey must be 32 std-base64-encoded bytes", fasthttp.StatusBadRequest)
		return
	}

	var deviceName *string
	if normalized, ok := NormalizeDeviceName(req.DeviceName); ok {
		deviceName = &normalized
	}

	verifier, err := hashAuthSecret(re.verifierKey, req.AuthSecret)
	if err != nil {
		log.Debug().Err(err).Msg("[REGISTER] Invalid authSecret")
		ctx.Error("authSecret is invalid", fasthttp.StatusBadRequest)
		return
	}

	if req.AccountKeyBlob == "" {
		log.Debug().Msg("[REGISTER] Missing accountKeyBlob")
		ctx.Error("accountKeyBlob is required", fasthttp.StatusBadRequest)
		return
	}
	if err := validateEscrowBlob(req.AccountKeyBlob, maxAccountKeyBlobLen); err != nil {
		log.Debug().Err(err).Msg("[REGISTER] Invalid accountKeyBlob")
		ctx.Error("accountKeyBlob is invalid", fasthttp.StatusBadRequest)
		return
	}

	if err := validateEscrowBlob(req.UserState, maxUserStateBlobLen); err != nil {
		log.Debug().Err(err).Msg("[REGISTER] Invalid userState")
		ctx.Error("userState is invalid", fasthttp.StatusBadRequest)
		return
	}

	limitReached, err := re.accountLimitReached()
	if err != nil {
		log.Error().Err(err).Msg("[REGISTER] Failed to check account limit")
		ctx.Error("internal server error", fasthttp.StatusInternalServerError)
		return
	}
	if limitReached {
		log.Debug().Msg("[REGISTER] Account limit reached")
		writeCodedError(ctx, fasthttp.StatusForbidden, "this space is not accepting new accounts", "account_limit_reached")
		return
	}

	createdAt := time.Now().Unix()
	err = re.userRepository.RegisterUser(req.PublicKey, username, verifier, strings.ToLower(username), req.AccountKeyBlob, req.UserState, req.DevicePublicKey, deviceName, createdAt)
	switch {
	case err == nil:
	case errors.Is(err, ErrUsernameTaken):
		log.Debug().Msg("[REGISTER] Username already taken")
		writeCodedError(ctx, fasthttp.StatusConflict, "username is already taken on this space", "username_taken")
		return
	case errors.Is(err, ErrAccountExists):
		log.Debug().Msg("[REGISTER] Account already exists")
		writeCodedError(ctx, fasthttp.StatusConflict, "an account with this public key already exists", "account_exists")
		return
	case errors.Is(err, ErrDeviceKeyTaken):
		log.Debug().Msg("[REGISTER] Device key already registered")
		writeCodedError(ctx, fasthttp.StatusConflict, "device key is already registered on this space", "device_key_taken")
		return
	default:
		log.Error().Err(err).Msg("[REGISTER] Failed to register user")
		ctx.Error("internal server error", fasthttp.StatusInternalServerError)
		return
	}

	log.Debug().Str("username", username).Msg("[REGISTER] Account registered")
	ctx.SetStatusCode(fasthttp.StatusCreated)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(claimOwnerResponse{
		UserPublicKey: req.PublicKey,
		Username:      username,
		Role:          RoleUser,
		CreatedAt:     createdAt,
	})
}

// RegistrationOpen reports whether Register would currently accept a new
// account, for GET /health. A failed count reads as closed.
func (re *RegisterEndpoints) RegistrationOpen() bool {
	if !re.openRegistration {
		return false
	}
	limitReached, err := re.accountLimitReached()
	if err != nil {
		log.Error().Err(err).Msg("[REGISTER] Failed to check account limit for health")
		return false
	}
	return !limitReached
}

// ponytail: soft cap, count-then-insert like the invite signup gate, so
// parallel registrations can overshoot MAX_ACCOUNTS slightly.
func (re *RegisterEndpoints) accountLimitReached() (bool, error) {
	if re.maxAccounts == 0 {
		return false, nil
	}
	n, err := re.userRepository.CountUsers()
	if err != nil {
		return false, fmt.Errorf("failed to count accounts: %w", err)
	}
	return n >= re.maxAccounts, nil
}

// writeCodedError writes the {"error", "code"} JSON body the app matches on.
func writeCodedError(ctx *fasthttp.RequestCtx, status int, message, code string) {
	body, _ := json.Marshal(map[string]string{"error": message, "code": code})
	ctx.SetStatusCode(status)
	ctx.SetContentType("application/json")
	ctx.SetBody(body)
}
