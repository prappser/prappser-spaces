package user

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

// OwnerClaimEndpoints exposes the one-shot, unauthenticated
// POST /users/owners/claim endpoint that creates a space's owner account
// (see Claim). It replaces the pre-#114 JWE/JWS registerOwner flow.
type OwnerClaimEndpoints struct {
	userRepository UserRepository
	verifierKey    []byte
	claimDeadline  time.Time
	spaceCreator   SpaceCreator
}

// ownerClaimWindow is how long after process start an unclaimed space accepts
// a claim. Restarting the server reopens it.
const ownerClaimWindow = 30 * time.Minute

// NewOwnerClaimEndpoints creates a new OwnerClaimEndpoints. verifierKey comes
// from DerivePasswordSecrets (see password.go), shared with PasswordEndpoints
// and DeviceEndpoints - all three are derived once from the space keypair in
// main.go. Claims are accepted until startedAt + ownerClaimWindow.
func NewOwnerClaimEndpoints(userRepository UserRepository, verifierKey []byte, startedAt time.Time, spaceCreator SpaceCreator) *OwnerClaimEndpoints {
	return &OwnerClaimEndpoints{userRepository: userRepository, verifierKey: verifierKey, claimDeadline: startedAt.Add(ownerClaimWindow), spaceCreator: spaceCreator}
}

// claimOwnerRequest is the request body for POST /users/owners/claim.
// Username is always required: an account always has a name by the time it
// claims a space. Older clients still send masterPasswordSalt and
// masterPasswordProof; they are ignored as unknown keys. AuthSecret,
// AccountKeyBlob, and UserState are optional - a claim may create an owner
// account with no password set yet; sent values validate exactly as before
// (see Claim). DevicePublicKey is optional too, defaulting to PublicKey when
// empty - today's behavior for every client that predates the account/device
// split.
type claimOwnerRequest struct {
	Username        string `json:"username"`
	PublicKey       string `json:"publicKey"`
	AuthSecret      string `json:"authSecret,omitempty"`
	AccountKeyBlob  string `json:"accountKeyBlob,omitempty"`
	UserState       string `json:"userState,omitempty"`
	DeviceName      string `json:"deviceName,omitempty"`
	DevicePublicKey string `json:"devicePublicKey,omitempty"`
}

// claimOwnerResponse is the response body for POST /users/owners/claim.
// Deliberately has NO token: the app authenticates through the existing
// challenge/auth flow (GetChallenge + UserAuth) immediately afterwards,
// exactly as the pre-#114 registerOwner flow did - do not "fix" this by
// minting a JWT here.
type claimOwnerResponse struct {
	UserPublicKey string `json:"userPublicKey"`
	Username      string `json:"username"`
	Role          string `json:"role"`
	CreatedAt     int64  `json:"createdAt"`
}

// Claim handles POST /users/owners/claim. UNauthenticated by design: it
// creates the very first account in a space, so there is nothing to
// authenticate against yet. The JWS proof-of-possession the old JWE/JWS flow
// required is dropped on purpose - the claimer picks the account public key
// either way, so a signature with it would prove nothing.
//
// Validation order matters and must not be reordered: all shape checks run
// first, since they are cheap and state-independent. HasClaim() is checked
// before the window, so an already-claimed space always answers 409, even
// after the window closes. This also keeps ErrUsernameTaken out of that path
// (ClaimOwner inserts the user before the claim row). Only then does
// ClaimOwner run.
func (oe *OwnerClaimEndpoints) Claim(ctx *fasthttp.RequestCtx) {
	var req claimOwnerRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		log.Error().Err(err).Msg("[OWNER_CLAIM] Failed to parse claim request body")
		ctx.Error("invalid request body", fasthttp.StatusBadRequest)
		return
	}

	username, err := NormalizeUsername(req.Username)
	if err != nil {
		log.Debug().Err(err).Msg("[OWNER_CLAIM] Invalid username")
		ctx.Error("username is invalid", fasthttp.StatusBadRequest)
		return
	}

	if !isValidPublicKey(req.PublicKey) {
		log.Debug().Msg("[OWNER_CLAIM] Invalid publicKey")
		ctx.Error("publicKey must be 32 std-base64-encoded bytes", fasthttp.StatusBadRequest)
		return
	}

	// devicePublicKey defaults to the account key, matching every client
	// that predates the account/device split; an explicit one is validated
	// exactly like publicKey above.
	devicePublicKey := req.DevicePublicKey
	if devicePublicKey == "" {
		devicePublicKey = req.PublicKey
	} else if !isValidPublicKey(devicePublicKey) {
		log.Debug().Msg("[OWNER_CLAIM] Invalid devicePublicKey")
		ctx.Error("devicePublicKey must be 32 std-base64-encoded bytes", fasthttp.StatusBadRequest)
		return
	}

	var deviceName *string
	if normalized, ok := NormalizeDeviceName(req.DeviceName); ok {
		deviceName = &normalized
	}

	if err := validateEscrowBlob(req.AccountKeyBlob, maxAccountKeyBlobLen); err != nil {
		log.Debug().Err(err).Msg("[OWNER_CLAIM] Invalid accountKeyBlob")
		ctx.Error("accountKeyBlob is invalid", fasthttp.StatusBadRequest)
		return
	}

	if err := validateEscrowBlob(req.UserState, maxUserStateBlobLen); err != nil {
		log.Debug().Err(err).Msg("[OWNER_CLAIM] Invalid userState")
		ctx.Error("userState is invalid", fasthttp.StatusBadRequest)
		return
	}

	// AuthSecret is optional: claiming without a password leaves both
	// verifier and handle empty, which ClaimOwner's NULLIF wrapping turns
	// into SQL NULL - hashAuthSecret must not run on an empty string, since
	// it requires exactly 32 base64-decoded bytes and would reject it.
	var verifier, handle string
	if req.AuthSecret != "" {
		verifier, err = hashAuthSecret(oe.verifierKey, req.AuthSecret)
		if err != nil {
			log.Debug().Err(err).Msg("[OWNER_CLAIM] Invalid authSecret")
			ctx.Error("authSecret is invalid", fasthttp.StatusBadRequest)
			return
		}
		handle = strings.ToLower(username)
	}

	hasClaim, err := oe.userRepository.HasClaim()
	if err != nil {
		log.Error().Err(err).Msg("[OWNER_CLAIM] Failed to check for existing claim")
		ctx.Error("internal server error", fasthttp.StatusInternalServerError)
		return
	}
	if hasClaim {
		log.Debug().Msg("[OWNER_CLAIM] Space already claimed")
		ctx.Error("space already claimed", fasthttp.StatusConflict)
		return
	}

	if time.Now().After(oe.claimDeadline) {
		log.Error().Msg("[OWNER_CLAIM] Owner claim window closed")
		ctx.Error("owner claim window closed, restart the server to reopen it", fasthttp.StatusForbidden)
		return
	}

	publicKey := req.PublicKey
	createdAt := time.Now().Unix()

	if err := oe.userRepository.ClaimOwner(publicKey, username, verifier, handle, req.AccountKeyBlob, req.UserState, devicePublicKey, deviceName, createdAt); err != nil {
		switch err {
		case ErrSpaceAlreadyClaimed:
			log.Debug().Msg("[OWNER_CLAIM] Space already claimed (lost the race)")
			ctx.Error("space already claimed", fasthttp.StatusConflict)
		case ErrUsernameTaken:
			log.Debug().Msg("[OWNER_CLAIM] Username already used for password login")
			ctx.Error("username already used for password login on this space", fasthttp.StatusConflict)
		case ErrDeviceKeyTaken:
			log.Debug().Msg("[OWNER_CLAIM] Device key already registered on this space")
			ctx.Error("device key is already registered on this space", fasthttp.StatusConflict)
		default:
			log.Error().Err(err).Msg("[OWNER_CLAIM] Failed to claim owner")
			ctx.Error("internal server error", fasthttp.StatusInternalServerError)
		}
		return
	}

	// Auto-create default space for the new owner - non-fatal, exactly like
	// the pre-#114 registerOwner flow: the owner account is the source of
	// truth, a missing default space can be created later.
	if oe.spaceCreator != nil {
		if err := oe.spaceCreator.CreateSpace(username+"'s space", &publicKey); err != nil {
			log.Error().Err(err).Msg("[OWNER_CLAIM] Failed to create default space for new owner")
		} else {
			log.Info().Str("publicKey", publicKey[:min(50, len(publicKey))]+"...").Msg("[OWNER_CLAIM] Default space created for new owner")
		}
	}

	log.Debug().Str("publicKey", publicKey[:min(50, len(publicKey))]+"...").Msg("[OWNER_CLAIM] Owner claimed")
	ctx.SetStatusCode(fasthttp.StatusCreated)
	ctx.SetContentType("application/json")
	json.NewEncoder(ctx).Encode(claimOwnerResponse{
		UserPublicKey: publicKey,
		Username:      username,
		Role:          RoleOwner,
		CreatedAt:     createdAt,
	})
}

// isValidPublicKey reports whether s decodes as std-base64 into exactly
// ed25519.PublicKeySize bytes - the shape both publicKey and devicePublicKey
// must have.
func isValidPublicKey(s string) bool {
	decoded, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(decoded) == ed25519.PublicKeySize
}
