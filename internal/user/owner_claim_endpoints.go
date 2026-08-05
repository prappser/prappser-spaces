package user

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/prappser/prappser-spaces/internal/keys"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

// OwnerClaimEndpoints exposes the one-shot, unauthenticated
// POST /users/owners/claim endpoint that creates a space's owner account
// (see Claim). It replaces the pre-#114 JWE/JWS registerOwner flow.
type OwnerClaimEndpoints struct {
	userRepository UserRepository
	verifierKey    []byte
	masterPassword string
	spaceCreator   SpaceCreator
}

// NewOwnerClaimEndpoints creates a new OwnerClaimEndpoints. verifierKey comes
// from DerivePasswordSecrets (see password.go), shared with PasswordEndpoints
// and DeviceEndpoints - all three are derived once from the space keypair in
// main.go. masterPassword is the space's plaintext master password
// (config.Users.MasterPassword); the claimer proves knowledge of it via an
// Argon2id proof (see Claim), never sends it directly.
func NewOwnerClaimEndpoints(userRepository UserRepository, verifierKey []byte, masterPassword string, spaceCreator SpaceCreator) *OwnerClaimEndpoints {
	return &OwnerClaimEndpoints{userRepository: userRepository, verifierKey: verifierKey, masterPassword: masterPassword, spaceCreator: spaceCreator}
}

// claimOwnerRequest is the request body for POST /users/owners/claim.
// MasterPasswordSalt and MasterPasswordProof are std-base64: proof is the
// client's Argon2id keys.DeriveKey(masterPassword, salt) - proving knowledge
// of the plaintext master password without ever putting it on the wire or in
// a proxy log (see Claim). AuthSecret, AccountKeyBlob, and UserState mirror
// setPasswordRequest (password_endpoints.go) - password is MANDATORY here,
// unlike SetPassword's authenticated flow.
type claimOwnerRequest struct {
	Username            string `json:"username"`
	PublicKey           string `json:"publicKey"`
	MasterPasswordSalt  string `json:"masterPasswordSalt"`
	MasterPasswordProof string `json:"masterPasswordProof"`
	AuthSecret          string `json:"authSecret"`
	AccountKeyBlob      string `json:"accountKeyBlob,omitempty"`
	UserState           string `json:"userState,omitempty"`
	DeviceName          string `json:"deviceName,omitempty"`
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
// either way, so signing with it proves nothing an attacker holding the
// master password couldn't also produce.
//
// Validation order matters and must not be reordered: all shape checks
// (username, publicKey, deviceName, escrow blobs, authSecret) run first,
// since they are cheap and state-independent. HasClaim() runs next, BEFORE
// the Argon2id master-password check below - this endpoint is
// unauthenticated by construction, and keys.DeriveKey costs 64 MiB of memory
// per call, so an already-claimed space must reject at DB-lookup cost, never
// at KDF cost, or an attacker gets a cheap memory-exhaustion lever against a
// space that has nothing left to claim. Only once all of that has passed
// does the handler pay for Argon2id and hit ClaimOwner's transaction.
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

	publicKeyBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(publicKeyBytes) != ed25519.PublicKeySize {
		log.Debug().Msg("[OWNER_CLAIM] Invalid publicKey")
		ctx.Error("publicKey must be 32 std-base64-encoded bytes", fasthttp.StatusBadRequest)
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

	// hashAuthSecret is a keyed HMAC over an already-high-entropy input, not
	// a KDF - cheap, so it belongs in shape validation, not behind the
	// HasClaim pre-check below (see this method's doc comment).
	verifier, err := hashAuthSecret(oe.verifierKey, req.AuthSecret)
	if err != nil {
		log.Debug().Err(err).Msg("[OWNER_CLAIM] Invalid authSecret")
		ctx.Error("authSecret is invalid", fasthttp.StatusBadRequest)
		return
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

	salt, err := base64.StdEncoding.DecodeString(req.MasterPasswordSalt)
	if err != nil || len(salt) != keys.SaltSize {
		log.Debug().Msg("[OWNER_CLAIM] Invalid masterPasswordSalt")
		ctx.Error("masterPasswordSalt must be 32 std-base64-encoded bytes", fasthttp.StatusBadRequest)
		return
	}
	proof, err := base64.StdEncoding.DecodeString(req.MasterPasswordProof)
	if err != nil {
		log.Debug().Msg("[OWNER_CLAIM] Invalid masterPasswordProof encoding")
		ctx.Error("masterPasswordProof is invalid", fasthttp.StatusBadRequest)
		return
	}

	expectedProof := keys.DeriveKey(oe.masterPassword, salt)
	if subtle.ConstantTimeCompare(expectedProof, proof) != 1 {
		log.Debug().Msg("[OWNER_CLAIM] Master password proof mismatch")
		ctx.Error("invalid master password proof", fasthttp.StatusUnauthorized)
		return
	}

	publicKey := req.PublicKey
	handle := strings.ToLower(username)
	createdAt := time.Now().Unix()

	if err := oe.userRepository.ClaimOwner(publicKey, username, verifier, handle, req.AccountKeyBlob, req.UserState, deviceName, createdAt); err != nil {
		switch err {
		case ErrSpaceAlreadyClaimed:
			log.Debug().Msg("[OWNER_CLAIM] Space already claimed (lost the race)")
			ctx.Error("space already claimed", fasthttp.StatusConflict)
		case ErrUsernameTaken:
			log.Debug().Msg("[OWNER_CLAIM] Username already used for password login")
			ctx.Error("username already used for password login on this space", fasthttp.StatusConflict)
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
