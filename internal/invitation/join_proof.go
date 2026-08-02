package invitation

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Join proof-of-possession (#110): before Join enrolls a device key it
// requires proof the caller controls the private key for that device
// public key. The proof is a short-lived JWS signed by the device key it
// names, bound to a specific invite (D4) so it can't be replayed against
// another invite or space.
const (
	// joinProofTTLSec is deliberately short compared to the cross-space
	// assertion TTL (assertionTTLSec = 120, user/assertion.go) - the proof
	// is inviteId-bound and Join is idempotent on re-join, so it only needs
	// to tolerate a slow argon2-less mobile POST, not a general freshness
	// window. Closest precedent is defaultRegistrationTokenTTLSec = 10
	// (internal/config.go).
	joinProofTTLSec = 60
	// joinProofSkewSec tolerates clock drift between the client device and
	// this space.
	joinProofSkewSec = 30
)

// ErrInvalidProof is the single error verifyJoinProof ever returns,
// regardless of which check failed - anti-enumeration, same rationale as
// user.ErrInvalidAssertion (see its doc comment).
var ErrInvalidProof = errors.New("invalid join proof")

// joinProofClaims are the claims of a join-proof JWS. The wire format is
// frozen: publicKey, devicePublicKey, username, inviteId, iat.
type joinProofClaims struct {
	PublicKey       string `json:"publicKey"`
	DevicePublicKey string `json:"devicePublicKey"`
	Username        string `json:"username"`
	InviteID        string `json:"inviteId"`
	IssuedAt        int64  `json:"iat"`
}

// verifyJoinProof validates a signed join-proof JWS and returns its claims.
// expectedInviteID must equal the invite this proof is being redeemed
// against (D4). Every failure collapses to ErrInvalidProof so callers never
// need to distinguish which specific check failed - just surface a generic
// 401.
//
// Verify order (mirrors user.VerifyAssertion, assertion.go:96-171):
//  1. parse claims unverified, reject if any required claim is empty
//  2. devicePublicKey decodes to exactly an Ed25519 public key's worth of bytes
//  3. signature verifies against devicePublicKey itself, requiring EdDSA
//  4. inviteId matches expectedInviteID
//  5. iat is set, not implausibly in the future (skew-tolerant), and not
//     older than joinProofTTLSec (skew-tolerant)
func verifyJoinProof(signedJWS, expectedInviteID string, now time.Time) (*joinProofClaims, error) {
	token, _, err := jwt.NewParser().ParseUnverified(signedJWS, jwt.MapClaims{})
	if err != nil {
		return nil, ErrInvalidProof
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidProof
	}

	var claims joinProofClaims
	if pk, ok := mapClaims["publicKey"].(string); ok {
		claims.PublicKey = pk
	}
	if dpk, ok := mapClaims["devicePublicKey"].(string); ok {
		claims.DevicePublicKey = dpk
	}
	if un, ok := mapClaims["username"].(string); ok {
		claims.Username = un
	}
	if inviteID, ok := mapClaims["inviteId"].(string); ok {
		claims.InviteID = inviteID
	}
	if iat, ok := mapClaims["iat"].(float64); ok {
		claims.IssuedAt = int64(iat)
	}

	if claims.PublicKey == "" || claims.DevicePublicKey == "" || claims.Username == "" || claims.InviteID == "" {
		return nil, ErrInvalidProof
	}

	deviceKeyBytes, err := base64.StdEncoding.DecodeString(claims.DevicePublicKey)
	if err != nil || len(deviceKeyBytes) != ed25519.PublicKeySize {
		return nil, ErrInvalidProof
	}
	devicePublicKey := ed25519.PublicKey(deviceKeyBytes)

	// WithoutClaimsValidation: iat gets its own skew-tolerant check below
	// instead of the library's zero-leeway default validation.
	verifiedToken, err := jwt.Parse(signedJWS, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, ErrInvalidProof
		}
		return devicePublicKey, nil
	}, jwt.WithoutClaimsValidation())
	if err != nil || !verifiedToken.Valid {
		return nil, ErrInvalidProof
	}

	if claims.InviteID != expectedInviteID {
		return nil, ErrInvalidProof
	}

	skew := time.Duration(joinProofSkewSec) * time.Second
	if claims.IssuedAt == 0 {
		return nil, ErrInvalidProof
	}
	issuedAt := time.Unix(claims.IssuedAt, 0)
	if issuedAt.After(now.Add(skew)) {
		return nil, ErrInvalidProof
	}
	ttl := time.Duration(joinProofTTLSec) * time.Second
	if now.After(issuedAt.Add(ttl).Add(skew)) {
		return nil, ErrInvalidProof
	}

	return &claims, nil
}
