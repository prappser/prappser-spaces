package user

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Cross-space identity assertions (#111): a space that vouches for an
// account (an "issuer") mints a short-lived, narrowly-scoped JWT that lets a
// different space (the "relying" space) learn who is joining and pin
// provenance accordingly (see UserRepository.UpdateUserIssuer). Verification
// mirrors verifyDelegation in device_endpoints.go: the signature is checked
// directly against the iss claim's own key - there is never an outbound
// request to the issuing space to confirm it (D2), which is what keeps this
// mechanism free of any SSRF surface.
const (
	// assertionTTLSec is how long a freshly minted assertion is valid for.
	assertionTTLSec = 120
	// assertionMaxTTLSec bounds exp-iat independent of the token's own exp
	// claim, the same way maxDelegationTTLSec does for delegations - a
	// mis-issued or tampered assertion can't stay usable indefinitely just
	// by carrying a far-future exp.
	assertionMaxTTLSec = 120
	// assertionSkewSec is the only clock-drift tolerance between two
	// independently-run spaces (the issuer that minted the assertion and the
	// relying space verifying it) - not a general leniency window.
	assertionSkewSec = 30
)

// ErrInvalidAssertion is the single error VerifyAssertion ever returns,
// regardless of which check failed. Collapsing every failure mode to one
// generic error is deliberate anti-enumeration: a caller always responds
// with the same 401 "invalid assertion" and never leaks which specific
// check tripped.
var ErrInvalidAssertion = errors.New("invalid assertion")

// assertionClaims are the claims of an identity assertion JWT. The wire
// format is frozen: iss, user_id, aud, username, dpk, iat, exp.
type assertionClaims struct {
	Issuer          string `json:"iss"`
	UserID          string `json:"user_id"`
	Audience        string `json:"aud"`
	Username        string `json:"username"`
	DevicePublicKey string `json:"dpk"`
	IssuedAt        int64  `json:"iat"`
	ExpiresAt       int64  `json:"exp"`
}

// mintAssertion signs a new identity assertion with priv. iss is the
// minting space's own public key - or, for a self-anchored account (D9), the
// account's own public key, signed with the account's key instead of a
// space's. The signature over iss is what makes the claim credible; exp is
// always now+assertionTTLSec.
func mintAssertion(priv ed25519.PrivateKey, iss, userID, audience, username, dpk string, now time.Time) (string, int64, error) {
	iat := now.Unix()
	exp := iat + assertionTTLSec

	claims := jwt.MapClaims{
		"iss":      iss,
		"user_id":  userID,
		"aud":      audience,
		"username": username,
		"dpk":      dpk,
		"iat":      iat,
		"exp":      exp,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(priv)
	if err != nil {
		return "", 0, err
	}
	return signed, exp, nil
}

// VerifyAssertion validates a signed identity assertion JWT and returns its
// claims. expectedAudience must equal the relying space's own public key;
// expectedDevicePublicKey must equal the device presenting the assertion
// (the PoP binding, D3). Every failure collapses to ErrInvalidAssertion (see
// its doc comment for why), so callers never need to distinguish which
// specific check failed - just surface a generic 401.
//
// Verify order (mirrors verifyDelegation in device_endpoints.go):
//  1. parse claims unverified, reject if any required claim is empty
//  2. iss decodes to exactly an Ed25519 public key's worth of bytes
//  3. signature verifies against iss itself, requiring EdDSA (D2: no
//     outbound request to the issuer - the iss claim IS the key)
//  4. aud matches expectedAudience
//  5. dpk matches expectedDevicePublicKey
//  6. exp is set and still valid within the clock-skew allowance
//  7. the token's total lifetime (exp-iat) is within assertionMaxTTLSec
//  8. iat is set and not implausibly in the future (skew-tolerant)
func VerifyAssertion(signedJWT, expectedAudience, expectedDevicePublicKey string, now time.Time) (*assertionClaims, error) {
	token, _, err := jwt.NewParser().ParseUnverified(signedJWT, jwt.MapClaims{})
	if err != nil {
		return nil, ErrInvalidAssertion
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidAssertion
	}

	var claims assertionClaims
	if iss, ok := mapClaims["iss"].(string); ok {
		claims.Issuer = iss
	}
	if userID, ok := mapClaims["user_id"].(string); ok {
		claims.UserID = userID
	}
	if aud, ok := mapClaims["aud"].(string); ok {
		claims.Audience = aud
	}
	if username, ok := mapClaims["username"].(string); ok {
		claims.Username = username
	}
	if dpk, ok := mapClaims["dpk"].(string); ok {
		claims.DevicePublicKey = dpk
	}
	if iat, ok := mapClaims["iat"].(float64); ok {
		claims.IssuedAt = int64(iat)
	}
	if exp, ok := mapClaims["exp"].(float64); ok {
		claims.ExpiresAt = int64(exp)
	}

	if claims.Issuer == "" || claims.UserID == "" || claims.Audience == "" || claims.Username == "" || claims.DevicePublicKey == "" {
		return nil, ErrInvalidAssertion
	}

	issuerKeyBytes, err := base64.StdEncoding.DecodeString(claims.Issuer)
	if err != nil || len(issuerKeyBytes) != ed25519.PublicKeySize {
		return nil, ErrInvalidAssertion
	}
	issuerPublicKey := ed25519.PublicKey(issuerKeyBytes)

	// WithoutClaimsValidation: exp/iat get their own skew-tolerant checks
	// below instead of the library's zero-leeway default validation.
	verifiedToken, err := jwt.Parse(signedJWT, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, ErrInvalidAssertion
		}
		return issuerPublicKey, nil
	}, jwt.WithoutClaimsValidation())
	if err != nil || !verifiedToken.Valid {
		return nil, ErrInvalidAssertion
	}

	if claims.Audience != expectedAudience {
		return nil, ErrInvalidAssertion
	}
	if claims.DevicePublicKey != expectedDevicePublicKey {
		return nil, ErrInvalidAssertion
	}

	skew := time.Duration(assertionSkewSec) * time.Second
	if claims.ExpiresAt == 0 || !now.Before(time.Unix(claims.ExpiresAt, 0).Add(skew)) {
		return nil, ErrInvalidAssertion
	}
	if claims.ExpiresAt-claims.IssuedAt > assertionMaxTTLSec {
		return nil, ErrInvalidAssertion
	}
	if claims.IssuedAt == 0 || claims.IssuedAt > now.Add(skew).Unix() {
		return nil, ErrInvalidAssertion
	}

	return &claims, nil
}
