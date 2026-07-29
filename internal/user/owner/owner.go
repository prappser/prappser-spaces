package owner

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/prappser/prappser-spaces/internal/keys"
)

// jweSaltHeaderParam is the custom JWE protected-header field carrying the
// per-message Argon2id salt used to derive the direct-encryption key.
const jweSaltHeaderParam = "salt"

// JWE/JWS claims for owner registration
type RegisterJWEClaims struct {
	JWS string `json:"jws"`
}

type RegisterJWSClaims struct {
	PublicKey string `json:"publicKey"`
	Username  string `json:"username"`
	IssuedAt  int64  `json:"iat"`
}

var timeNowFunc = time.Now

// ExtractJWEFromAuthorizationHeader extracts JWE token from Authorization header
func ExtractJWEFromAuthorizationHeader(authHeader string) (string, error) {
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", fmt.Errorf("invalid Authorization header format")
	}
	return parts[1], nil
}

// DecryptJWE decrypts the JWE using a key derived from the plaintext master
// password and the salt carried in the JWE's protected header.
func DecryptJWE(encryptedJWE string, masterPassword string) (*RegisterJWEClaims, error) {
	msg, err := jwe.Parse([]byte(encryptedJWE))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWE: %w", err)
	}

	var saltB64 string
	if err := msg.ProtectedHeaders().Get(jweSaltHeaderParam, &saltB64); err != nil {
		return nil, fmt.Errorf("missing salt header: %w", err)
	}

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, fmt.Errorf("invalid salt encoding: %w", err)
	}
	if len(salt) != keys.SaltSize {
		return nil, fmt.Errorf("invalid salt length: expected %d, got %d", keys.SaltSize, len(salt))
	}

	aesKey := keys.DeriveKey(masterPassword, salt)

	decrypted, err := jwe.Decrypt([]byte(encryptedJWE), jwe.WithKey(jwa.DIRECT(), aesKey))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt JWE: %v", err)
	}
	var registerJWEClaims RegisterJWEClaims
	if err := json.Unmarshal(decrypted, &registerJWEClaims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWE claims: %w", err)
	}
	return &registerJWEClaims, nil
}

// VerifyJWS verifies the JWT using the Ed25519 public key from its claims
func VerifyJWS(signedJWT string, registrationTokenTTLSec int32) (*RegisterJWSClaims, error) {
	// Parse JWT without verification first to get claims
	token, _, err := jwt.NewParser().ParseUnverified(signedJWT, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid JWT claims format")
	}

	var registerJWSClaims RegisterJWSClaims
	if pk, ok := mapClaims["publicKey"].(string); ok {
		registerJWSClaims.PublicKey = pk
	}
	if un, ok := mapClaims["username"].(string); ok {
		registerJWSClaims.Username = un
	}
	if iat, ok := mapClaims["iat"].(float64); ok {
		registerJWSClaims.IssuedAt = int64(iat)
	}

	// Check if the JWT is expired
	var timeNow = timeNowFunc()
	var issuedAtTime = time.Unix(registerJWSClaims.IssuedAt, 0)
	if issuedAtTime.Add(time.Duration(registrationTokenTTLSec) * time.Second).Before(timeNow) {
		return nil, fmt.Errorf("JWT has expired")
	}

	// Decode the Ed25519 public key from base64
	publicKeyBytes, err := base64.StdEncoding.DecodeString(registerJWSClaims.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(publicKeyBytes))
	}

	ed25519PublicKey := ed25519.PublicKey(publicKeyBytes)

	// Verify the JWT signature using Ed25519 public key
	verifiedToken, err := jwt.Parse(signedJWT, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return ed25519PublicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to verify JWT: %w", err)
	}

	if !verifiedToken.Valid {
		return nil, fmt.Errorf("JWT signature verification failed")
	}

	return &registerJWSClaims, nil
}

// SetTimeNowFunc allows injection of time function for testing
func SetTimeNowFunc(fn func() time.Time) {
	timeNowFunc = fn
}
