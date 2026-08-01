package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// buildAssertionJWS signs an identity-assertion payload with signKey using
// the given signing method (EdDSA for valid assertions, something else to
// exercise the alg check). An empty string arg omits that claim entirely, to
// exercise the required-claim checks.
func buildAssertionJWS(t *testing.T, method jwt.SigningMethod, signKey interface{}, iss, userID, aud, username, dpk string, iat, exp int64) string {
	t.Helper()
	claims := jwt.MapClaims{"iat": iat, "exp": exp}
	if iss != "" {
		claims["iss"] = iss
	}
	if userID != "" {
		claims["user_id"] = userID
	}
	if aud != "" {
		claims["aud"] = aud
	}
	if username != "" {
		claims["username"] = username
	}
	if dpk != "" {
		claims["dpk"] = dpk
	}
	token := jwt.NewWithClaims(method, claims)
	signed, err := token.SignedString(signKey)
	assert.NoError(t, err)
	return signed
}

func TestMintAssertion_VerifyAssertion_ShouldRoundtrip(t *testing.T) {
	// given
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	issB64 := base64.StdEncoding.EncodeToString(pub)
	now := time.Now()

	// when
	signed, exp, err := mintAssertion(priv, issB64, "user-1", "aud-key", "alice", "device-1", now)
	assert.NoError(t, err)
	claims, verifyErr := VerifyAssertion(signed, "aud-key", "device-1", now)

	// then
	assert.Equal(t, now.Unix()+assertionTTLSec, exp)
	assert.NoError(t, verifyErr)
	assert.Equal(t, issB64, claims.Issuer)
	assert.Equal(t, "user-1", claims.UserID)
	assert.Equal(t, "aud-key", claims.Audience)
	assert.Equal(t, "alice", claims.Username)
	assert.Equal(t, "device-1", claims.DevicePublicKey)
	assert.Equal(t, exp, claims.ExpiresAt)
}

func TestVerifyAssertion(t *testing.T) {
	issuerPub, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	issuerB64 := base64.StdEncoding.EncodeToString(issuerPub)

	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	now := time.Now()
	nowUnix := now.Unix()

	const (
		userIDB64   = "user-account-key"
		audienceB64 = "relying-space-key"
		dpkB64      = "device-key"
	)

	tests := []struct {
		name    string
		build   func() string
		wantErr bool
	}{
		{
			name: "happy path",
			build: func() string {
				return buildAssertionJWS(t, jwt.SigningMethodEdDSA, issuerPriv, issuerB64, userIDB64, audienceB64, "alice", dpkB64, nowUnix, nowUnix+120)
			},
			wantErr: false,
		},
		{
			// exp is technically already in the past, but well within the
			// 30s clock-skew allowance between independently-run spaces.
			name: "accepted within skew despite exp already passed",
			build: func() string {
				return buildAssertionJWS(t, jwt.SigningMethodEdDSA, issuerPriv, issuerB64, userIDB64, audienceB64, "alice", dpkB64, nowUnix-140, nowUnix-20)
			},
			wantErr: false,
		},
		{
			name: "expired beyond skew",
			build: func() string {
				return buildAssertionJWS(t, jwt.SigningMethodEdDSA, issuerPriv, issuerB64, userIDB64, audienceB64, "alice", dpkB64, nowUnix-1000, nowUnix-400)
			},
			wantErr: true,
		},
		{
			// exp-iat = 600, well over assertionMaxTTLSec (120).
			name: "exp-iat exceeds max ttl",
			build: func() string {
				return buildAssertionJWS(t, jwt.SigningMethodEdDSA, issuerPriv, issuerB64, userIDB64, audienceB64, "alice", dpkB64, nowUnix, nowUnix+600)
			},
			wantErr: true,
		},
		{
			// [G5] iat implausibly in the future - without this check a
			// self-minted token could be minted far-future and never expire.
			name: "future iat rejected",
			build: func() string {
				return buildAssertionJWS(t, jwt.SigningMethodEdDSA, issuerPriv, issuerB64, userIDB64, audienceB64, "alice", dpkB64, nowUnix+1000, nowUnix+1100)
			},
			wantErr: true,
		},
		{
			name: "wrong aud",
			build: func() string {
				return buildAssertionJWS(t, jwt.SigningMethodEdDSA, issuerPriv, issuerB64, userIDB64, "wrong-aud", "alice", dpkB64, nowUnix, nowUnix+120)
			},
			wantErr: true,
		},
		{
			name: "wrong dpk",
			build: func() string {
				return buildAssertionJWS(t, jwt.SigningMethodEdDSA, issuerPriv, issuerB64, userIDB64, audienceB64, "alice", "wrong-dpk", nowUnix, nowUnix+120)
			},
			wantErr: true,
		},
		{
			// Signed by a different key than the one named in iss.
			name: "bad signature",
			build: func() string {
				return buildAssertionJWS(t, jwt.SigningMethodEdDSA, otherPriv, issuerB64, userIDB64, audienceB64, "alice", dpkB64, nowUnix, nowUnix+120)
			},
			wantErr: true,
		},
		{
			name: "alg none rejected",
			build: func() string {
				return buildAssertionJWS(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, issuerB64, userIDB64, audienceB64, "alice", dpkB64, nowUnix, nowUnix+120)
			},
			wantErr: true,
		},
		{
			// HS256 alg-confusion attempt: even if an attacker could guess
			// or obtain issuerB64 as an HMAC key, the EdDSA-only keyfunc
			// rejects the method before ever comparing the signature.
			name: "HS256 rejected",
			build: func() string {
				return buildAssertionJWS(t, jwt.SigningMethodHS256, []byte("secret"), issuerB64, userIDB64, audienceB64, "alice", dpkB64, nowUnix, nowUnix+120)
			},
			wantErr: true,
		},
		{
			name: "iss wrong length",
			build: func() string {
				return buildAssertionJWS(t, jwt.SigningMethodEdDSA, issuerPriv, "not-a-32-byte-key", userIDB64, audienceB64, "alice", dpkB64, nowUnix, nowUnix+120)
			},
			wantErr: true,
		},
		{
			name: "missing iss",
			build: func() string {
				return buildAssertionJWS(t, jwt.SigningMethodEdDSA, issuerPriv, "", userIDB64, audienceB64, "alice", dpkB64, nowUnix, nowUnix+120)
			},
			wantErr: true,
		},
		{
			name: "missing user_id",
			build: func() string {
				return buildAssertionJWS(t, jwt.SigningMethodEdDSA, issuerPriv, issuerB64, "", audienceB64, "alice", dpkB64, nowUnix, nowUnix+120)
			},
			wantErr: true,
		},
		{
			name: "missing aud",
			build: func() string {
				return buildAssertionJWS(t, jwt.SigningMethodEdDSA, issuerPriv, issuerB64, userIDB64, "", "alice", dpkB64, nowUnix, nowUnix+120)
			},
			wantErr: true,
		},
		{
			name: "missing username",
			build: func() string {
				return buildAssertionJWS(t, jwt.SigningMethodEdDSA, issuerPriv, issuerB64, userIDB64, audienceB64, "", dpkB64, nowUnix, nowUnix+120)
			},
			wantErr: true,
		},
		{
			name: "missing dpk",
			build: func() string {
				return buildAssertionJWS(t, jwt.SigningMethodEdDSA, issuerPriv, issuerB64, userIDB64, audienceB64, "alice", "", nowUnix, nowUnix+120)
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jws := tc.build()
			claims, err := VerifyAssertion(jws, audienceB64, dpkB64, now)

			if tc.wantErr {
				assert.ErrorIs(t, err, ErrInvalidAssertion)
				assert.Nil(t, claims)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, claims)
			}
		})
	}
}
