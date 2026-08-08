package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"math"
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

// buildRebindJWS signs a rebind payload with signKey using the given signing
// method (EdDSA for valid rebinds, something else to exercise the alg
// check). An empty string arg omits that claim entirely, to exercise the
// required-claim checks - mirrors buildAssertionJWS above.
func buildRebindJWS(t *testing.T, method jwt.SigningMethod, signKey interface{}, iss, userID, aud, newIssuer, jti string, iat, exp int64) string {
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
	if newIssuer != "" {
		claims["new_issuer"] = newIssuer
	}
	if jti != "" {
		claims["jti"] = jti
	}
	token := jwt.NewWithClaims(method, claims)
	signed, err := token.SignedString(signKey)
	assert.NoError(t, err)
	return signed
}

func TestVerifyRebind(t *testing.T) {
	accountPub, accountPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	accountB64 := base64.StdEncoding.EncodeToString(accountPub)

	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	now := time.Now()
	nowUnix := now.Unix()

	const (
		audienceB64  = "relying-space-key"
		newIssuerB64 = "new-issuer-key"
	)

	store := newJTIStore()

	tests := []struct {
		name    string
		build   func() string
		wantErr bool
	}{
		{
			name: "happy path",
			build: func() string {
				return buildRebindJWS(t, jwt.SigningMethodEdDSA, accountPriv, accountB64, accountB64, audienceB64, newIssuerB64, "jti-1", nowUnix, nowUnix+120)
			},
			wantErr: false,
		},
		{
			// Signed by a different key than the one named in iss.
			name: "bad signature",
			build: func() string {
				return buildRebindJWS(t, jwt.SigningMethodEdDSA, otherPriv, accountB64, accountB64, audienceB64, newIssuerB64, "jti-2", nowUnix, nowUnix+120)
			},
			wantErr: true,
		},
		{
			// The whole point of the self-sign rule: iss must equal user_id.
			name: "iss != user_id",
			build: func() string {
				return buildRebindJWS(t, jwt.SigningMethodEdDSA, accountPriv, accountB64, "a-different-account", audienceB64, newIssuerB64, "jti-3", nowUnix, nowUnix+120)
			},
			wantErr: true,
		},
		{
			name: "wrong aud",
			build: func() string {
				return buildRebindJWS(t, jwt.SigningMethodEdDSA, accountPriv, accountB64, accountB64, "wrong-aud", newIssuerB64, "jti-4", nowUnix, nowUnix+120)
			},
			wantErr: true,
		},
		{
			name: "expired beyond skew",
			build: func() string {
				return buildRebindJWS(t, jwt.SigningMethodEdDSA, accountPriv, accountB64, accountB64, audienceB64, newIssuerB64, "jti-5", nowUnix-1000, nowUnix-400)
			},
			wantErr: true,
		},
		{
			// [G5] iat implausibly in the future.
			name: "future iat rejected",
			build: func() string {
				return buildRebindJWS(t, jwt.SigningMethodEdDSA, accountPriv, accountB64, accountB64, audienceB64, newIssuerB64, "jti-6", nowUnix+1000, nowUnix+1100)
			},
			wantErr: true,
		},
		{
			// Extreme negative iat must not int64-overflow the exp-iat
			// subtraction into a false-negative TTL check.
			name: "iat extreme negative rejected",
			build: func() string {
				return buildRebindJWS(t, jwt.SigningMethodEdDSA, accountPriv, accountB64, accountB64, audienceB64, newIssuerB64, "jti-overflow", math.MinInt64, nowUnix+120)
			},
			wantErr: true,
		},
		{
			name: "alg none rejected",
			build: func() string {
				return buildRebindJWS(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, accountB64, accountB64, audienceB64, newIssuerB64, "jti-none", nowUnix, nowUnix+120)
			},
			wantErr: true,
		},
		{
			// HS256 alg-confusion attempt: even if an attacker could guess
			// or obtain accountB64 as an HMAC key, the EdDSA-only keyfunc
			// rejects the method before ever comparing the signature.
			name: "HS256 rejected",
			build: func() string {
				return buildRebindJWS(t, jwt.SigningMethodHS256, []byte("secret"), accountB64, accountB64, audienceB64, newIssuerB64, "jti-hs256", nowUnix, nowUnix+120)
			},
			wantErr: true,
		},
		{
			name: "iss wrong length",
			build: func() string {
				return buildRebindJWS(t, jwt.SigningMethodEdDSA, accountPriv, "not-a-32-byte-key", "not-a-32-byte-key", audienceB64, newIssuerB64, "jti-badlen", nowUnix, nowUnix+120)
			},
			wantErr: true,
		},
		{
			name: "missing jti",
			build: func() string {
				return buildRebindJWS(t, jwt.SigningMethodEdDSA, accountPriv, accountB64, accountB64, audienceB64, newIssuerB64, "", nowUnix, nowUnix+120)
			},
			wantErr: true,
		},
		{
			// Verify the SAME jws twice against the SAME store - the second
			// call must be rejected as a replay.
			name: "replayed jti",
			build: func() string {
				jws := buildRebindJWS(t, jwt.SigningMethodEdDSA, accountPriv, accountB64, accountB64, audienceB64, newIssuerB64, "jti-replay", nowUnix, nowUnix+120)
				_, firstErr := VerifyRebind(jws, audienceB64, accountB64, store, now)
				assert.NoError(t, firstErr)
				return jws
			},
			wantErr: true,
		},
		{
			name: "malformed JWS missing iss",
			build: func() string {
				return buildRebindJWS(t, jwt.SigningMethodEdDSA, accountPriv, "", accountB64, audienceB64, newIssuerB64, "jti-7", nowUnix, nowUnix+120)
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jws := tc.build()
			claims, err := VerifyRebind(jws, audienceB64, accountB64, store, now)

			if tc.wantErr {
				assert.ErrorIs(t, err, ErrInvalidRebind)
				assert.Nil(t, claims)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, claims)
			}
		})
	}
}

// TestVerifyRebind_UserMismatchShouldNotConsumeJTI covers the ordering fix:
// expectedUserID is checked BEFORE markUsed, so presenting a valid JWS under
// the wrong session (e.g. the handler's authenticated-user check) never
// burns its jti - the rightful owner can still redeem the very same JWS
// afterward, within its validity window.
func TestVerifyRebind_UserMismatchShouldNotConsumeJTI(t *testing.T) {
	// given
	accountPub, accountPriv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	accountB64 := base64.StdEncoding.EncodeToString(accountPub)

	now := time.Now()
	nowUnix := now.Unix()
	const audienceB64 = "relying-space-key"

	store := newJTIStore()
	jws := buildRebindJWS(t, jwt.SigningMethodEdDSA, accountPriv, accountB64, accountB64, audienceB64, "new-issuer-key", "jti-shared", nowUnix, nowUnix+120)

	// when - presented while authenticated as a DIFFERENT account: rejected
	_, err = VerifyRebind(jws, audienceB64, "someone-else", store, now)
	assert.ErrorIs(t, err, ErrInvalidRebind)

	// then - the rightful owner can still successfully verify the SAME jws
	// afterward - the mismatch above must not have consumed the jti
	claims, err := VerifyRebind(jws, audienceB64, accountB64, store, now)
	assert.NoError(t, err)
	assert.NotNil(t, claims)
}
