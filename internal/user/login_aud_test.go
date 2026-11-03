package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

type deviceRepo struct {
	*mockUserRepository
	device *Device
}

func (d *deviceRepo) GetDevice(string) (*Device, error) { return d.device, nil }

func signedLogin(t *testing.T, aud any) (UserEndpoints, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	pk := base64.StdEncoding.EncodeToString(pub)
	ue := UserEndpoints{
		userRepository: &deviceRepo{newMockUserRepository(), &Device{DevicePublicKey: pk, UserPublicKey: pk}},
		challenges:     newChallengeStore(),
	}
	ue.challenges.store("c1", challengeInfo{publicKey: pk, expiresAt: time.Now().Add(time.Minute)})
	claims := jwt.MapClaims{"publicKey": pk, "challenge": "c1", "iat": time.Now().Unix()}
	if aud != nil {
		claims["aud"] = aud
	}
	jws, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(priv)
	assert.NoError(t, err)
	return ue, jws
}

func TestVerifyUserAuthJWS_ShouldRejectMismatchedAud(t *testing.T) {
	// given
	ue, jws := signedLogin(t, "https://evil.example")

	// when
	_, err := ue.verifyUserAuthJWS(jws, 300, "https://space.prappser.app")

	// then
	assert.ErrorIs(t, err, ErrAudienceMismatch)
}

func TestVerifyUserAuthJWS_ShouldRejectNonStringAud(t *testing.T) {
	// given
	ue, jws := signedLogin(t, 42)

	// when
	_, err := ue.verifyUserAuthJWS(jws, 300, "https://space.prappser.app")

	// then
	assert.ErrorIs(t, err, ErrAudienceMismatch)
}

func TestVerifyUserAuthJWS_ShouldRejectAudWhenOwnURLUnknown(t *testing.T) {
	// given
	ue, jws := signedLogin(t, "https://space.prappser.app")

	// when
	_, err := ue.verifyUserAuthJWS(jws, 300, "")

	// then
	assert.ErrorIs(t, err, ErrAudienceMismatch)
}

func TestVerifyUserAuthJWS_ShouldAcceptMatchingAud(t *testing.T) {
	// given
	ue, jws := signedLogin(t, "HTTPS://Space.Prappser.app:443/")

	// when
	_, err := ue.verifyUserAuthJWS(jws, 300, "https://space.prappser.app")

	// then
	assert.NoError(t, err)
}

func TestVerifyUserAuthJWS_ShouldAcceptMissingAud(t *testing.T) {
	// given
	ue, jws := signedLogin(t, nil)

	// when
	_, err := ue.verifyUserAuthJWS(jws, 300, "https://space.prappser.app")

	// then
	assert.NoError(t, err)
}

func TestUserAuth_ShouldReturn401OnAudMismatch(t *testing.T) {
	// given
	ue, jws := signedLogin(t, "https://evil.example")
	ue.config = Config{ChallengeTTLSec: 300, ExternalURL: "https://space.prappser.app"}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("Authorization", "Bearer "+jws)

	// when
	ue.UserAuth(ctx)

	// then
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}

func TestNormalizeSpaceURL_ShouldNormalize(t *testing.T) {
	cases := map[string]string{
		"https://space.prappser.app:443":     "https://space.prappser.app",
		"http://localhost:80":                "http://localhost",
		"http://localhost:4545/":             "http://localhost:4545",
		"HTTPS://Space.Prappser.APP/a/b?q=1": "https://space.prappser.app",
		"https://[::1]:8443/x#f":             "https://[::1]:8443",
		"https://[::1]:443":                  "https://[::1]",
	}
	for in, want := range cases {
		// when
		got, err := normalizeSpaceURL(in)

		// then
		assert.NoError(t, err, in)
		assert.Equal(t, want, got, in)
	}
}

func TestNormalizeSpaceURL_ShouldRejectInvalid(t *testing.T) {
	for _, in := range []string{"", "space.prappser.app", "ftp://x.y", "https://", "://bad", "https://space.prappser.app@evil.example"} {
		// when
		_, err := normalizeSpaceURL(in)

		// then
		assert.Error(t, err, in)
	}
}

func TestExpectedSpaceURL_ShouldPreferExternalURL(t *testing.T) {
	// given
	ue := UserEndpoints{config: Config{ExternalURL: "https://Space.Prappser.app/"}}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetHost("other.example")

	// then
	assert.Equal(t, "https://space.prappser.app", ue.expectedSpaceURL(ctx))
}

func TestExpectedSpaceURL_ShouldUseHostAndForwardedProtoIgnoringForwardedHost(t *testing.T) {
	// given
	ue := UserEndpoints{config: Config{TrustProxyHeaders: true}}
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetHost("space.prappser.app")
	ctx.Request.Header.Set("X-Forwarded-Proto", "https, http")
	ctx.Request.Header.Set("X-Forwarded-Host", "evil.example")

	// then
	assert.Equal(t, "https://space.prappser.app", ue.expectedSpaceURL(ctx))
}
