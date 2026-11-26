package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestAgentService_ValidateAccessToken_ShouldRejectWrongTyp(t *testing.T) {
	// given
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	svc := &AgentService{publicKey: pub, issuer: "https://space.test", audience: "https://space.test/mcp"}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.RegisteredClaims{
		Issuer: svc.issuer, Subject: "agent_x", Audience: jwt.ClaimStrings{svc.audience},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	tok.Header["typ"] = "JWT"
	signed, err := tok.SignedString(priv)
	assert.NoError(t, err)

	// when
	_, err = svc.ValidateAccessToken(signed)

	// then
	assert.ErrorContains(t, err, "not an access token")
}
