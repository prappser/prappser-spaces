//go:build integration

package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

const agentTestURL = "https://space.test"

func newAgentTestService(t *testing.T, db *sql.DB, userKey string) (*AgentService, *UserService) {
	t.Helper()
	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at, issuer) VALUES ($1,$2,$3,$4,$1) ON CONFLICT DO NOTHING",
		userKey, userKey, "user", time.Now().Unix(),
	); err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	repo := NewUserRepository(db)
	// clear leftovers from earlier runs so the live-agent count starts at zero
	if _, err := db.Exec("DELETE FROM user_devices WHERE user_public_key = $1 AND kind = 'agent'", userKey); err != nil {
		t.Fatalf("Failed to clean agents: %v", err)
	}
	us := NewUserService(repo, nil, Config{JWTExpirationHours: 24}, priv, pub)
	return NewAgentService(db, repo, priv, pub, agentTestURL), us
}

func TestAgentService_IssueTokens_ShouldCreateAgentDeviceAndTokens_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-issue-user")

	// when
	tokens, err := svc.IssueTokens("test-agent-issue-user", "my agent")

	// then
	assert.NoError(t, err)
	device, err := NewUserRepository(db).GetDevice(tokens.DevicePublicKey)
	assert.NoError(t, err)
	assert.Equal(t, DeviceKindAgent, device.Kind)
	assert.Nil(t, device.LastSeenAt)
	var stored string
	assert.NoError(t, db.QueryRow("SELECT token_hash FROM agent_refresh_tokens WHERE device_public_key = $1", tokens.DevicePublicKey).Scan(&stored))
	assert.NotEqual(t, tokens.RefreshToken, stored)
	u, err := svc.ValidateAccessToken(tokens.AccessToken)
	assert.NoError(t, err)
	assert.Equal(t, "test-agent-issue-user", u.PublicKey)
	assert.Equal(t, tokens.DevicePublicKey, u.DevicePublicKey)
}

func TestAgentService_IssueTokens_ShouldEnforceLimitOfFive_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-limit-user")
	var first *AgentTokens
	for i := 0; i < maxLiveAgentsPerAccount; i++ {
		tk, err := svc.IssueTokens("test-agent-limit-user", "")
		assert.NoError(t, err)
		if first == nil {
			first = tk
		}
	}

	// when
	_, errOver := svc.IssueTokens("test-agent-limit-user", "")
	assert.NoError(t, NewUserRepository(db).RevokeDevice(first.DevicePublicKey, time.Now().Unix()))
	_, errAfter := svc.IssueTokens("test-agent-limit-user", "")

	// then
	assert.ErrorIs(t, errOver, ErrAgentLimit)
	assert.NoError(t, errAfter)
}

func TestAgentService_IssueTokens_ExpiredAgentsShouldNotCountTowardLimit_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-expcap-user")
	for i := 0; i < maxLiveAgentsPerAccount; i++ {
		_, err := svc.IssueTokens("test-agent-expcap-user", "")
		assert.NoError(t, err)
	}
	_, err := db.Exec(
		"UPDATE agent_refresh_tokens SET expires_at = $1 WHERE device_public_key IN (SELECT device_public_key FROM user_devices WHERE user_public_key = $2)",
		time.Now().Unix()-10, "test-agent-expcap-user",
	)
	assert.NoError(t, err)

	// when
	_, err = svc.IssueTokens("test-agent-expcap-user", "")

	// then
	assert.NoError(t, err)
}

func TestAgentService_Refresh_ShouldRotateToken_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-rotate-user")
	tokens, err := svc.IssueTokens("test-agent-rotate-user", "")
	assert.NoError(t, err)

	// when
	next, err := svc.Refresh(tokens.RefreshToken)

	// then
	assert.NoError(t, err)
	assert.Equal(t, tokens.DevicePublicKey, next.DevicePublicKey)
	assert.NotEqual(t, tokens.RefreshToken, next.RefreshToken)
	_, err = svc.ValidateAccessToken(next.AccessToken)
	assert.NoError(t, err)
	_, err = svc.Refresh(next.RefreshToken)
	assert.NoError(t, err)
}

func TestAgentService_Refresh_PreviousToken_ShouldRevokeDevice_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-reuse-user")
	tokens, err := svc.IssueTokens("test-agent-reuse-user", "")
	assert.NoError(t, err)
	next, err := svc.Refresh(tokens.RefreshToken)
	assert.NoError(t, err)

	// when
	_, errOld := svc.Refresh(tokens.RefreshToken)
	_, errCurrent := svc.Refresh(next.RefreshToken)

	// then
	assert.ErrorIs(t, errOld, ErrInvalidRefreshToken)
	assert.ErrorIs(t, errCurrent, ErrInvalidRefreshToken)
	device, err := NewUserRepository(db).GetDevice(tokens.DevicePublicKey)
	assert.NoError(t, err)
	assert.NotNil(t, device.RevokedAt)
	var n int
	assert.NoError(t, db.QueryRow("SELECT COUNT(*) FROM agent_refresh_tokens WHERE device_public_key = $1", tokens.DevicePublicKey).Scan(&n))
	assert.Equal(t, 0, n)
}

func TestAgentService_Refresh_Expired_ShouldFail_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-expired-user")
	tokens, err := svc.IssueTokens("test-agent-expired-user", "")
	assert.NoError(t, err)
	_, err = db.Exec("UPDATE agent_refresh_tokens SET expires_at = $1 WHERE device_public_key = $2", time.Now().Unix()-10, tokens.DevicePublicKey)
	assert.NoError(t, err)

	// when
	_, err = svc.Refresh(tokens.RefreshToken)

	// then
	assert.ErrorIs(t, err, ErrInvalidRefreshToken)
	device, err := NewUserRepository(db).GetDevice(tokens.DevicePublicKey)
	assert.NoError(t, err)
	assert.Nil(t, device.RevokedAt)
}

func TestAgentService_Refresh_RevokedDevice_ShouldFail_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-revrefresh-user")
	tokens, err := svc.IssueTokens("test-agent-revrefresh-user", "")
	assert.NoError(t, err)
	_, err = db.Exec("UPDATE user_devices SET revoked_at = $1 WHERE device_public_key = $2", time.Now().Unix(), tokens.DevicePublicKey)
	assert.NoError(t, err)

	// when
	_, err = svc.Refresh(tokens.RefreshToken)

	// then
	assert.ErrorIs(t, err, ErrInvalidRefreshToken)
}

func TestAgentService_ValidateAccessToken_ShouldAcceptValid_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-valid-user")
	tokens, err := svc.IssueTokens("test-agent-valid-user", "")
	assert.NoError(t, err)

	// when
	u, err := svc.ValidateAccessToken(tokens.AccessToken)

	// then
	assert.NoError(t, err)
	assert.Equal(t, "test-agent-valid-user", u.PublicKey)
	device, err := NewUserRepository(db).GetDevice(tokens.DevicePublicKey)
	assert.NoError(t, err)
	assert.Nil(t, device.LastSeenAt)
}

func TestAgentService_ValidateAccessToken_ShouldRejectWrongAudience_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-aud-user")
	tokens, err := svc.IssueTokens("test-agent-aud-user", "")
	assert.NoError(t, err)
	other := *svc
	other.audience = "https://other.test/mcp"

	// when
	_, err = other.ValidateAccessToken(tokens.AccessToken)

	// then
	assert.Error(t, err)
}

func TestAgentService_ValidateAccessToken_ShouldRejectWrongTyp_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-typ-user")
	tokens, err := svc.IssueTokens("test-agent-typ-user", "")
	assert.NoError(t, err)
	claims := jwt.RegisteredClaims{
		Issuer:    svc.issuer,
		Subject:   tokens.DevicePublicKey,
		Audience:  jwt.ClaimStrings{svc.audience},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(svc.privateKey)
	assert.NoError(t, err)

	// when
	_, err = svc.ValidateAccessToken(signed)

	// then
	assert.Error(t, err)
}

func TestAgentService_ValidateAccessToken_ShouldRejectRevokedDevice_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-revoked-user")
	tokens, err := svc.IssueTokens("test-agent-revoked-user", "")
	assert.NoError(t, err)
	assert.NoError(t, NewUserRepository(db).RevokeDevice(tokens.DevicePublicKey, time.Now().Unix()))

	// when
	_, err = svc.ValidateAccessToken(tokens.AccessToken)

	// then
	assert.Error(t, err)
}

func TestAgentService_ValidateAccessToken_ShouldRejectHumanDevice_Integration(t *testing.T) {
	// given: a correctly signed access token whose subject is a human device
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-human-user")
	assert.NoError(t, NewUserRepository(db).EnsureDevice("test-agent-human-user", "test-agent-human-user", nil, time.Now().Unix()))
	signed, _, err := svc.mintAccessToken("test-agent-human-user")
	assert.NoError(t, err)

	// when
	_, err = svc.ValidateAccessToken(signed)

	// then
	assert.Error(t, err)
}

func TestAgentService_ValidateAccessToken_ShouldRejectHumanSessionJWT_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, us := newAgentTestService(t, db, "test-agent-session-user")
	assert.NoError(t, NewUserRepository(db).EnsureDevice("test-agent-session-user", "test-agent-session-user", nil, time.Now().Unix()))
	signed, _, err := us.GenerateJWT(&User{PublicKey: "test-agent-session-user", Role: "user"}, "test-agent-session-user")
	assert.NoError(t, err)

	// when
	_, err = svc.ValidateAccessToken(signed)

	// then
	assert.Error(t, err)
}

func TestAgentService_ValidateAccessToken_TrailingSlashExternalURL_ShouldUseCleanAudience_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	base, _ := newAgentTestService(t, db, "test-agent-slash-user")
	svc := NewAgentService(db, base.userRepository, base.privateKey, base.publicKey, agentTestURL+"/")
	tokens, err := svc.IssueTokens("test-agent-slash-user", "")
	assert.NoError(t, err)

	// when
	parsed, _, err := jwt.NewParser().ParseUnverified(tokens.AccessToken, jwt.MapClaims{})
	_, validateErr := svc.ValidateAccessToken(tokens.AccessToken)

	// then
	assert.NoError(t, err)
	aud, _ := parsed.Claims.GetAudience()
	assert.Equal(t, jwt.ClaimStrings{agentTestURL + "/mcp"}, aud)
	assert.NoError(t, validateErr)
}
