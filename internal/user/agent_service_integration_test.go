//go:build integration

package user

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

const agentTestURL = "https://space.test"

func newAgentTestService(t *testing.T, db *sql.DB, userKey string) (*AgentService, *UserService) {
	t.Helper()
	if _, err := db.Exec(
		"INSERT INTO users (public_key, username, role, created_at) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
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
	ageRotation(t, db, tokens.DevicePublicKey)

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

func ageRotation(t *testing.T, db *sql.DB, device string) {
	t.Helper()
	if _, err := db.Exec("UPDATE agent_refresh_tokens SET rotated_at = $1 WHERE device_public_key = $2", time.Now().Add(-refreshGraceWindow-5*time.Second).Unix(), device); err != nil {
		t.Fatalf("Failed to age rotation: %v", err)
	}
}

func deviceRevoked(t *testing.T, db *sql.DB, device string) bool {
	t.Helper()
	d, err := NewUserRepository(db).GetDevice(device)
	assert.NoError(t, err)
	return d.RevokedAt != nil
}

func TestAgentService_Refresh_PreviousTokenWithinGrace_ShouldReturnSameRefreshToken_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-grace-user")
	tokens, err := svc.IssueTokens("test-agent-grace-user", "")
	assert.NoError(t, err)
	first, err := svc.Refresh(tokens.RefreshToken)
	assert.NoError(t, err)

	// when
	retry, err := svc.Refresh(tokens.RefreshToken)

	// then
	assert.NoError(t, err)
	assert.Equal(t, first.RefreshToken, retry.RefreshToken)
	assert.Equal(t, tokens.DevicePublicKey, retry.DevicePublicKey)
	_, err = svc.ValidateAccessToken(retry.AccessToken)
	assert.NoError(t, err)
	assert.False(t, deviceRevoked(t, db, tokens.DevicePublicKey))
	_, err = svc.Refresh(first.RefreshToken)
	assert.NoError(t, err)
}

func TestAgentService_Refresh_PreviousTokenAfterTwoRotations_ShouldNotGraceOldest_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-tworot-user")
	tokens, err := svc.IssueTokens("test-agent-tworot-user", "")
	assert.NoError(t, err)
	first, err := svc.Refresh(tokens.RefreshToken)
	assert.NoError(t, err)
	second, err := svc.Refresh(first.RefreshToken)
	assert.NoError(t, err)

	// when
	_, errOldest := svc.Refresh(tokens.RefreshToken)
	again, errMiddle := svc.Refresh(first.RefreshToken)

	// then
	assert.ErrorIs(t, errOldest, ErrInvalidRefreshToken)
	assert.NoError(t, errMiddle)
	assert.Equal(t, second.RefreshToken, again.RefreshToken)
}

func TestAgentService_Refresh_PreviousTokenAfterGrace_ShouldRevokeAfterTwoRotations_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-latereuse-user")
	tokens, err := svc.IssueTokens("test-agent-latereuse-user", "")
	assert.NoError(t, err)
	first, err := svc.Refresh(tokens.RefreshToken)
	assert.NoError(t, err)
	_, err = svc.Refresh(first.RefreshToken)
	assert.NoError(t, err)
	ageRotation(t, db, tokens.DevicePublicKey)

	// when
	_, err = svc.Refresh(first.RefreshToken)

	// then
	assert.ErrorIs(t, err, ErrInvalidRefreshToken)
	assert.True(t, deviceRevoked(t, db, tokens.DevicePublicKey))
}

func TestAgentService_Refresh_UnknownToken_ShouldFailWithoutRevoke_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-unknown-user")
	tokens, err := svc.IssueTokens("test-agent-unknown-user", "")
	assert.NoError(t, err)

	// when
	_, err = svc.Refresh("not-a-token")

	// then
	assert.ErrorIs(t, err, ErrInvalidRefreshToken)
	assert.False(t, deviceRevoked(t, db, tokens.DevicePublicKey))
}

func TestAgentService_Refresh_ParallelWithSameToken_ShouldAllSucceedWithOneRotation_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-parallel-user")
	tokens, err := svc.IssueTokens("test-agent-parallel-user", "")
	assert.NoError(t, err)
	const n = 8
	results := make([]*AgentTokens, n)
	errs := make([]error, n)
	var wg sync.WaitGroup

	// when
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = svc.Refresh(tokens.RefreshToken)
		}()
	}
	wg.Wait()

	// then
	for i := 0; i < n; i++ {
		assert.NoError(t, errs[i])
		assert.Equal(t, results[0].RefreshToken, results[i].RefreshToken)
	}
	assert.False(t, deviceRevoked(t, db, tokens.DevicePublicKey))
	_, err = svc.Refresh(results[0].RefreshToken)
	assert.NoError(t, err)
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

func TestAgentService_CanAddAgent_ShouldReportRoomUntilLimit_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-canadd-user")
	before, errBefore := svc.CanAddAgent("test-agent-canadd-user")
	for i := 0; i < maxLiveAgentsPerAccount; i++ {
		_, err := svc.IssueTokens("test-agent-canadd-user", "")
		assert.NoError(t, err)
	}

	// when
	after, errAfter := svc.CanAddAgent("test-agent-canadd-user")

	// then
	assert.NoError(t, errBefore)
	assert.NoError(t, errAfter)
	assert.True(t, before)
	assert.False(t, after)
}

func TestAgentService_IssueTokensForClient_ShouldStoreClientOnDevice_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-client-user")

	// when
	tokens, err := svc.IssueTokensForClient("test-agent-client-user", "prappser-agent", "client-a", "built-in")

	// then
	assert.NoError(t, err)
	repo := NewUserRepository(db)
	device, err := repo.GetDevice(tokens.DevicePublicKey)
	assert.NoError(t, err)
	assert.Equal(t, "prappser-agent", *device.DeviceName)
	assert.Equal(t, "client-a", *device.ClientID)
	assert.Equal(t, "built-in", *device.ClientHost)
	listed, err := repo.ListDevices("test-agent-client-user", false)
	assert.NoError(t, err)
	assert.Len(t, listed, 1)
	assert.Equal(t, "client-a", *listed[0].ClientID)
	assert.Equal(t, "built-in", *listed[0].ClientHost)
}

func TestAgentService_IssueTokensForClient_ShouldRevokeSameClientOnly_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-relogin-user")
	disconnected := map[string]bool{}
	svc.Disconnect = func(_, device string) { disconnected[device] = true }
	oldA, _ := svc.IssueTokensForClient("test-agent-relogin-user", "a", "client-a", "h")
	otherB, _ := svc.IssueTokensForClient("test-agent-relogin-user", "b", "client-b", "h")
	noClient, _ := svc.IssueTokens("test-agent-relogin-user", "c")

	// when
	newA, err := svc.IssueTokensForClient("test-agent-relogin-user", "a", "client-a", "h")

	// then
	assert.NoError(t, err)
	active := func(device string) bool { ok, _ := svc.DeviceActive(device); return ok }
	assert.False(t, active(oldA.DevicePublicKey))
	assert.True(t, disconnected[oldA.DevicePublicKey])
	assert.True(t, active(newA.DevicePublicKey))
	assert.True(t, active(otherB.DevicePublicKey))
	assert.True(t, active(noClient.DevicePublicKey))
}

func TestAgentService_IssueTokensForClient_ShouldNotHitLimitBecauseOfOwnStaleDevice_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-relogincap-user")
	for i := 0; i < maxLiveAgentsPerAccount-1; i++ {
		_, err := svc.IssueTokensForClient("test-agent-relogincap-user", "", "other-"+string(rune('a'+i)), "")
		assert.NoError(t, err)
	}
	_, err := svc.IssueTokensForClient("test-agent-relogincap-user", "", "client-a", "")
	assert.NoError(t, err)

	// when
	_, errSame := svc.IssueTokensForClient("test-agent-relogincap-user", "", "client-a", "")
	_, errNew := svc.IssueTokensForClient("test-agent-relogincap-user", "", "client-new", "")

	// then
	assert.NoError(t, errSame)
	assert.ErrorIs(t, errNew, ErrAgentLimit)
}

func TestAgentService_IssueTokensForClient_EmptyClientIDShouldNotRevoke_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	svc, _ := newAgentTestService(t, db, "test-agent-noclient-user")
	first, _ := svc.IssueTokens("test-agent-noclient-user", "")

	// when
	_, err := svc.IssueTokens("test-agent-noclient-user", "")

	// then
	assert.NoError(t, err)
	ok, _ := svc.DeviceActive(first.DevicePublicKey)
	assert.True(t, ok)
}

func TestAgentService_CanAddAgentForClient_ShouldIgnoreOwnClientDevices_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	const key = "test-agent-canaddclient-user"
	svc, _ := newAgentTestService(t, db, key)
	for i := 0; i < maxLiveAgentsPerAccount-1; i++ {
		_, err := svc.IssueTokens(key, "")
		assert.NoError(t, err)
	}
	_, err := svc.IssueTokensForClient(key, "", "client-x", "")
	assert.NoError(t, err)

	// when
	sameClient, errSame := svc.CanAddAgentForClient(key, "client-x")
	otherClient, errOther := svc.CanAddAgentForClient(key, "client-y")

	// then
	assert.NoError(t, errSame)
	assert.NoError(t, errOther)
	assert.True(t, sameClient)
	assert.False(t, otherClient)
}

func TestAgentService_IssueTokensForClient_CreateFailure_ShouldKeepOldDeviceLiveAndConnected_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	const key = "test-agent-createfail-user"
	svc, _ := newAgentTestService(t, db, key)
	disconnected := 0
	svc.Disconnect = func(_, _ string) { disconnected++ }
	old, err := svc.IssueTokensForClient(key, "a", "client-a", "h")
	assert.NoError(t, err)

	// when
	// a NUL byte makes the device insert fail after the token is minted
	_, err = svc.IssueTokensForClient(key, "bad\x00name", "client-a", "h")

	// then
	assert.Error(t, err)
	ok, _ := svc.DeviceActive(old.DevicePublicKey)
	assert.True(t, ok)
	assert.Equal(t, 0, disconnected)
}

type failingRevokeRepo struct {
	UserRepository
}

func (failingRevokeRepo) RevokeDevice(string, int64) error { return errors.New("revoke failed") }

func TestAgentService_IssueTokensForClient_StaleRevokeFailure_ShouldNotDisconnectButReturnTokens_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	const key = "test-agent-revokefail-user"
	svc, _ := newAgentTestService(t, db, key)
	disconnected := 0
	svc.Disconnect = func(_, _ string) { disconnected++ }
	old, err := svc.IssueTokensForClient(key, "a", "client-a", "h")
	assert.NoError(t, err)
	svc.userRepository = failingRevokeRepo{svc.userRepository}

	// when
	tokens, err := svc.IssueTokensForClient(key, "a", "client-a", "h")

	// then
	assert.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.Equal(t, 0, disconnected)
	assert.False(t, deviceRevoked(t, db, old.DevicePublicKey))
	assert.False(t, deviceRevoked(t, db, tokens.DevicePublicKey))
}

func TestAgentService_Refresh_PreviousTokenWithNullRotatedAt_ShouldRevokeNotGrace_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	const key = "test-agent-nullrot-user"
	svc, _ := newAgentTestService(t, db, key)
	tokens, err := svc.IssueTokens(key, "")
	assert.NoError(t, err)
	_, err = svc.Refresh(tokens.RefreshToken)
	assert.NoError(t, err)
	_, err = db.Exec("UPDATE agent_refresh_tokens SET rotated_at = NULL WHERE device_public_key = $1", tokens.DevicePublicKey)
	assert.NoError(t, err)

	// when
	_, err = svc.Refresh(tokens.RefreshToken)

	// then
	assert.ErrorIs(t, err, ErrInvalidRefreshToken)
	assert.True(t, deviceRevoked(t, db, tokens.DevicePublicKey))
}

func TestAgentService_Refresh_PreviousTokenInGraceWithMismatchingCurrentHash_ShouldFailWithoutRevoke_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	const key = "test-agent-keyrot-user"
	svc, _ := newAgentTestService(t, db, key)
	tokens, err := svc.IssueTokens(key, "")
	assert.NoError(t, err)
	_, err = svc.Refresh(tokens.RefreshToken)
	assert.NoError(t, err)
	// simulates a derivation key that changed since the rotation
	_, err = db.Exec("UPDATE agent_refresh_tokens SET token_hash = 'other' WHERE device_public_key = $1", tokens.DevicePublicKey)
	assert.NoError(t, err)

	// when
	_, err = svc.Refresh(tokens.RefreshToken)

	// then
	assert.ErrorIs(t, err, ErrInvalidRefreshToken)
	assert.False(t, deviceRevoked(t, db, tokens.DevicePublicKey))
}

func TestAgentService_Refresh_PreviousTokenAfterGraceWithMismatchingCurrentHash_ShouldRevoke_Integration(t *testing.T) {
	// given
	db := getTestDB(t)
	defer db.Close()
	const key = "test-agent-keyrotlate-user"
	svc, _ := newAgentTestService(t, db, key)
	tokens, err := svc.IssueTokens(key, "")
	assert.NoError(t, err)
	_, err = svc.Refresh(tokens.RefreshToken)
	assert.NoError(t, err)
	_, err = db.Exec("UPDATE agent_refresh_tokens SET token_hash = 'other' WHERE device_public_key = $1", tokens.DevicePublicKey)
	assert.NoError(t, err)
	ageRotation(t, db, tokens.DevicePublicKey)

	// when
	_, err = svc.Refresh(tokens.RefreshToken)

	// then
	assert.ErrorIs(t, err, ErrInvalidRefreshToken)
	assert.True(t, deviceRevoked(t, db, tokens.DevicePublicKey))
}
