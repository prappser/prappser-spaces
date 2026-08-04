package user

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockUserRepository for testing
type mockUserRepository struct {
	users           map[string]*User
	updateRoleCalls []struct {
		publicKey string
		role      string
	}
}

func newMockUserRepository() *mockUserRepository {
	return &mockUserRepository{
		users: make(map[string]*User),
		updateRoleCalls: []struct {
			publicKey string
			role      string
		}{},
	}
}

func (m *mockUserRepository) CreateUser(user *User) error {
	if _, exists := m.users[user.PublicKey]; exists {
		return fmt.Errorf("user already exists")
	}
	m.users[user.PublicKey] = user
	return nil
}

func (m *mockUserRepository) GetUserByPublicKey(publicKey string) (*User, error) {
	user, exists := m.users[publicKey]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}
	return user, nil
}

func (m *mockUserRepository) UpdateUserRole(publicKey string, role string) error {
	m.updateRoleCalls = append(m.updateRoleCalls, struct {
		publicKey string
		role      string
	}{publicKey, role})

	user, exists := m.users[publicKey]
	if !exists {
		return fmt.Errorf("user not found")
	}
	user.Role = role
	return nil
}

func (m *mockUserRepository) UpdateUserIssuer(publicKey, issuer string) error { return nil }
func (m *mockUserRepository) EnsureDevice(devicePublicKey, userPublicKey string, deviceName *string, createdAt int64) error {
	return nil
}
func (m *mockUserRepository) GetDevice(devicePublicKey string) (*Device, error) { return nil, nil }
func (m *mockUserRepository) ListDevices(userPublicKey string) ([]*Device, error) {
	return nil, nil
}
func (m *mockUserRepository) RevokeDevice(devicePublicKey string, ts int64) error   { return nil }
func (m *mockUserRepository) RenameDevice(devicePublicKey, deviceName string) error { return nil }
func (m *mockUserRepository) TouchDeviceLastSeen(devicePublicKey string, ts int64) error {
	return nil
}
func (m *mockUserRepository) SetPasswordCredentials(publicKey, passwordVerifier, handle, accountKeyBlob, userState string) error {
	return nil
}
func (m *mockUserRepository) GetPasswordCredential(username string) (string, string, error) {
	return "", "", nil
}
func (m *mockUserRepository) GetPasswordHandle(username string) (string, error) {
	return "", nil
}
func (m *mockUserRepository) GetEscrow(publicKey string) (string, string, error) {
	return "", "", nil
}
func (m *mockUserRepository) ClaimOwner(publicKey, username, passwordVerifier, handle, accountKeyBlob, userState string, deviceName *string, createdAt int64) error {
	return nil
}
func (m *mockUserRepository) HasClaim() (bool, error) { return false, nil }

func TestGenerateChallenge_ShouldGenerateUniqueChallenge(t *testing.T) {
	// when
	challenge1, err1 := generateChallenge()
	challenge2, err2 := generateChallenge()

	// then
	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.NotEmpty(t, challenge1)
	assert.NotEmpty(t, challenge2)
	assert.NotEqual(t, challenge1, challenge2)
}

func TestExtractJWSFromAuthorizationHeader_ShouldExtractValidly(t *testing.T) {
	// given
	authHeader := "Bearer eyJhbGciOiJSUzI1NiJ9.eyJ1c2VybmFtZSI6ImFsaWNlIiwiY2hhbGxlbmdlIjoiYTF..."

	// when
	jws, err := extractJWSFromAuthorizationHeader(authHeader)

	// then
	assert.NoError(t, err)
	assert.NotEmpty(t, jws)
	assert.Contains(t, jws, "eyJhbGciOiJSUzI1NiJ9")
}

func TestExtractJWSFromAuthorizationHeader_ShouldFailWithInvalidFormat(t *testing.T) {
	// given
	authHeader := "InvalidFormat"

	// when
	jws, err := extractJWSFromAuthorizationHeader(authHeader)

	// then
	assert.Error(t, err)
	assert.Empty(t, jws)
}

func TestExtractJWTFromAuthorizationHeader_ShouldExtractValidly(t *testing.T) {
	// given
	authHeader := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

	// when
	jwt, err := extractJWTFromAuthorizationHeader(authHeader)

	// then
	assert.NoError(t, err)
	assert.NotEmpty(t, jwt)
	assert.Contains(t, jwt, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
}

func TestExtractJWTFromAuthorizationHeader_ShouldFailWithInvalidFormat(t *testing.T) {
	// given
	authHeader := "InvalidFormat"

	// when
	jwt, err := extractJWTFromAuthorizationHeader(authHeader)

	// then
	assert.Error(t, err)
	assert.Empty(t, jwt)
}

func TestUpdateUserRole_ShouldUpdateExistingUserRole(t *testing.T) {
	// given
	repo := newMockUserRepository()
	user := &User{
		PublicKey: "test-public-key",
		Username:  "testuser",
		Role:      "member",
		CreatedAt: 123456789,
	}
	repo.CreateUser(user)

	// when
	err := repo.UpdateUserRole("test-public-key", RoleOwner)

	// then
	assert.NoError(t, err)
	updatedUser, _ := repo.GetUserByPublicKey("test-public-key")
	assert.Equal(t, RoleOwner, updatedUser.Role)
	assert.Len(t, repo.updateRoleCalls, 1)
	assert.Equal(t, "test-public-key", repo.updateRoleCalls[0].publicKey)
	assert.Equal(t, RoleOwner, repo.updateRoleCalls[0].role)
}

func TestUpdateUserRole_ShouldFailForNonExistentUser(t *testing.T) {
	// given
	repo := newMockUserRepository()

	// when
	err := repo.UpdateUserRole("non-existent-key", RoleOwner)

	// then
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

func TestUpdateUserRole_ShouldAllowMultipleRoleChanges(t *testing.T) {
	// given
	repo := newMockUserRepository()
	user := &User{
		PublicKey: "test-public-key",
		Username:  "testuser",
		Role:      "member",
		CreatedAt: 123456789,
	}
	repo.CreateUser(user)

	// when - first update
	err1 := repo.UpdateUserRole("test-public-key", RoleOwner)
	// when - second update back to member
	err2 := repo.UpdateUserRole("test-public-key", "member")

	// then
	assert.NoError(t, err1)
	assert.NoError(t, err2)
	finalUser, _ := repo.GetUserByPublicKey("test-public-key")
	assert.Equal(t, "member", finalUser.Role)
	assert.Len(t, repo.updateRoleCalls, 2)
}
