package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadWithLimits(t *testing.T, quotaMB, maxApps string) *Config {
	t.Helper()
	t.Setenv("MASTER_PASSWORD", "test")
	t.Setenv("STORAGE_ACCOUNT_QUOTA_MB", quotaMB)
	t.Setenv("MAX_APPS_PER_ACCOUNT", maxApps)
	config, err := LoadConfig()
	require.NoError(t, err)
	return config
}

func TestLoadConfig_LimitsSet_ShouldParseQuotaInBytesAndAppCap(t *testing.T) {
	// given / when
	config := loadWithLimits(t, "250", "20")

	// then
	assert.Equal(t, int64(250*1024*1024), config.Storage.AccountQuota)
	assert.Equal(t, 20, config.MaxAppsPerAccount)
}

func TestLoadConfig_LimitsInvalidOrNegative_ShouldDefaultToOff(t *testing.T) {
	// given / when
	config := loadWithLimits(t, "-5", "abc")

	// then
	assert.Equal(t, int64(0), config.Storage.AccountQuota)
	assert.Equal(t, 0, config.MaxAppsPerAccount)
}

func TestLoadConfig_SignupLimitsUnset_ShouldDefaultToOff(t *testing.T) {
	// given
	t.Setenv("MASTER_PASSWORD", "test")

	// when
	config, err := LoadConfig()

	// then
	require.NoError(t, err)
	assert.False(t, config.SignupSingleUseInvites)
	assert.Equal(t, 0, config.MaxAccounts)
}

func TestLoadConfig_SignupLimitsSet_ShouldParse(t *testing.T) {
	// given
	t.Setenv("MASTER_PASSWORD", "test")
	t.Setenv("SIGNUP_SINGLE_USE_INVITES", "true")
	t.Setenv("MAX_ACCOUNTS", "10")

	// when
	config, err := LoadConfig()

	// then
	require.NoError(t, err)
	assert.True(t, config.SignupSingleUseInvites)
	assert.Equal(t, 10, config.MaxAccounts)
}

func TestLoadConfig_MasterPasswordUnset_ShouldLoad(t *testing.T) {
	// given
	t.Setenv("MASTER_PASSWORD", "")
	t.Setenv("STORAGE_PATH", "")

	// when
	config, err := LoadConfig()

	// then
	require.NoError(t, err)
	assert.Equal(t, "", config.MasterPassword)
	assert.False(t, config.Storage.LocalPathExplicit)
}

func TestLoadConfig_StoragePathSet_ShouldMarkExplicit(t *testing.T) {
	// given
	t.Setenv("STORAGE_PATH", "/data")

	// when
	config, err := LoadConfig()

	// then
	require.NoError(t, err)
	assert.True(t, config.Storage.LocalPathExplicit)
	assert.Equal(t, "/data", config.Storage.LocalPath)
}
