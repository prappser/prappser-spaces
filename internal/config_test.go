package internal

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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

func TestLoadConfig_OpenRegistrationUnset_ShouldDefaultToOff(t *testing.T) {
	// given
	t.Setenv("MASTER_PASSWORD", "test")

	// when
	config, err := LoadConfig()

	// then
	require.NoError(t, err)
	assert.False(t, config.OpenRegistration)
}

func TestLoadConfig_OpenRegistrationTrue_ShouldEnable(t *testing.T) {
	// given
	t.Setenv("MASTER_PASSWORD", "test")
	t.Setenv("OPEN_REGISTRATION", "true")

	// when
	config, err := LoadConfig()

	// then
	require.NoError(t, err)
	assert.True(t, config.OpenRegistration)
}

func TestLoadConfig_OpenRegistrationInvalid_ShouldStayOff(t *testing.T) {
	// given
	t.Setenv("MASTER_PASSWORD", "test")
	t.Setenv("OPEN_REGISTRATION", "yes please")

	// when
	config, err := LoadConfig()

	// then
	require.NoError(t, err)
	assert.False(t, config.OpenRegistration)
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

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Logger
	log.Logger = zerolog.New(&buf)
	t.Cleanup(func() { log.Logger = orig })
	return &buf
}

func TestLoadConfig_MCPEnabledUnset_ShouldDefaultToOn(t *testing.T) {
	// given
	t.Setenv("MCP_ENABLED", "")
	t.Setenv("EXTERNAL_URL", "https://space.example.com")

	// when
	config, err := LoadConfig()

	// then
	require.NoError(t, err)
	assert.True(t, config.MCPEnabled)
}

func TestLoadConfig_MCPEnabledFalse_ShouldDisable(t *testing.T) {
	// given
	logs := captureLog(t)
	t.Setenv("MCP_ENABLED", "false")
	t.Setenv("EXTERNAL_URL", "https://space.example.com")

	// when
	config, err := LoadConfig()

	// then
	require.NoError(t, err)
	assert.False(t, config.MCPEnabled)
	assert.NotContains(t, logs.String(), "MCP")
}

func TestLoadConfig_MCPEnabledUnsetWithoutExternalURL_ShouldStayOff(t *testing.T) {
	// given
	logs := captureLog(t)
	t.Setenv("MCP_ENABLED", "")
	t.Setenv("EXTERNAL_URL", "")

	// when
	config, err := LoadConfig()

	// then
	require.NoError(t, err)
	assert.False(t, config.MCPEnabled)
	assert.Contains(t, logs.String(), "MCP disabled: EXTERNAL_URL is not set")
}

func TestLoadConfig_MCPEnabledTrue_ShouldEnable(t *testing.T) {
	// given
	t.Setenv("MCP_ENABLED", "true")
	t.Setenv("EXTERNAL_URL", "https://space.example.com")

	// when
	config, err := LoadConfig()

	// then
	require.NoError(t, err)
	assert.True(t, config.MCPEnabled)
}

func TestLoadConfig_MCPEnabledInvalid_ShouldStayOff(t *testing.T) {
	// given
	t.Setenv("MCP_ENABLED", "maybe")
	t.Setenv("EXTERNAL_URL", "https://space.example.com")

	// when
	config, err := LoadConfig()

	// then
	require.NoError(t, err)
	assert.False(t, config.MCPEnabled)
}

func TestLoadConfig_AppURL_ShouldDefaultAndTrimTrailingSlash(t *testing.T) {
	// given
	t.Setenv("MASTER_PASSWORD", "test")
	t.Setenv("APP_URL", "")
	defaultConfig, err := LoadConfig()
	require.NoError(t, err)
	t.Setenv("APP_URL", "https://app.example.com/")

	// when
	custom, err := LoadConfig()

	// then
	require.NoError(t, err)
	assert.Equal(t, "https://prappser.app", defaultConfig.AppURL)
	assert.Equal(t, "https://app.example.com", custom.AppURL)
}

func loadWithSchemaBundleURL(t *testing.T, value string) (*Config, error) {
	t.Helper()
	t.Setenv("MASTER_PASSWORD", "test")
	t.Setenv("SCHEMA_BUNDLE_URL", value)
	return LoadConfig()
}

func TestLoadConfig_SchemaBundleURLUnsetOrEmpty_ShouldUseDefault(t *testing.T) {
	// given
	t.Setenv("MASTER_PASSWORD", "test")
	unset, err := LoadConfig()
	require.NoError(t, err)

	// when
	empty, err := loadWithSchemaBundleURL(t, "")

	// then
	require.NoError(t, err)
	assert.Equal(t, defaultSchemaBundleURL, unset.SchemaBundleURL)
	assert.Equal(t, defaultSchemaBundleURL, empty.SchemaBundleURL)
}

func TestLoadConfig_SchemaBundleURLOff_ShouldDisableFetching(t *testing.T) {
	// given / when
	config, err := loadWithSchemaBundleURL(t, " off ")

	// then
	require.NoError(t, err)
	assert.Equal(t, "", config.SchemaBundleURL)
}

func TestLoadConfig_SchemaBundleURLOffUppercase_ShouldDisableFetching(t *testing.T) {
	// given / when
	config, err := loadWithSchemaBundleURL(t, "OFF")

	// then
	require.NoError(t, err)
	assert.Equal(t, "", config.SchemaBundleURL)
}

func TestLoadConfig_SchemaBundleURLCustom_ShouldKeepIt(t *testing.T) {
	// given / when
	config, err := loadWithSchemaBundleURL(t, "http://127.0.0.1:9/b.json")

	// then
	require.NoError(t, err)
	assert.Equal(t, "http://127.0.0.1:9/b.json", config.SchemaBundleURL)
}

func TestLoadConfig_SchemaBundleURLInvalid_ShouldReturnError(t *testing.T) {
	for _, v := range []string{"ftp://x", "not a url", "https://"} {
		// given / when
		_, err := loadWithSchemaBundleURL(t, v)

		// then
		assert.Error(t, err, v)
	}
}

func TestLoadConfig_PushAllowPrivateEndpointsUnset_ShouldDefaultToOff(t *testing.T) {
	// given
	t.Setenv("MASTER_PASSWORD", "test")

	// when
	config, err := LoadConfig()

	// then
	require.NoError(t, err)
	assert.False(t, config.PushAllowPrivateEndpoints)
}

func TestLoadConfig_PushAllowPrivateEndpointsTrue_ShouldEnable(t *testing.T) {
	// given
	t.Setenv("MASTER_PASSWORD", "test")
	t.Setenv("PUSH_ALLOW_PRIVATE_ENDPOINTS", "true")

	// when
	config, err := LoadConfig()

	// then
	require.NoError(t, err)
	assert.True(t, config.PushAllowPrivateEndpoints)
}

func TestLoadConfig_PushAllowPrivateEndpointsInvalid_ShouldStayOff(t *testing.T) {
	// given
	t.Setenv("MASTER_PASSWORD", "test")
	t.Setenv("PUSH_ALLOW_PRIVATE_ENDPOINTS", "yes please")

	// when
	config, err := LoadConfig()

	// then
	require.NoError(t, err)
	assert.False(t, config.PushAllowPrivateEndpoints)
}
