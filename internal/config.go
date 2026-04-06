package internal

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/prappser/prappser-spaces/internal/user"
)

type Config struct {
	Users          user.Config
	Storage        StorageConfig
	Port           string
	ExternalURL    string
	AllowedOrigins []string
	MasterPassword string
}

type StorageConfig struct {
	StorageType  string
	LocalPath    string
	S3Endpoint   string
	S3Bucket     string
	S3AccessKey  string
	S3SecretKey  string
	S3Region     string
	S3UseSSL     bool
	MaxFileSize  int64
	ChunkSize    int64
}

// Defaults
const (
	defaultPort                    = "4545"
	defaultJWTExpirationHours      = 24
	defaultChallengeTTLSec         = 300
	defaultRegistrationTokenTTLSec = 10
)

var defaultAllowedOrigins = []string{"https://prappser.app", "http://localhost:*", "https://localhost:*"}

func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func resolveExternalURL(externalURL, hostingProvider, port string) string {
	if externalURL == "" {
		return fmt.Sprintf("http://localhost:%s", port)
	}

	urlWithoutScheme := externalURL
	hasHTTPS := strings.HasPrefix(externalURL, "https://")
	hasHTTP := strings.HasPrefix(externalURL, "http://")
	if hasHTTPS {
		urlWithoutScheme = strings.TrimPrefix(externalURL, "https://")
	} else if hasHTTP {
		urlWithoutScheme = strings.TrimPrefix(externalURL, "http://")
	}

	isFullDomain := strings.Contains(urlWithoutScheme, ".")

	if hostingProvider == "zeabur" && !isFullDomain {
		return fmt.Sprintf("https://%s.zeabur.app", urlWithoutScheme)
	}

	if !hasHTTPS && !hasHTTP {
		return fmt.Sprintf("https://%s", externalURL)
	}

	return externalURL
}

func LoadConfig() (*Config, error) {
	envPort := os.Getenv("PORT")
	envExternalURL := os.Getenv("EXTERNAL_URL")
	envHostingProvider := os.Getenv("HOSTING_PROVIDER")
	envMasterPassword := os.Getenv("MASTER_PASSWORD")
	envAllowedOrigins := os.Getenv("ALLOWED_ORIGINS")
	envJWTExpirationHours := os.Getenv("JWT_EXPIRATION_HOURS")
	envChallengeTTLSec := os.Getenv("CHALLENGE_TTL_SEC")
	envRegistrationTokenTTLSec := os.Getenv("REGISTRATION_TOKEN_TTL_SEC")

	// Validate required config
	if envMasterPassword == "" {
		return nil, fmt.Errorf("MASTER_PASSWORD environment variable is required")
	}

	// Build config with defaults and env overrides
	config := &Config{
		MasterPassword: envMasterPassword,
	}

	if envPort == "" {
		envPort = defaultPort
	}
	config.Port = envPort

	// External URL
	config.ExternalURL = resolveExternalURL(envExternalURL, envHostingProvider, config.Port)

	// Allowed Origins
	if envAllowedOrigins != "" {
		origins := strings.Split(envAllowedOrigins, ",")
		for i := range origins {
			origins[i] = strings.TrimSpace(origins[i])
		}
		config.AllowedOrigins = origins
	} else {
		config.AllowedOrigins = defaultAllowedOrigins
	}

	// User config
	hash := md5.Sum([]byte(envMasterPassword))
	config.Users.MasterPasswordMD5Hash = hex.EncodeToString(hash[:])

	config.Users.JWTExpirationHours = defaultJWTExpirationHours
	if envJWTExpirationHours != "" {
		if hours, err := strconv.Atoi(envJWTExpirationHours); err == nil {
			config.Users.JWTExpirationHours = hours
		}
	}

	config.Users.ChallengeTTLSec = defaultChallengeTTLSec
	if envChallengeTTLSec != "" {
		if seconds, err := strconv.Atoi(envChallengeTTLSec); err == nil {
			config.Users.ChallengeTTLSec = seconds
		}
	}

	config.Users.RegistrationTokenTTLSec = defaultRegistrationTokenTTLSec
	if envRegistrationTokenTTLSec != "" {
		if seconds, err := strconv.Atoi(envRegistrationTokenTTLSec); err == nil {
			config.Users.RegistrationTokenTTLSec = int32(seconds)
		}
	}

	config.Storage.StorageType = getEnvOrDefault("STORAGE_TYPE", "local")
	config.Storage.LocalPath = getEnvOrDefault("STORAGE_PATH", "./storage")

	config.Storage.S3Endpoint = os.Getenv("STORAGE_S3_ENDPOINT")
	config.Storage.S3Bucket = os.Getenv("STORAGE_S3_BUCKET")
	config.Storage.S3AccessKey = os.Getenv("STORAGE_S3_ACCESS_KEY")
	config.Storage.S3SecretKey = os.Getenv("STORAGE_S3_SECRET_KEY")
	config.Storage.S3Region = getEnvOrDefault("STORAGE_S3_REGION", "us-east-1")
	config.Storage.S3UseSSL = os.Getenv("STORAGE_S3_USE_SSL") != "false"

	maxFileSizeMBStr := os.Getenv("STORAGE_MAX_FILE_SIZE_MB")
	if maxFileSizeMBStr != "" {
		if sizeMB, err := strconv.ParseInt(maxFileSizeMBStr, 10, 64); err == nil {
			config.Storage.MaxFileSize = sizeMB * 1024 * 1024
		}
	}
	if config.Storage.MaxFileSize <= 0 {
		config.Storage.MaxFileSize = 50 * 1024 * 1024 // 50MB default
	}

	chunkSizeMBStr := os.Getenv("STORAGE_CHUNK_SIZE_MB")
	if chunkSizeMBStr != "" {
		if sizeMB, err := strconv.ParseInt(chunkSizeMBStr, 10, 64); err == nil {
			config.Storage.ChunkSize = sizeMB * 1024 * 1024
		}
	}
	if config.Storage.ChunkSize <= 0 {
		config.Storage.ChunkSize = 5 * 1024 * 1024 // 5MB default
	}

	return config, nil
}
