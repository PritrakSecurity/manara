package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
)

// Config holds application configuration
type Config struct {
	DatabaseURL      string
	JWTSecret        string
	JWTExpiryHours   int
	GRPCListenAddr   string
	HTTPListenAddr   string
	TLSCertPath      string
	TLSKeyPath       string
	LogLevel         string
	Environment      string
	AESEncryptionKey string
	AllowedWSOrigins []string
	AllowedOrigins   []string
	AdminEmail       string
	AdminPassword    string
}

// LoadFromEnv loads configuration from environment variables.
//
// JWT_SECRET is mandatory: if it is not set the server fails to start so it can
// never sign tokens with a predictable key. The only exception is
// ENVIRONMENT=development, where a fresh random secret is generated for local
// convenience (every restart invalidates previously issued tokens).
func LoadFromEnv() (*Config, error) {
	environment := getEnv("ENVIRONMENT", "development")

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		if environment == "development" {
			jwtSecret = generateRandomSecret()
		} else {
			return nil, errors.New("JWT_SECRET is required: set the JWT_SECRET environment variable before starting the server")
		}
	}

	// ALLOWED_ORIGINS is the strict allowlist for CORS. It falls back to
	// ALLOWED_WEBSOCKET_ORIGINS for backwards compatibility, then to local
	// development origins.
	allowedOrigins := parseCSV(os.Getenv("ALLOWED_ORIGINS"), nil)
	if len(allowedOrigins) == 0 {
		allowedOrigins = parseCSV(os.Getenv("ALLOWED_WEBSOCKET_ORIGINS"), []string{"http://localhost:5173", "http://localhost:8080"})
	}

	cfg := &Config{
		DatabaseURL:      os.Getenv("DATABASE_URL"), // Required — no default; the server fails fast without it
		JWTSecret:        jwtSecret,
		JWTExpiryHours:   24,
		GRPCListenAddr:   getEnv("GRPC_LISTEN_ADDR", ":50051"),
		HTTPListenAddr:   getEnv("HTTP_LISTEN_ADDR", ":8080"),
		TLSCertPath:      getEnv("TLS_CERT_PATH", "certs/server.crt"),
		TLSKeyPath:       getEnv("TLS_KEY_PATH", "certs/server.key"),
		LogLevel:         getEnv("LOG_LEVEL", "INFO"),
		Environment:      environment,
		AESEncryptionKey: os.Getenv("AES_ENCRYPTION_KEY"), // Required — no default
		AllowedWSOrigins: parseCSV(os.Getenv("ALLOWED_WEBSOCKET_ORIGINS"), []string{"http://localhost:5173", "http://localhost:8080"}),
		AllowedOrigins:   allowedOrigins,
		AdminEmail:       os.Getenv("ADMIN_EMAIL"),
		AdminPassword:    os.Getenv("ADMIN_PASSWORD"),
	}
	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// generateRandomSecret returns a cryptographically secure random hex string.
// Used only when ENVIRONMENT=development and JWT_SECRET is not set.
func generateRandomSecret() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "dev-insecure-fallback-do-not-use-in-production"
	}
	return hex.EncodeToString(buf)
}

// parseCSV splits a comma-separated env var into a slice, returning defaultValue if empty.
func parseCSV(raw string, defaultValue []string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultValue
	}
	parts := strings.Split(raw, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
