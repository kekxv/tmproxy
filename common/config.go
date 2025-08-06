package common

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/pquerna/otp/totp"
)

// Config defines the structure for the server configuration.
// It includes settings for the listener, proxying, and security.
// Note: Field names are in uppercase to match the JSON file format.
type Config struct {
	LISTEN_ADDR         string `json:"LISTEN_ADDR"`
	MAX_CLIENTS         int    `json:"MAX_CLIENTS"`
	WEBSOCKET_PATH      string `json:"WEBSOCKET_PATH"`
	DEFAULT_REMOTE_PORT int    `json:"DEFAULT_REMOTE_PORT"`
	DEFAULT_LOCAL_PORT  int    `json:"DEFAULT_LOCAL_PORT"`
	TOTP_SECRET_KEY     string `json:"TOTP_SECRET_KEY"`
	TLS_CERT_FILE       string `json:"TLS_CERT_FILE,omitempty"`
	TLS_KEY_FILE        string `json:"TLS_KEY_FILE,omitempty"`

	// Admin Panel Configuration
	ADMIN_USERNAME        string `json:"ADMIN_USERNAME"`
	ADMIN_PASSWORD_HASH   string `json:"ADMIN_PASSWORD_HASH"` // Store hashed password
	ADMIN_TOTP_SECRET_KEY string `json:"ADMIN_TOTP_SECRET_KEY"`
	ENABLE_ADMIN_TOTP     bool   `json:"ENABLE_ADMIN_TOTP"`
}

// LoadConfig reads the configuration from a JSON file.
// If the file does not exist, it generates a default configuration with a new TOTP key.
func LoadConfig(path string) (*Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return createDefaultConfig(path)
	}

	file, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(file, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// createDefaultConfig generates a new configuration file with a random TOTP secret.
// It saves the config to the specified path and prints instructions for the user.
func createDefaultConfig(path string) (*Config, error) {
	fmt.Println("Configuration file not found. Creating a new one...")

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "tmproxyServer",
		AccountName: "proxy-user",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	config := &Config{
		LISTEN_ADDR:         "0.0.0.0:8001",
		MAX_CLIENTS:         100,
		WEBSOCKET_PATH:      "/proxy_ws",
		DEFAULT_REMOTE_PORT: 8080,
		DEFAULT_LOCAL_PORT:  3000,
		TOTP_SECRET_KEY:     key.Secret(),
		TLS_CERT_FILE:       "",
		TLS_KEY_FILE:        "",

		// Admin Panel Configuration
		ADMIN_USERNAME:        "admin",
		ADMIN_PASSWORD_HASH:   "changeme", // IMPORTANT: Change this default password in your config file!
		ADMIN_TOTP_SECRET_KEY: "",         // Leave empty to disable TOTP for admin, or generate one
		ENABLE_ADMIN_TOTP:     false,
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal default config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to write config file: %w", err)
	}

	fmt.Printf("Successfully created config file at '%s'\n", path)
	fmt.Println("Scan this QR code with your authenticator app (e.g., Google Authenticator):")
	fmt.Printf("Or use this URI: %s\n", key.URL())
	fmt.Printf("Your TOTP Secret Key is: %s\n", key.Secret())

	return config, nil
}

// GenerateTOTP generates a TOTP token from a given secret.
func GenerateTOTP(secret string) (string, error) {
	token, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return "", fmt.Errorf("failed to generate TOTP code: %w", err)
	}
	return token, nil
}
