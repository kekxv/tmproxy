package common

import (
	"encoding/json"
	"fmt"
	"os"
)

// ClientConfig defines the structure for the client configuration.
// It includes settings for connecting to the server.
type ClientConfig struct {
	ServerAddr    string `json:"SERVER_ADDR"`
	ProxyUser     string `json:"PROXY_USER,omitempty"`
	ProxyPasswd   string `json:"PROXY_PASSWD,omitempty"`
	TOTPSecretKey string `json:"TOTP_SECRET_KEY,omitempty"`
	WebPassword   string `json:"WEB_PASSWORD,omitempty"`
}

// LoadClientConfig reads the client configuration from a JSON file.
func LoadClientConfig(path string) (*ClientConfig, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("client config file not found: %s", path)
	}

	file, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read client config file: %w", err)
	}

	var config ClientConfig
	if err := json.Unmarshal(file, &config); err != nil {
		return nil, fmt.Errorf("failed to parse client config file: %w", err)
	}

	return &config, nil
}

// SaveClientConfig writes the client configuration to a JSON file without destroying other fields.
func SaveClientConfig(path string, config *ClientConfig) error {
	// Read existing content to preserve other fields (like server config)
	existingData, err := os.ReadFile(path)
	var fullMap map[string]interface{}
	if err == nil {
		json.Unmarshal(existingData, &fullMap)
	} else {
		fullMap = make(map[string]interface{})
	}

	// Update only client-related fields
	if config.ServerAddr != "" {
		fullMap["SERVER_ADDR"] = config.ServerAddr
	}
	if config.ProxyUser != "" {
		fullMap["PROXY_USER"] = config.ProxyUser
	}
	if config.ProxyPasswd != "" {
		fullMap["PROXY_PASSWD"] = config.ProxyPasswd
	}
	if config.TOTPSecretKey != "" {
		fullMap["TOTP_SECRET_KEY"] = config.TOTPSecretKey
	}

	data, err := json.MarshalIndent(fullMap, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
