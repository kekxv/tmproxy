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
