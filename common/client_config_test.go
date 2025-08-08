package common

import (
	"os"
	"testing"
)

func TestLoadClientConfig(t *testing.T) {
	// Create a temporary config file for testing
	configContent := `{
		"SERVER_ADDR": "ws://localhost:8001/proxy_ws",
		"PROXY_USER": "testuser",
		"PROXY_PASSWD": "testpass",
		"TOTP_SECRET_KEY": "TEST_SECRET"
	}`

	tmpFile, err := os.CreateTemp("", "client_config_test*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write([]byte(configContent)); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	// Test loading the config
	config, err := LoadClientConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify the config values
	if config.ServerAddr != "ws://localhost:8001/proxy_ws" {
		t.Errorf("Expected SERVER_ADDR 'ws://localhost:8001/proxy_ws', got '%s'", config.ServerAddr)
	}
	if config.ProxyUser != "testuser" {
		t.Errorf("Expected PROXY_USER 'testuser', got '%s'", config.ProxyUser)
	}
	if config.ProxyPasswd != "testpass" {
		t.Errorf("Expected PROXY_PASSWD 'testpass', got '%s'", config.ProxyPasswd)
	}
	if config.TOTPSecretKey != "TEST_SECRET" {
		t.Errorf("Expected TOTP_SECRET_KEY 'TEST_SECRET', got '%s'", config.TOTPSecretKey)
	}
}

func TestLoadClientConfigNonExistent(t *testing.T) {
	_, err := LoadClientConfig("non_existent_config.json")
	if err == nil {
		t.Fatal("Expected error when loading non-existent config file, but got none")
	}
}
