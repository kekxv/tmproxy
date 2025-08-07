package common

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCreateDefaultConfig verifies that a new config file is created with a valid TOTP key.
func TestCreateDefaultConfig(t *testing.T) {
	path := "test_config.json"
	defer os.Remove(path) // Clean up the file after the test.

	config, err := createDefaultConfig(path)

	assert.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, "0.0.0.0:8001", config.LISTEN_ADDR)
	assert.Equal(t, 100, config.MAX_CLIENTS)
	assert.NotEmpty(t, config.TOTP_SECRET_KEY)

	// Verify the file was actually created.
	_, err = os.Stat(path)
	assert.NoError(t, err, "Config file should exist")
}

// TestCreateDefaultConfig_WriteError tests error handling when the config file cannot be written.
func TestCreateDefaultConfig_WriteError(t *testing.T) {
	// Using a directory that doesn't exist to simulate a write error
	path := "nonexistent_directory/config.json"

	config, err := createDefaultConfig(path)

	assert.Error(t, err)
	assert.Nil(t, config)
}

// TestLoadConfig verifies that an existing config file is loaded correctly.
func TestLoadConfig(t *testing.T) {
	path := "test_config_load.json"
	defer os.Remove(path)

	// Create a dummy config file.
	content := `{
		"LISTEN_ADDR": "127.0.0.1:9000",
		"MAX_CLIENTS": 50,
		"WEBSOCKET_PATH": "/ws",
		"FORWARD": [
			{
				"REMOTE_PORT": 9090,
				"LOCAL_ADDR": "127.0.0.1:4000"
			}
		],
		"TOTP_SECRET_KEY": "JBSWY3DPEHPK3PXP"
	}`
	err := os.WriteFile(path, []byte(content), 0644)
	assert.NoError(t, err)

	config, err := LoadConfig(path)

	assert.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, "127.0.0.1:9000", config.LISTEN_ADDR)
	assert.Equal(t, 50, config.MAX_CLIENTS)
	assert.Equal(t, "/ws", config.WEBSOCKET_PATH)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", config.TOTP_SECRET_KEY)
}

// TestLoadConfig_NotFound verifies that LoadConfig calls createDefaultConfig when the file doesn't exist.
func TestLoadConfig_NotFound(t *testing.T) {
	path := "non_existent_config.json"
	defer os.Remove(path) // Clean up if created.

	config, err := LoadConfig(path)

	assert.NoError(t, err)
	assert.NotNil(t, config)
	assert.NotEmpty(t, config.TOTP_SECRET_KEY, "A new TOTP key should have been generated")
}

// TestLoadConfig_InvalidJSON tests error handling when the config file contains invalid JSON.
func TestLoadConfig_InvalidJSON(t *testing.T) {
	path := "invalid_config.json"
	defer os.Remove(path)

	// Create a config file with invalid JSON.
	content := `{
		"LISTEN_ADDR": "127.0.0.1:9000",
		"MAX_CLIENTS": 50,
		"WEBSOCKET_PATH": "/ws",
		// Missing closing brace
	`
	err := os.WriteFile(path, []byte(content), 0644)
	assert.NoError(t, err)

	config, err := LoadConfig(path)

	assert.Error(t, err)
	assert.Nil(t, config)
}

// TestLoadConfig_ReadError tests error handling when the config file cannot be read.
func TestLoadConfig_ReadError(t *testing.T) {
	// Using a directory path instead of a file path to simulate a read error
	path := "test_directory"
	defer os.RemoveAll(path)
	
	err := os.Mkdir(path, 0755)
	assert.NoError(t, err)

	config, err := LoadConfig(path)

	assert.Error(t, err)
	assert.Nil(t, config)
}

// TestGenerateTOTP tests the GenerateTOTP function.
func TestGenerateTOTP(t *testing.T) {
	// Test with a valid secret
	secret := "JBSWY3DPEHPK3PXP"
	token, err := GenerateTOTP(secret)

	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Len(t, token, 6) // TOTP tokens are typically 6 digits

	// Test with an invalid secret
	invalidSecret := "INVALID_SECRET"
	token, err = GenerateTOTP(invalidSecret)

	assert.Error(t, err)
	assert.Empty(t, token)
}
