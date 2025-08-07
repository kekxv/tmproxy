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
