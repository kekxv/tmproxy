package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gemini-cli/tmproxy/common"
	"github.com/gorilla/websocket"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

// setupTestServer creates a new server instance with a mock configuration for testing.
func setupTestServer() (*Server, *common.Config) {
	config := &common.Config{
		LISTEN_ADDR:         "127.0.0.1:0", // Use port 0 to let the OS pick a free port
		MAX_CLIENTS:         5,
		WEBSOCKET_PATH:      "/test_ws",
		DEFAULT_REMOTE_PORT: 8080,
		TOTP_SECRET_KEY:     "JBSWY3DPEHPK3PXP", // A fixed key for predictable tests
	}
	return NewServer(config), config
}

// TestHandleHomePage verifies that the home page handler returns the correct content.
func TestHandleHomePage(t *testing.T) {
	server, _ := setupTestServer()
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	server.handleHomePage(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "<h1>tmproxy Server</h1>")
	assert.Contains(t, w.Body.String(), "./tmproxy client --server")
}

// TestWebSocketAuthentication tests the full authentication flow.
func TestWebSocketAuthentication(t *testing.T) {
	server, config := setupTestServer()
	httpServer := httptest.NewServer(http.HandlerFunc(server.handleWebSocket))
	defer httpServer.Close()

	wsURL := "ws" + strings.TrimPrefix(httpServer.URL, "http")

	// --- Test Case 1: Successful Authentication ---
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(t, err)
	defer ws.Close()

	// Generate a valid TOTP token.
	token, err := totp.GenerateCode(config.TOTP_SECRET_KEY, time.Now())
	assert.NoError(t, err)

	// Send auth request.
	request := common.Message{Type: "auth_request", Payload: common.AuthRequest{Token: token}}
	err = ws.WriteJSON(request)
	assert.NoError(t, err)

	// Check for successful auth response.
	var response common.Message
	err = ws.ReadJSON(&response)
	assert.NoError(t, err)
	assert.Equal(t, "auth_response", response.Type)
	// We need to cast the payload to the correct type to check its fields.
	payloadMap := response.Payload.(map[string]interface{})
	assert.True(t, payloadMap["success"].(bool))

	// --- Test Case 2: Failed Authentication ---
	ws2, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(t, err)
	defer ws2.Close()

	// Send invalid auth request.
	invalidRequest := common.Message{Type: "auth_request", Payload: common.AuthRequest{Token: "000000"}}
	err = ws2.WriteJSON(invalidRequest)
	assert.NoError(t, err)

	// Check for failed auth response.
	var failedResponse common.Message
	err = ws2.ReadJSON(&failedResponse)
	assert.NoError(t, err)
	assert.Equal(t, "auth_response", failedResponse.Type)
	failedPayloadMap := failedResponse.Payload.(map[string]interface{})
	assert.False(t, failedPayloadMap["success"].(bool))
	assert.Equal(t, "Invalid token", failedPayloadMap["message"].(string))
}

// TestProxyRequestFlow simulates a client connecting, authenticating, and requesting a proxy.
func TestProxyRequestFlow(t *testing.T) {
	server, config := setupTestServer()
	httpServer := httptest.NewServer(http.HandlerFunc(server.handleWebSocket))
	defer httpServer.Close()

	wsURL := "ws" + strings.TrimPrefix(httpServer.URL, "http")

	// Connect and authenticate.
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(t, err)
	defer ws.Close()

	token, _ := totp.GenerateCode(config.TOTP_SECRET_KEY, time.Now())
	ws.WriteJSON(common.Message{Type: "auth_request", Payload: common.AuthRequest{Token: token}})
	var authResp common.Message
	ws.ReadJSON(&authResp) // Consume auth response

	// Send proxy request.
	proxyReq := common.Message{Type: "proxy_request", Payload: common.ProxyRequest{RemotePort: 9999}}
	err = ws.WriteJSON(proxyReq)
	assert.NoError(t, err)

	// Check for successful proxy response.
	var proxyResp common.Message
	ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	err = ws.ReadJSON(&proxyResp)
	assert.NoError(t, err)
	assert.Equal(t, "proxy_response", proxyResp.Type)

	payload := proxyResp.Payload.(map[string]interface{})
	assert.True(t, payload["success"].(bool))
	assert.Contains(t, payload["public_url"].(string), ":9999")
}
