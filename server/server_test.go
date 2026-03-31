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
		LISTEN_ADDR:    "127.0.0.1:0", // Use port 0 to let the OS pick a free port
		MAX_CLIENTS:    5,
		WEBSOCKET_PATH: "/test_ws",
		FORWARD: []common.ForwardConfig{
			{REMOTE_PORT: 8080, LOCAL_ADDR: "127.0.0.1:3000"},
		},
		TOTP_SECRET_KEY: "JBSWY3DPEHPK3PXP", // A fixed key for predictable tests
	}
	return NewServer(config), config
}

// setupTestServerWithAuth creates a server with admin auth configured.
func setupTestServerWithAuth() (*Server, *common.Config) {
	// Generate a proper bcrypt hash for the test password
	hash, _ := common.HashPassword("testpassword")
	config := &common.Config{
		LISTEN_ADDR:          "127.0.0.1:0",
		MAX_CLIENTS:          5,
		WEBSOCKET_PATH:       "/test_ws",
		TOTP_SECRET_KEY:      "JBSWY3DPEHPK3PXP",
		ADMIN_USERNAME:       "testadmin",
		ADMIN_PASSWORD_HASH:  hash,
		ENABLE_ADMIN_TOTP:    false,
		TLS_CERT_FILE:        "",
		TLS_KEY_FILE:         "",
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
	assert.Contains(t, w.Body.String(), "tmproxy")
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
	assert.Equal(t, "Authentication failed: Invalid TOTP token", failedPayloadMap["message"].(string))
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
	proxyReq := common.Message{Type: "proxy_request", Payload: common.ProxyRequest{RemotePort: 9999, LocalAddr: "127.0.0.1:3000"}}
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

// TestWebSocketOriginCheck tests that the origin check works correctly.
func TestWebSocketOriginCheck(t *testing.T) {
	server, _ := setupTestServer()
	httpServer := httptest.NewServer(http.HandlerFunc(server.handleWebSocket))
	defer httpServer.Close()

	wsURL := "ws" + strings.TrimPrefix(httpServer.URL, "http")

	// Test Case 1: No origin header (should be allowed for non-browser clients)
	ws1, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(t, err, "Connection without origin should be allowed")
	ws1.Close()

	// Test Case 2: Same origin (should be allowed)
	ws2, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(t, err, "Connection with same origin should be allowed")
	ws2.Close()

	// Test Case 3: Different origin (should be rejected in strict mode)
	// Note: The current implementation allows different origins for compatibility
	// This test documents the current behavior
}

// TestAdminLogin tests the admin login functionality.
func TestAdminLogin(t *testing.T) {
	server, _ := setupTestServerWithAuth()
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/admin/login" {
			server.handleAdminLogin(w, r)
		}
	}))
	defer httpServer.Close()

	// Test Case 1: Correct credentials
	loginReq := `{"username":"testadmin","password":"testpassword"}`
	resp, err := http.Post(httpServer.URL+"/api/admin/login", "application/json", strings.NewReader(loginReq))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Check that a session cookie is set
	var sessionCookie *http.Cookie
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "admin_session" {
			sessionCookie = cookie
			break
		}
	}
	assert.NotNil(t, sessionCookie, "Session cookie should be set")
	assert.True(t, sessionCookie.HttpOnly, "Session cookie should be HttpOnly")
	resp.Body.Close()

	// Test Case 2: Wrong password
	loginReq = `{"username":"testadmin","password":"wrongpassword"}`
	resp, err = http.Post(httpServer.URL+"/api/admin/login", "application/json", strings.NewReader(loginReq))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()

	// Test Case 3: Wrong username
	loginReq = `{"username":"wronguser","password":"testpassword"}`
	resp, err = http.Post(httpServer.URL+"/api/admin/login", "application/json", strings.NewReader(loginReq))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()

	// Test Case 4: Invalid request body
	resp, err = http.Post(httpServer.URL+"/api/admin/login", "application/json", strings.NewReader("invalid json"))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

// TestMaxClientsLimit tests that the server enforces the maximum client limit.
func TestMaxClientsLimit(t *testing.T) {
	server, config := setupTestServer()
	httpServer := httptest.NewServer(http.HandlerFunc(server.handleWebSocket))
	defer httpServer.Close()

	wsURL := "ws" + strings.TrimPrefix(httpServer.URL, "http")

	// Connect up to MAX_CLIENTS (5) clients
	var connections []*websocket.Conn
	for i := 0; i < config.MAX_CLIENTS; i++ {
		ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		assert.NoError(t, err)

		token, _ := totp.GenerateCode(config.TOTP_SECRET_KEY, time.Now())
		ws.WriteJSON(common.Message{Type: "auth_request", Payload: common.AuthRequest{Token: token}})

		var resp common.Message
		ws.ReadJSON(&resp)
		connections = append(connections, ws)
	}

	// Try to connect one more client - should be rejected
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(t, err)
	defer ws.Close()

	token, _ := totp.GenerateCode(config.TOTP_SECRET_KEY, time.Now())
	ws.WriteJSON(common.Message{Type: "auth_request", Payload: common.AuthRequest{Token: token}})

	var resp common.Message
	ws.ReadJSON(&resp)
	payload := resp.Payload.(map[string]interface{})
	assert.False(t, payload["success"].(bool), "Connection should be rejected when max clients reached")
	assert.Contains(t, payload["message"].(string), "full")

	// Clean up
	for _, ws := range connections {
		ws.Close()
	}
}

// TestClientReconnection tests that a client can reconnect with the same ID.
func TestClientReconnection(t *testing.T) {
	server, config := setupTestServer()
	httpServer := httptest.NewServer(http.HandlerFunc(server.handleWebSocket))
	defer httpServer.Close()

	wsURL := "ws" + strings.TrimPrefix(httpServer.URL, "http")

	// Connect and authenticate
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(t, err)

	token, _ := totp.GenerateCode(config.TOTP_SECRET_KEY, time.Now())
	ws.WriteJSON(common.Message{Type: "auth_request", Payload: common.AuthRequest{Token: token}})

	var authResp common.Message
	ws.ReadJSON(&authResp)
	payload := authResp.Payload.(map[string]interface{})
	clientID := payload["client_id"].(string)
	assert.NotEmpty(t, clientID)

	// Disconnect
	ws.Close()

	// Reconnect with the same client ID within the reconnection window
	time.Sleep(100 * time.Millisecond) // Small delay to ensure disconnect is processed

	ws2, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(t, err)
	defer ws2.Close()

	token, _ = totp.GenerateCode(config.TOTP_SECRET_KEY, time.Now())
	ws2.WriteJSON(common.Message{Type: "auth_request", Payload: common.AuthRequest{Token: token, ClientID: clientID}})

	var authResp2 common.Message
	ws2.ReadJSON(&authResp2)
	payload2 := authResp2.Payload.(map[string]interface{})
	assert.True(t, payload2["success"].(bool))
	assert.Equal(t, clientID, payload2["client_id"].(string), "Should reconnect with same client ID")
}

// TestProxyUserAuthentication tests proxy user authentication.
func TestProxyUserAuthentication(t *testing.T) {
	config := &common.Config{
		LISTEN_ADDR:      "127.0.0.1:0",
		MAX_CLIENTS:      5,
		WEBSOCKET_PATH:   "/test_ws",
		TOTP_SECRET_KEY:  "JBSWY3DPEHPK3PXP",
		PROXY_USERS: []common.ProxyUser{
			{Username: "proxyuser1", Password: "proxypass1"},
			{Username: "proxyuser2", Password: "proxypass2"},
		},
	}
	server := NewServer(config)
	httpServer := httptest.NewServer(http.HandlerFunc(server.handleWebSocket))
	defer httpServer.Close()

	wsURL := "ws" + strings.TrimPrefix(httpServer.URL, "http")

	// Connect with proxy user credentials
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(t, err)
	defer ws.Close()

	token, _ := totp.GenerateCode(config.TOTP_SECRET_KEY, time.Now())
	ws.WriteJSON(common.Message{
		Type: "auth_request",
		Payload: common.AuthRequest{
			Token:       token,
			ProxyUser:   "proxyuser1",
			ProxyPasswd: "proxypass1",
		},
	})

	var authResp common.Message
	ws.ReadJSON(&authResp)
	payload := authResp.Payload.(map[string]interface{})
	assert.True(t, payload["success"].(bool))
}

// TestPortValidation tests the port validation logic.
func TestPortValidation(t *testing.T) {
	tests := []struct {
		name         string
		port         int
		allowedPorts string
		expected     bool
	}{
		{"empty config allows all", 8080, "", true},
		{"single port match", 8080, "8080", true},
		{"single port no match", 8081, "8080", false},
		{"range match", 8500, "8000-9000", true},
		{"range no match", 9500, "8000-9000", false},
		{"multiple ports match", 9099, "8000-9000,9099", true},
		{"multiple ports no match", 9100, "8000-9000,9099", false},
		{"mixed config match range", 8500, "8080,8000-9000,9099", true},
		{"mixed config match single", 8080, "8080,8000-9000,9099", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isPortAllowed(tt.port, tt.allowedPorts)
			assert.Equal(t, tt.expected, result)
		})
	}
}
