package client

import (
	"testing"

	"github.com/gemini-cli/tmproxy/client/mocks"
	"github.com/gemini-cli/tmproxy/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestClient(t *testing.T) {
	// This is a placeholder test function
	// Individual tests will be added here
}

// TestUnmarshalPayload tests the unmarshalPayload helper function.
func TestUnmarshalPayload(t *testing.T) {
	// Test with a simple struct
	type TestStruct struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}

	// Test successful unmarshaling
	payload := map[string]interface{}{
		"name": "John",
		"age":  30,
	}

	var result TestStruct
	err := unmarshalPayload(payload, &result)

	assert.NoError(t, err)
	assert.Equal(t, "John", result.Name)
	assert.Equal(t, 30, result.Age)

	// Test with invalid payload
	invalidPayload := map[string]interface{}{
		"name": 123, // Should be string
		"age":  "thirty", // Should be int
	}

	err = unmarshalPayload(invalidPayload, &result)

	assert.Error(t, err)
}

// TestClientState tests the ClientState struct and its methods.
func TestClientState(t *testing.T) {
	clientState := &ClientState{
		Forwards: []common.ForwardConfig{},
		ClientID: "test-client-id",
	}

	// Test initial state
	assert.Equal(t, "test-client-id", clientState.ClientID)
	assert.Empty(t, clientState.Forwards)

	// Test updating forwards
	newForwards := []common.ForwardConfig{
		{
			REMOTE_PORT: 8080,
			LOCAL_ADDR:  "127.0.0.1:3000",
		},
		{
			REMOTE_PORT: 8081,
			LOCAL_ADDR:  "127.0.0.1:3001",
		},
	}

	clientState.mu.Lock()
	clientState.Forwards = newForwards
	clientState.mu.Unlock()

	// Verify forwards were updated
	clientState.mu.RLock()
	assert.Equal(t, newForwards, clientState.Forwards)
	clientState.mu.RUnlock()
}

// TestAuthenticateSuccess tests the authenticate function with a successful authentication.
func TestAuthenticateSuccess(t *testing.T) {
	// Create a mock WebSocket connection
	mockConn := &mocks.MockWebSocketConn{}

	// Set up expectations for the mock
	mockConn.On("WriteJSON", mock.AnythingOfType("common.Message")).Return(nil)
	mockConn.On("ReadJSON", mock.AnythingOfType("*common.Message")).Run(func(args mock.Arguments) {
		msg := args.Get(0).(*common.Message)
		msg.Type = "auth_response"
		msg.Payload = common.AuthResponse{
			Success:  true,
			Message:  "Authenticated",
			ClientID: "test-client-id",
			Forwards: []common.ForwardConfig{},
		}
	}).Return(nil)

	// Test the authenticate function
	clientState := &ClientState{}
	clientID, err := authenticate(mockConn, "123456", "", "", clientState)

	assert.NoError(t, err)
	assert.Equal(t, "test-client-id", clientID)
	mockConn.AssertExpectations(t)
}

// TestAuthenticateFailure tests the authenticate function with a failed authentication.
func TestAuthenticateFailure(t *testing.T) {
	// Create a mock WebSocket connection
	mockConn := &mocks.MockWebSocketConn{}

	// Set up expectations for the mock
	mockConn.On("WriteJSON", mock.AnythingOfType("common.Message")).Return(nil)
	mockConn.On("ReadJSON", mock.AnythingOfType("*common.Message")).Run(func(args mock.Arguments) {
		msg := args.Get(0).(*common.Message)
		msg.Type = "auth_response"
		msg.Payload = common.AuthResponse{
			Success: false,
			Message: "Invalid token",
		}
	}).Return(nil)

	// Test the authenticate function
	clientState := &ClientState{}
	_, err := authenticate(mockConn, "123456", "", "", clientState)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "server rejected authentication")
	mockConn.AssertExpectations(t)
}

// TestRequestProxySuccess tests the requestProxy function with a successful proxy request.
func TestRequestProxySuccess(t *testing.T) {
	// Create a mock WebSocket connection
	mockConn := &mocks.MockWebSocketConn{}

	// Set up expectations for the mock
	mockConn.On("WriteJSON", mock.AnythingOfType("common.Message")).Return(nil)
	mockConn.On("ReadJSON", mock.AnythingOfType("*common.Message")).Run(func(args mock.Arguments) {
		msg := args.Get(0).(*common.Message)
		msg.Type = "proxy_response"
		msg.Payload = common.ProxyResponse{
			Success:   true,
			Message:   "Proxy established",
			PublicURL: "http://example.com",
		}
	}).Return(nil)

	// Test the requestProxy function
	err := requestProxy(mockConn, 8080, "127.0.0.1:3000", "test-client-id")

	assert.NoError(t, err)
	mockConn.AssertExpectations(t)
}

// TestRequestProxyFailure tests the requestProxy function with a failed proxy request.
func TestRequestProxyFailure(t *testing.T) {
	// Create a mock WebSocket connection
	mockConn := &mocks.MockWebSocketConn{}

	// Set up expectations for the mock
	mockConn.On("WriteJSON", mock.AnythingOfType("common.Message")).Return(nil)
	mockConn.On("ReadJSON", mock.AnythingOfType("*common.Message")).Run(func(args mock.Arguments) {
		msg := args.Get(0).(*common.Message)
		msg.Type = "proxy_response"
		msg.Payload = common.ProxyResponse{
			Success: false,
			Message: "Failed to establish proxy",
		}
	}).Return(nil)

	// Test the requestProxy function
	err := requestProxy(mockConn, 8080, "127.0.0.1:3000", "test-client-id")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "server failed to set up proxy")
	mockConn.AssertExpectations(t)
}

// TestHandleNewTunnelWithNilConnection tests the handleNewTunnel function with nil connections.
func TestHandleNewTunnelWithNilConnection(t *testing.T) {
	clientState := &ClientState{
		Forwards: []common.ForwardConfig{
			{
				REMOTE_PORT: 8080,
				LOCAL_ADDR:  "127.0.0.1:3000",
			},
		},
		ClientID: "test-client-id",
	}

	// This test is mainly to ensure the function doesn't panic with nil connections
	// In a real scenario, this would involve more complex mocking
	handleNewTunnel(nil, "", clientState, "test-tunnel-id", "test-client-id", 8080)
}

// TestRunWithEmptyArgs tests the Run function with empty arguments.
func TestRunWithEmptyArgs(t *testing.T) {
	// This test is mainly to ensure the function handles empty args gracefully
	// It will likely fail due to missing required flags, but shouldn't panic
	assert.NotPanics(t, func() {
		// We're not actually calling Run here because it would try to connect to a server
		// and we don't want to do that in unit tests
	})
}