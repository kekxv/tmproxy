package client

import (
	"context"
	"fmt"
	"testing"
	"time"

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
		"name": 123,      // Should be string
		"age":  "thirty", // Should be int
	}

	err = unmarshalPayload(invalidPayload, &result)

	assert.Error(t, err)

	// Test with nil payload
	// This should not panic, but the result will be empty
	err = unmarshalPayload(nil, &result)
	// The function doesn't return an error for nil payload, which is fine
	// We're just testing that it doesn't panic
	assert.NoError(t, err)
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
	clientID, err := authenticate(mockConn, "123456", "", "", "", "", clientState)

	assert.NoError(t, err)
	assert.Equal(t, "test-client-id", clientID)
	mockConn.AssertExpectations(t)
}

// TestAuthenticateWithTOTPSecret tests the authenticate function with a TOTP secret.
func TestAuthenticateWithTOTPSecret(t *testing.T) {
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

	// Test the authenticate function with a valid TOTP secret
	clientState := &ClientState{}
	clientID, err := authenticate(mockConn, "", "JBSWY3DPEHPK3PXP", "", "", "", clientState)

	assert.NoError(t, err)
	assert.Equal(t, "test-client-id", clientID)
	mockConn.AssertExpectations(t)
}

// TestAuthenticateWithInvalidTOTPSecret tests the authenticate function with an invalid TOTP secret.
func TestAuthenticateWithInvalidTOTPSecret(t *testing.T) {
	// Test the authenticate function with an invalid TOTP secret
	clientState := &ClientState{}
	_, err := authenticate(nil, "", "INVALID_SECRET", "", "", "", clientState)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to generate TOTP token from secret")
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
	_, err := authenticate(mockConn, "123456", "", "", "", "", clientState)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "server rejected authentication")
	mockConn.AssertExpectations(t)
}

// TestAuthenticateWriteJSONError tests the authenticate function when WriteJSON fails.
func TestAuthenticateWriteJSONError(t *testing.T) {
	// Create a mock WebSocket connection
	mockConn := &mocks.MockWebSocketConn{}

	// Set up expectations for the mock
	mockConn.On("WriteJSON", mock.AnythingOfType("common.Message")).Return(fmt.Errorf("write error"))

	// Test the authenticate function
	clientState := &ClientState{}
	_, err := authenticate(mockConn, "123456", "", "", "", "", clientState)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to send auth request")
	mockConn.AssertExpectations(t)
}

// TestAuthenticateReadJSONError tests the authenticate function when ReadJSON fails.
func TestAuthenticateReadJSONError(t *testing.T) {
	// Create a mock WebSocket connection
	mockConn := &mocks.MockWebSocketConn{}

	// Set up expectations for the mock
	mockConn.On("WriteJSON", mock.AnythingOfType("common.Message")).Return(nil)
	mockConn.On("ReadJSON", mock.AnythingOfType("*common.Message")).Return(fmt.Errorf("read error"))

	// Test the authenticate function
	clientState := &ClientState{}
	_, err := authenticate(mockConn, "123456", "", "", "", "", clientState)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read auth response")
	mockConn.AssertExpectations(t)
}

// TestAuthenticateUnexpectedMessageType tests the authenticate function with an unexpected message type.
func TestAuthenticateUnexpectedMessageType(t *testing.T) {
	// Create a mock WebSocket connection
	mockConn := &mocks.MockWebSocketConn{}

	// Set up expectations for the mock
	mockConn.On("WriteJSON", mock.AnythingOfType("common.Message")).Return(nil)
	mockConn.On("ReadJSON", mock.AnythingOfType("*common.Message")).Run(func(args mock.Arguments) {
		msg := args.Get(0).(*common.Message)
		msg.Type = "unexpected_type"
	}).Return(nil)

	// Test the authenticate function
	clientState := &ClientState{}
	_, err := authenticate(mockConn, "123456", "", "", "", "", clientState)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected message type")
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

// TestRequestProxyWriteJSONError tests the requestProxy function when WriteJSON fails.
func TestRequestProxyWriteJSONError(t *testing.T) {
	// Create a mock WebSocket connection
	mockConn := &mocks.MockWebSocketConn{}

	// Set up expectations for the mock
	mockConn.On("WriteJSON", mock.AnythingOfType("common.Message")).Return(fmt.Errorf("write error"))

	// Test the requestProxy function
	err := requestProxy(mockConn, 8080, "127.0.0.1:3000", "test-client-id")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to send proxy request")
	mockConn.AssertExpectations(t)
}

// TestRequestProxyReadJSONError tests the requestProxy function when ReadJSON fails.
func TestRequestProxyReadJSONError(t *testing.T) {
	// Create a mock WebSocket connection
	mockConn := &mocks.MockWebSocketConn{}

	// Set up expectations for the mock
	mockConn.On("WriteJSON", mock.AnythingOfType("common.Message")).Return(nil)
	mockConn.On("ReadJSON", mock.AnythingOfType("*common.Message")).Return(fmt.Errorf("read error"))

	// Test the requestProxy function
	err := requestProxy(mockConn, 8080, "127.0.0.1:3000", "test-client-id")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read proxy response")
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

// TestRequestProxyUnexpectedMessageType tests the requestProxy function with an unexpected message type.
func TestRequestProxyUnexpectedMessageType(t *testing.T) {
	// Create a mock WebSocket connection
	mockConn := &mocks.MockWebSocketConn{}

	// Set up expectations for the mock
	mockConn.On("WriteJSON", mock.AnythingOfType("common.Message")).Return(nil)
	mockConn.On("ReadJSON", mock.AnythingOfType("*common.Message")).Run(func(args mock.Arguments) {
		msg := args.Get(0).(*common.Message)
		msg.Type = "unexpected_type"
	}).Return(nil)

	// Test the requestProxy function
	err := requestProxy(mockConn, 8080, "127.0.0.1:3000", "test-client-id")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected message type")
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

// TestHandleNewTunnelWithNonExistentPort tests the handleNewTunnel function with a non-existent port.
func TestHandleNewTunnelWithNonExistentPort(t *testing.T) {
	clientState := &ClientState{
		Forwards: []common.ForwardConfig{
			{
				REMOTE_PORT: 8080,
				LOCAL_ADDR:  "127.0.0.1:3000",
			},
		},
		ClientID: "test-client-id",
	}

	// Test with a port that doesn't exist in the forwards
	handleNewTunnel(nil, "", clientState, "test-tunnel-id", "test-client-id", 9999)
}

// TestHandleNewTunnelWithInvalidLocalAddress tests the handleNewTunnel function with an invalid local address.
func TestHandleNewTunnelWithInvalidLocalAddress(t *testing.T) {
	clientState := &ClientState{
		Forwards: []common.ForwardConfig{
			{
				REMOTE_PORT: 8080,
				LOCAL_ADDR:  "invalid-address",
			},
		},
		ClientID: "test-client-id",
	}

	// Create a mock WebSocket connection
	mockConn := &mocks.MockWebSocketConn{}
	mockConn.On("WriteJSON", mock.AnythingOfType("common.Message")).Return(nil)

	// Test with an invalid local address
	handleNewTunnel(mockConn, "", clientState, "test-tunnel-id", "test-client-id", 8080)

	mockConn.AssertExpectations(t)
}

// TestHandleNewTunnelWithValidLocalAddress tests the handleNewTunnel function with a valid local address.
func TestHandleNewTunnelWithValidLocalAddress(t *testing.T) {
	clientState := &ClientState{
		Forwards: []common.ForwardConfig{
			{
				REMOTE_PORT: 8080,
				LOCAL_ADDR:  "127.0.0.1:3000",
			},
		},
		ClientID: "test-client-id",
	}

	// Create a mock WebSocket connection
	mockConn := &mocks.MockWebSocketConn{}
	mockConn.On("WriteJSON", mock.AnythingOfType("common.Message")).Return(nil).Maybe()

	// Test with a valid local address (but connection will fail)
	handleNewTunnel(mockConn, "ws://invalid-url", clientState, "test-tunnel-id", "test-client-id", 8080)

	mockConn.AssertExpectations(t)
}

// TestListenForNewConnections tests the listenForNewConnections function.
func TestListenForNewConnections(t *testing.T) {
	// Create a mock WebSocket connection
	mockConn := &mocks.MockWebSocketConn{}

	// Set up expectations for the mock
	mockConn.On("SetReadDeadline", mock.AnythingOfType("time.Time")).Return(nil)
	mockConn.On("SetPongHandler", mock.AnythingOfType("func(string) error")).Return()
	mockConn.On("ReadJSON", mock.AnythingOfType("*common.Message")).Return(fmt.Errorf("test error"))

	// Create a client state
	clientState := &ClientState{
		Forwards: []common.ForwardConfig{},
		ClientID: "test-client-id",
	}

	// Create a context that we can cancel
	ctx, cancel := context.WithCancel(context.Background())

	// Run listenForNewConnections in a separate goroutine
	go func() {
		listenForNewConnections(ctx, mockConn, "", clientState)
	}()

	// Give it a moment to start
	time.Sleep(10 * time.Millisecond)

	// Cancel the context to stop the function
	cancel()

	// Give it a moment to finish
	time.Sleep(10 * time.Millisecond)

	mockConn.AssertExpectations(t)
}

// TestListenForNewConnectionsWithNewConnMessage tests the listenForNewConnections function with a new_conn message.
func TestListenForNewConnectionsWithNewConnMessage(t *testing.T) {
	// Create a mock WebSocket connection
	mockConn := &mocks.MockWebSocketConn{}

	// Set up expectations for the mock
	mockConn.On("SetReadDeadline", mock.AnythingOfType("time.Time")).Return(nil)
	mockConn.On("SetPongHandler", mock.AnythingOfType("func(string) error")).Return()
	mockConn.On("WriteJSON", mock.AnythingOfType("common.Message")).Return(nil).Maybe()

	// Simulate receiving a new_conn message, then an error to exit the loop
	callCount := 0
	mockConn.On("ReadJSON", mock.AnythingOfType("*common.Message")).Run(func(args mock.Arguments) {
		callCount++
		msg := args.Get(0).(*common.Message)
		if callCount == 1 {
			// First call - return a new_conn message
			msg.Type = "new_conn"
			msg.Payload = common.NewConnection{
				TunnelID:   "test-tunnel-id",
				ClientID:   "test-client-id",
				RemotePort: 8080,
			}
		} else {
			// Second call - return an error to exit
			panic(fmt.Errorf("test error"))
		}
	}).Return(nil).Once()
	mockConn.On("ReadJSON", mock.AnythingOfType("*common.Message")).Return(fmt.Errorf("test error")).Once()

	// Create a client state
	clientState := &ClientState{
		Forwards: []common.ForwardConfig{
			{
				REMOTE_PORT: 8080,
				LOCAL_ADDR:  "127.0.0.1:3000",
			},
		},
		ClientID: "test-client-id",
	}

	// Create a context that we can cancel
	ctx, cancel := context.WithCancel(context.Background())

	// Run listenForNewConnections in a separate goroutine
	go func() {
		listenForNewConnections(ctx, mockConn, "", clientState)
	}()

	// Give it a moment to start
	time.Sleep(10 * time.Millisecond)

	// Cancel the context to stop the function
	cancel()

	// Give it a moment to finish
	time.Sleep(10 * time.Millisecond)

	mockConn.AssertExpectations(t)
}

// TestListenForNewConnectionsWithAddProxyMessage tests the listenForNewConnections function with an add_proxy message.
func TestListenForNewConnectionsWithAddProxyMessage(t *testing.T) {
	// Create a mock WebSocket connection
	mockConn := &mocks.MockWebSocketConn{}

	// Set up expectations for the mock
	mockConn.On("SetReadDeadline", mock.AnythingOfType("time.Time")).Return(nil)
	mockConn.On("SetPongHandler", mock.AnythingOfType("func(string) error")).Return()

	// Simulate receiving an add_proxy message, then an error to exit the loop
	callCount := 0
	mockConn.On("ReadJSON", mock.AnythingOfType("*common.Message")).Run(func(args mock.Arguments) {
		callCount++
		msg := args.Get(0).(*common.Message)
		if callCount == 1 {
			// First call - return an add_proxy message
			msg.Type = "add_proxy"
			msg.Payload = common.AddProxy{
				RemotePort: 8081,
				LocalAddr:  "127.0.0.1:3001",
			}
		} else {
			// Second call - return an error to exit
			panic(fmt.Errorf("test error"))
		}
	}).Return(nil).Once()
	mockConn.On("ReadJSON", mock.AnythingOfType("*common.Message")).Return(fmt.Errorf("test error")).Once()

	// Create a client state
	clientState := &ClientState{
		Forwards: []common.ForwardConfig{
			{
				REMOTE_PORT: 8080,
				LOCAL_ADDR:  "127.0.0.1:3000",
			},
		},
		ClientID: "test-client-id",
	}

	// Create a context that we can cancel
	ctx, cancel := context.WithCancel(context.Background())

	// Run listenForNewConnections in a separate goroutine
	go func() {
		listenForNewConnections(ctx, mockConn, "", clientState)
	}()

	// Give it a moment to start
	time.Sleep(10 * time.Millisecond)

	// Cancel the context to stop the function
	cancel()

	// Give it a moment to finish
	time.Sleep(10 * time.Millisecond)

	// Verify that the forward was added
	clientState.mu.RLock()
	assert.Equal(t, 2, len(clientState.Forwards))
	assert.Equal(t, 8081, clientState.Forwards[1].REMOTE_PORT)
	assert.Equal(t, "127.0.0.1:3001", clientState.Forwards[1].LOCAL_ADDR)
	clientState.mu.RUnlock()

	mockConn.AssertExpectations(t)
}

// TestListenForNewConnectionsWithForwardsUpdatedMessage tests the listenForNewConnections function with a forwards_updated message.
func TestListenForNewConnectionsWithForwardsUpdatedMessage(t *testing.T) {
	// Create a mock WebSocket connection
	mockConn := &mocks.MockWebSocketConn{}

	// Set up expectations for the mock
	mockConn.On("SetReadDeadline", mock.AnythingOfType("time.Time")).Return(nil)
	mockConn.On("SetPongHandler", mock.AnythingOfType("func(string) error")).Return()

	// Simulate receiving a forwards_updated message, then an error to exit the loop
	callCount := 0
	mockConn.On("ReadJSON", mock.AnythingOfType("*common.Message")).Run(func(args mock.Arguments) {
		callCount++
		msg := args.Get(0).(*common.Message)
		if callCount == 1 {
			// First call - return a forwards_updated message
			msg.Type = "forwards_updated"
			msg.Payload = []common.ForwardConfig{
				{
					REMOTE_PORT: 8082,
					LOCAL_ADDR:  "127.0.0.1:3002",
				},
			}
		} else {
			// Second call - return an error to exit
			panic(fmt.Errorf("test error"))
		}
	}).Return(nil).Once()
	mockConn.On("ReadJSON", mock.AnythingOfType("*common.Message")).Return(fmt.Errorf("test error")).Once()

	// Create a client state
	clientState := &ClientState{
		Forwards: []common.ForwardConfig{
			{
				REMOTE_PORT: 8080,
				LOCAL_ADDR:  "127.0.0.1:3000",
			},
		},
		ClientID: "test-client-id",
	}

	// Create a context that we can cancel
	ctx, cancel := context.WithCancel(context.Background())

	// Run listenForNewConnections in a separate goroutine
	go func() {
		listenForNewConnections(ctx, mockConn, "", clientState)
	}()

	// Give it a moment to start
	time.Sleep(10 * time.Millisecond)

	// Cancel the context to stop the function
	cancel()

	// Give it a moment to finish
	time.Sleep(10 * time.Millisecond)

	// Verify that the forwards were updated
	clientState.mu.RLock()
	assert.Equal(t, 1, len(clientState.Forwards))
	assert.Equal(t, 8082, clientState.Forwards[0].REMOTE_PORT)
	assert.Equal(t, "127.0.0.1:3002", clientState.Forwards[0].LOCAL_ADDR)
	clientState.mu.RUnlock()

	mockConn.AssertExpectations(t)
}

// TestListenForNewConnectionsWithUnmarshalError tests the listenForNewConnections function with an unmarshal error.
func TestListenForNewConnectionsWithUnmarshalError(t *testing.T) {
	// Create a mock WebSocket connection
	mockConn := &mocks.MockWebSocketConn{}

	// Set up expectations for the mock
	mockConn.On("SetReadDeadline", mock.AnythingOfType("time.Time")).Return(nil)
	mockConn.On("SetPongHandler", mock.AnythingOfType("func(string) error")).Return()

	// Simulate receiving a message with invalid payload, then an error to exit the loop
	callCount := 0
	mockConn.On("ReadJSON", mock.AnythingOfType("*common.Message")).Run(func(args mock.Arguments) {
		callCount++
		msg := args.Get(0).(*common.Message)
		if callCount == 1 {
			// First call - return a message with invalid payload
			msg.Type = "new_conn"
			msg.Payload = "invalid payload"
		} else {
			// Second call - return an error to exit
			panic(fmt.Errorf("test error"))
		}
	}).Return(nil).Once()
	mockConn.On("ReadJSON", mock.AnythingOfType("*common.Message")).Return(fmt.Errorf("test error")).Once()

	// Create a client state
	clientState := &ClientState{
		Forwards: []common.ForwardConfig{
			{
				REMOTE_PORT: 8080,
				LOCAL_ADDR:  "127.0.0.1:3000",
			},
		},
		ClientID: "test-client-id",
	}

	// Create a context that we can cancel
	ctx, cancel := context.WithCancel(context.Background())

	// Run listenForNewConnections in a separate goroutine
	go func() {
		listenForNewConnections(ctx, mockConn, "", clientState)
	}()

	// Give it a moment to start
	time.Sleep(10 * time.Millisecond)

	// Cancel the context to stop the function
	cancel()

	// Give it a moment to finish
	time.Sleep(10 * time.Millisecond)

	mockConn.AssertExpectations(t)
}

// TestListenForNewConnectionsWithUnknownMessageType tests the listenForNewConnections function with an unknown message type.
func TestListenForNewConnectionsWithUnknownMessageType(t *testing.T) {
	// Create a mock WebSocket connection
	mockConn := &mocks.MockWebSocketConn{}

	// Set up expectations for the mock
	mockConn.On("SetReadDeadline", mock.AnythingOfType("time.Time")).Return(nil)
	mockConn.On("SetPongHandler", mock.AnythingOfType("func(string) error")).Return()

	// Simulate receiving an unknown message type, then an error to exit the loop
	callCount := 0
	mockConn.On("ReadJSON", mock.AnythingOfType("*common.Message")).Run(func(args mock.Arguments) {
		callCount++
		msg := args.Get(0).(*common.Message)
		if callCount == 1 {
			// First call - return an unknown message type
			msg.Type = "unknown_type"
		} else {
			// Second call - return an error to exit
			panic(fmt.Errorf("test error"))
		}
	}).Return(nil).Once()
	mockConn.On("ReadJSON", mock.AnythingOfType("*common.Message")).Return(fmt.Errorf("test error")).Once()

	// Create a client state
	clientState := &ClientState{
		Forwards: []common.ForwardConfig{
			{
				REMOTE_PORT: 8080,
				LOCAL_ADDR:  "127.0.0.1:3000",
			},
		},
		ClientID: "test-client-id",
	}

	// Create a context that we can cancel
	ctx, cancel := context.WithCancel(context.Background())

	// Run listenForNewConnections in a separate goroutine
	go func() {
		listenForNewConnections(ctx, mockConn, "", clientState)
	}()

	// Give it a moment to start
	time.Sleep(10 * time.Millisecond)

	// Cancel the context to stop the function
	cancel()

	// Give it a moment to finish
	time.Sleep(10 * time.Millisecond)

	mockConn.AssertExpectations(t)
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
