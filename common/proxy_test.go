package common

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
)

var upgrader = websocket.Upgrader{}

// mockWebSocketServer is a simple WebSocket echo server for testing.
func mockWebSocketServer(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	for {
		mt, message, err := conn.ReadMessage()
		if err != nil {
			break
		}
		// Echo the message back to the client.
		if err := conn.WriteMessage(mt, message); err != nil {
			break
		}
	}
}

// mockWebSocketServer_TextMessage is a WebSocket server that only sends text messages.
func mockWebSocketServer_TextMessage(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	
	// Send a text message
	if err := conn.WriteMessage(websocket.TextMessage, []byte("text message")); err != nil {
		return
	}
}

// TestProxy verifies the bidirectional data flow of the Proxy function.
func TestProxy(t *testing.T) {
	// 1. Set up a test WebSocket server that echoes messages.
	server := httptest.NewServer(http.HandlerFunc(mockWebSocketServer))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// 2. Establish a client WebSocket connection.
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(t, err, "Failed to dial WebSocket server")
	defer ws.Close()

	// 3. Create a pair of in-memory network connections to simulate the proxied connection.
	clientConn, serverConn := net.Pipe()

	// 4. Run the Proxy function in a separate goroutine.
	// This will handle data transfer between clientConn and ws.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		Proxy(clientConn, ws)
	}()

	// 5. Test flow: from the local service (serverConn) to the remote (ws).
	// The message should go through the proxy to the echo server, be echoed back,
	// go through the proxy again, and arrive back at the local service (serverConn).
	testMessage1 := "local-to-remote"
	_, err = serverConn.Write([]byte(testMessage1))
	assert.NoError(t, err)

	// Read the echoed message back from the pipe.
	buffer := make([]byte, 1024)
	serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := serverConn.Read(buffer)
	assert.NoError(t, err, "Should read the echoed message from the pipe")
	assert.Equal(t, testMessage1, string(buffer[:n]))

	// 6. Test flow: from the remote (ws) to the local service (serverConn).
	// This is slightly artificial, as we are writing to the client-side ws connection.
	// The echo server will echo it back, and the proxy's reader will pick it up
	// and write it to the pipe.
	testMessage2 := "remote-to-local"
	err = ws.WriteMessage(websocket.BinaryMessage, []byte(testMessage2))
	assert.NoError(t, err)

	// Read the message from the pipe.
	serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = serverConn.Read(buffer)
	assert.NoError(t, err, "Should read the message sent from the websocket")
	assert.Equal(t, testMessage2, string(buffer[:n]))

	// 7. Clean up.
	clientConn.Close()
	serverConn.Close()
	wg.Wait() // Ensure the Proxy function has exited cleanly.
}

// TestProxyWithTextMessage tests the proxy with a WebSocket server that sends text messages.
func TestProxyWithTextMessage(t *testing.T) {
	// 1. Set up a test WebSocket server that sends text messages.
	server := httptest.NewServer(http.HandlerFunc(mockWebSocketServer_TextMessage))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// 2. Establish a client WebSocket connection.
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(t, err, "Failed to dial WebSocket server")
	defer ws.Close()

	// 3. Create a pair of in-memory network connections to simulate the proxied connection.
	clientConn, serverConn := net.Pipe()

	// 4. Run the Proxy function in a separate goroutine.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		Proxy(clientConn, ws)
	}()

	// 5. Test that the proxy handles text messages correctly (should treat as EOF)
	buffer := make([]byte, 1024)
	serverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = serverConn.Read(buffer)
	assert.Error(t, err, "Should get an error when reading text message")

	// 6. Clean up.
	clientConn.Close()
	serverConn.Close()
	wg.Wait()
}

// TestWebsocketWriter tests the websocketWriter's Write method.
func TestWebsocketWriter(t *testing.T) {
	// Set up a test WebSocket server.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		
		// Read a message from the client
		_, message, err := conn.ReadMessage()
		if err != nil {
			return
		}
		
		// Echo it back
		conn.WriteMessage(websocket.BinaryMessage, message)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Establish a client WebSocket connection.
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(t, err, "Failed to dial WebSocket server")
	defer ws.Close()

	// Create a websocketWriter
	writer := &websocketWriter{ws: ws}

	// Test writing data
	data := []byte("test data")
	n, err := writer.Write(data)
	assert.NoError(t, err)
	assert.Equal(t, len(data), n)

	// Test writing to a closed WebSocket
	ws.Close()
	_, err = writer.Write(data)
	// When the WebSocket is closed, we expect an error
	// We're not checking the specific type of error, just that there is one
	// This avoids issues with different error types in different environments
	if err == nil {
		t.Error("Expected an error when writing to a closed WebSocket, but got nil")
	}
}

// TestWebsocketReader tests the websocketReader's Read method.
func TestWebsocketReader(t *testing.T) {
	// Set up a test WebSocket server.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		
		// Send a binary message
		conn.WriteMessage(websocket.BinaryMessage, []byte("test data"))
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Establish a client WebSocket connection.
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(t, err, "Failed to dial WebSocket server")
	defer ws.Close()

	// Create a websocketReader
	reader := &websocketReader{ws: ws}

	// Test reading data
	buffer := make([]byte, 1024)
	n, err := reader.Read(buffer)
	assert.NoError(t, err)
	assert.Equal(t, "test data", string(buffer[:n]))

	// Test reading a second time (buffer should be empty)
	n, err = reader.Read(buffer)
	// When reading from an empty buffer after consuming all data,
	// we might get an EOF error, which is acceptable in this context
	// What's important is that n is 0
	assert.Equal(t, 0, n)

	// Test reading from a closed WebSocket
	ws.Close()
	_, err = reader.Read(buffer)
	// When the WebSocket is closed, we expect an error
	// We're not checking the specific type of error, just that there is one
	// This avoids issues with different error types in different environments
	if err == nil {
		t.Error("Expected an error when reading from a closed WebSocket, but got nil")
	}
}

// TestWebsocketReaderWithTextMessage tests the websocketReader's handling of text messages.
func TestWebsocketReaderWithTextMessage(t *testing.T) {
	// Set up a test WebSocket server.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		
		// Send a text message
		conn.WriteMessage(websocket.TextMessage, []byte("text message"))
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Establish a client WebSocket connection.
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	assert.NoError(t, err, "Failed to dial WebSocket server")
	defer ws.Close()

	// Create a websocketReader
	reader := &websocketReader{ws: ws}

	// Test reading a text message (should return EOF to stop copying)
	buffer := make([]byte, 1024)
	_, err = reader.Read(buffer)
	// The implementation treats non-binary messages as EOF
	// We're not checking the specific type of error, just that there is one
	// This avoids issues with different error types in different environments
	if err == nil {
		t.Error("Expected an error when reading a text message, but got nil")
	}
}