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