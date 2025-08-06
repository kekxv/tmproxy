package common

import (
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Proxy copies data between a standard network connection and a WebSocket connection.
// It runs two goroutines to handle bidirectional data flow and waits for both to complete.
func Proxy(conn net.Conn, ws *websocket.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	var once sync.Once
	closeConns := func() {
		conn.Close()
		ws.Close()
		log.Printf("Proxy for %s and %s closed.", conn.RemoteAddr(), ws.RemoteAddr())
	}

	// Goroutine to copy data from the network connection to the WebSocket.
	go func() {
		defer wg.Done()
		defer once.Do(closeConns)
		// Create a custom writer for the WebSocket connection.
		wsWriter := &websocketWriter{ws: ws}
		// Set read deadline for the network connection
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		// Set write deadline for the WebSocket connection
		ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.Copy(wsWriter, conn); err != nil {
			log.Printf("Error copying from network to WebSocket: %v", err)
		}
		conn.SetReadDeadline(time.Time{}) // Clear deadline
		ws.SetWriteDeadline(time.Time{})  // Clear deadline
	}()

	// Goroutine to copy data from the WebSocket to the network connection.
	go func() {
		defer wg.Done()
		defer once.Do(closeConns)
		// Create a custom reader for the WebSocket connection.
		wsReader := &websocketReader{ws: ws}
		// Set read deadline for the WebSocket connection
		ws.SetReadDeadline(time.Now().Add(5 * time.Second))
		// Set write deadline for the network connection
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.Copy(conn, wsReader); err != nil {
			log.Printf("Error copying from WebSocket to network: %v", err)
		}
		ws.SetReadDeadline(time.Time{})    // Clear deadline
		conn.SetWriteDeadline(time.Time{}) // Clear deadline
	}()

	wg.Wait()
}

// websocketWriter is an io.Writer that writes to a WebSocket connection.
type websocketWriter struct {
	ws *websocket.Conn
}

func (w *websocketWriter) Write(p []byte) (n int, err error) {
	if err := w.ws.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// websocketReader is an io.Reader that reads from a WebSocket connection.
type websocketReader struct {
	ws *websocket.Conn
	// Buffer to hold data read from the WebSocket.
	// This is needed because ReadMessage reads a whole message at once.
	buffer []byte
}

func (r *websocketReader) Read(p []byte) (n int, err error) {
	// If buffer is empty, read a new message from WebSocket.
	if len(r.buffer) == 0 {
		msgType, msg, err := r.ws.ReadMessage()
		if err != nil {
			// Treat any error from ReadMessage as a signal to terminate the read operation.
			// This ensures io.Copy exits when the WebSocket connection is closed or encounters an issue.
			log.Printf("Error reading WebSocket message: %v", err)
			return 0, io.EOF
		}
		// Only process binary messages for data transfer.
		if msgType == websocket.BinaryMessage {
			r.buffer = msg
		} else {
			// Skip non-binary messages or handle them as needed.
			return 0, io.EOF // Treat as end of file for non-binary messages
		}
	}

	// Copy from internal buffer to p.
	n = copy(p, r.buffer)
	r.buffer = r.buffer[n:] // Advance the buffer
	return n, nil
}
