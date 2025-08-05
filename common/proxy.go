package common

import (
	"io"
	"log"
	"net"

	"github.com/gorilla/websocket"
)

// Proxy copies data between a standard network connection and a WebSocket connection.
// It runs two goroutines to handle bidirectional data flow and waits for both to complete.
func Proxy(conn net.Conn, ws *websocket.Conn) {
	// Use a channel to signal when one of the copy operations is finished.
	done := make(chan struct{})

	// Goroutine to copy data from the network connection to the WebSocket.
	go func() {
		defer func() {
			conn.Close()
			ws.Close()
			close(done) // Signal completion.
		}()

		// Buffer to hold data read from the network connection.
		buffer := make([]byte, 32*1024) // 32KB buffer
		for {
			n, err := conn.Read(buffer)
			if err != nil {
				if err != io.EOF {
					log.Printf("Error reading from source connection: %v", err)
				}
				return
			}
			// Write the data as a binary message to the WebSocket.
			if err := ws.WriteMessage(websocket.BinaryMessage, buffer[:n]); err != nil {
				log.Printf("Error writing to WebSocket: %v", err)
				return
			}
		}
	}()

	// Goroutine to copy data from the WebSocket to the network connection.
	go func() {
		defer func() {
			conn.Close()
			ws.Close()
		}()

		for {
			// Read a message from the WebSocket.
			msgType, p, err := ws.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					log.Printf("WebSocket closed unexpectedly: %v", err)
				}
				return
			}

			// We only care about binary messages for data transfer.
			if msgType == websocket.BinaryMessage {
				// Write the received payload to the network connection.
				if _, err := conn.Write(p); err != nil {
					log.Printf("Error writing to destination connection: %v", err)
					return
				}
			}
		}
	}()

	// Wait for the first goroutine to finish. The second will exit shortly after.
	<-done
}
