package client

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gemini-cli/tmproxy/common"
	"github.com/gorilla/websocket"
)

// ClientState holds the dynamic state of the client's forwarding configuration.
type ClientState struct {
	mu         sync.RWMutex
	LocalAddr  string
	RemotePort int
}

// Run starts the client mode of the application.
// It parses command-line arguments, connects to the server, and handles the proxying.
func Run(args []string) {
	// Define and parse command-line flags.
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	serverAddr := fs.String("server", "", "Server WebSocket URL (e.g., ws://localhost:8001/proxy_ws)")
	localAddr := fs.String("local", "localhost:3000", "Local service address to expose")
	remotePort := fs.Int("remote", 8080, "Requested public port on the server")
	totpSecret := fs.String("totp-secret", "", "TOTP secret key for long-term authentication")
	controlByServer := fs.Bool("control-by-server", false, "Let the server control local and remote addresses")
	fs.Parse(args)

	if *serverAddr == "" {
		log.Fatal("Server URL is required. Use the --server flag.")
	}

	clientState := &ClientState{
		LocalAddr:  *localAddr,
		RemotePort: *remotePort,
	}

	// Prompt for the TOTP token if no secret is provided.
	token := ""
	if *totpSecret == "" {
		fmt.Print("Enter 6-digit TOTP token: ")
		reader := bufio.NewReader(os.Stdin)
		readToken, _ := reader.ReadString('\n')
		token = strings.TrimSpace(readToken)
	}

	// Establish the main control connection.
	controlConn, _, err := websocket.DefaultDialer.Dial(*serverAddr, nil)
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	// Removed defer controlConn.Close() from here

	// Set up a channel to listen for OS signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Println("Connected to server. Authenticating...")

	// Authenticate with the server.
	if err := authenticate(controlConn, token, *totpSecret); err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	log.Println("Authentication successful.")

	// Request the proxy to be set up if not controlled by server.
	if !*controlByServer {
		log.Printf("Sending proxy request for local service %s...", clientState.LocalAddr)
		if err := requestProxy(controlConn, clientState.RemotePort); err != nil {
			log.Fatalf("Failed to request proxy: %v", err)
		}
		log.Printf("Proxy requested for local service %s. Waiting for connections...", clientState.LocalAddr)
	} else {
		log.Println("Client is controlled by server. Waiting for server to assign forwarding targets...")
	}

	// Use a context to manage the lifecycle of the listenForNewConnections goroutine
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		listenForNewConnections(ctx, controlConn, *serverAddr, clientState, *controlByServer)
	}()

	// Wait for a signal to gracefully shut down
	select {
	case sig := <-sigChan:
		log.Printf("Received signal %v. Shutting down client gracefully...", sig)
		cancel() // Signal the listenForNewConnections goroutine to stop
		// Wait for the listenForNewConnections goroutine to finish
		wg.Wait()
	}

	log.Println("Client shutdown complete.")
}

// authenticate sends the TOTP token to the server and waits for a successful response.
func authenticate(conn *websocket.Conn, token, totpSecret string) error {
	// If a TOTP secret is provided, generate the token from it.
	if totpSecret != "" {
		generatedToken, err := common.GenerateTOTP(totpSecret)
		if err != nil {
			return fmt.Errorf("failed to generate TOTP token from secret: %w", err)
		}
		token = generatedToken
	}

	// Send authentication request.
	req := common.Message{Type: "auth_request", Payload: common.AuthRequest{Token: token}}
	if err := conn.WriteJSON(req); err != nil {
		return fmt.Errorf("failed to send auth request: %w", err)
	}

	// Wait for authentication response.
	var resp common.Message
	if err := conn.ReadJSON(&resp); err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp.Type != "auth_response" {
		return fmt.Errorf("unexpected message type: %s", resp.Type)
	}

	// Unmarshal the payload into an AuthResponse struct.
	var authResp common.AuthResponse
	payloadBytes, _ := json.Marshal(resp.Payload)
	json.Unmarshal(payloadBytes, &authResp)

	if !authResp.Success {
		return fmt.Errorf("server rejected authentication: %s", authResp.Message)
	}

	return nil
}

// requestProxy sends a request to the server to open a public port.
func requestProxy(conn *websocket.Conn, remotePort int) error {
	req := common.Message{Type: "proxy_request", Payload: common.ProxyRequest{RemotePort: remotePort}}
	if err := conn.WriteJSON(req); err != nil {
		return fmt.Errorf("failed to send proxy request: %w", err)
	}

	// Wait for proxy response.
	var resp common.Message
	if err := conn.ReadJSON(&resp); err != nil {
		return fmt.Errorf("failed to read proxy response: %w", err)
	}

	if resp.Type != "proxy_response" {
		return fmt.Errorf("unexpected message type: %s", resp.Type)
	}

	var proxyResp common.ProxyResponse
	payloadBytes, _ := json.Marshal(resp.Payload)
	json.Unmarshal(payloadBytes, &proxyResp)

	if !proxyResp.Success {
		return fmt.Errorf("server failed to set up proxy: %s", proxyResp.Message)
	}

	log.Printf("Server confirmed proxy. Public URL: %s", proxyResp.PublicURL)
	return nil
}

// listenForNewConnections waits for `new_conn` messages and spawns goroutines to handle them.
func listenForNewConnections(ctx context.Context, controlConn *websocket.Conn, serverAddr string, state *ClientState, controlByServer bool) {
	msgChan := make(chan common.Message)
	errChan := make(chan error, 1)

	const readTimeout = 30 * time.Second
	const pingInterval = (readTimeout * 9) / 10 // Ping more frequently than timeout

	// Set a pong handler to extend the read deadline upon receiving a pong.
	controlConn.SetReadDeadline(time.Now().Add(readTimeout))
	controlConn.SetPongHandler(func(string) error {
		controlConn.SetReadDeadline(time.Now().Add(readTimeout))
		return nil
	})

	// Goroutine to continuously read messages from the control connection.
	go func() {
		defer close(errChan)
		for {
			select {
			case <-ctx.Done():
				return // Exit if context is cancelled.
			default:
			}

			var msg common.Message
			// ReadJSON will be interrupted by pongs, which reset the deadline via the pong handler.
			// A timeout error here means the connection is genuinely stale.
			if err := controlConn.ReadJSON(&msg); err != nil {
				// Avoid logging an error if the context was cancelled during the read.
				select {
				case <-ctx.Done():
					errChan <- nil // Signal graceful shutdown
				default:
					errChan <- err // Signal a real error
				}
				return
			}
			msgChan <- msg
		}
	}()

	// Goroutine to send pings to keep the connection alive.
	go func() {
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Use WriteControl for ping messages. It's safe for concurrent use.
				deadline := time.Now().Add(5 * time.Second)
				if err := controlConn.WriteControl(websocket.PingMessage, nil, deadline); err != nil {
					log.Printf("Pinger: Failed to send ping: %v", err)
					// The read goroutine will eventually time out and report the connection error.
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Main loop to process messages and errors.
	for {
		select {
		case <-ctx.Done():
			log.Println("listenForNewConnections: Context cancelled. Shutting down.")
			// Attempt a clean close of the websocket connection.
			// The error is ignored as we are shutting down anyway.
			controlConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			return
		case err := <-errChan:
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					log.Printf("Control connection read timeout (no pong received): %v. Closing connection.", err)
				} else if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					log.Printf("Control connection closed gracefully: %v.", err)
				} else if err == io.EOF {
					log.Println("Control connection closed by peer (EOF).")
				} else {
					log.Printf("Error reading from control connection: %v.", err)
				}
			}
			return
		case msg := <-msgChan:
			// Process application-level messages.
			switch msg.Type {
			case "new_conn":
				var newConnPayload common.NewConnection
				payloadBytes, _ := json.Marshal(msg.Payload)
				json.Unmarshal(payloadBytes, &newConnPayload)

				log.Printf("Received new connection request for tunnel: %s (Client ID: %s)", newConnPayload.TunnelID, newConnPayload.ClientID)
				state.mu.RLock()
				go handleNewTunnel(controlConn, serverAddr, state, newConnPayload.TunnelID, newConnPayload.ClientID)
				state.mu.RUnlock()
			case "update_forwarding":
				if controlByServer {
					var updatePayload common.UpdateForwarding
					payloadBytes, _ := json.Marshal(msg.Payload)
					json.Unmarshal(payloadBytes, &updatePayload)

					state.mu.Lock()
					state.LocalAddr = fmt.Sprintf("%s:%d", updatePayload.RemoteHost, updatePayload.RemotePort)
					state.RemotePort = updatePayload.RemotePort
					state.mu.Unlock()
					log.Printf("Server updated forwarding target to: %s", state.LocalAddr)
				} else {
					log.Println("Received update_forwarding message but client is not in server-controlled mode.")
				}
			default:
				log.Printf("Received unknown message type: %s", msg.Type)
			}
		}
	}
}

// handleNewTunnel connects to the local service and establishes a new data WebSocket connection.
func handleNewTunnel(controlConn *websocket.Conn, serverAddr string, state *ClientState, tunnelID string, clientID string) {
	state.mu.RLock()
	currentLocalAddr := state.LocalAddr
	state.mu.RUnlock()

	// Connect to the local service.
	localConn, err := net.Dial("tcp", currentLocalAddr)
	if err != nil {
		log.Printf("Failed to connect to local service at %s: %v", currentLocalAddr, err)
		// Notify the server that the local connection failed.
		msg := common.Message{Type: "local_connect_failed", Payload: common.LocalConnectFailed{TunnelID: tunnelID}}
		if err := controlConn.WriteJSON(msg); err != nil {
			log.Printf("Failed to send local connect failed message to server: %v", err)
		}
		return
	}
	defer localConn.Close()

	log.Printf("[%s] Connected to local service %s. Establishing data tunnel...", tunnelID, currentLocalAddr)

	// Construct the data tunnel URL with the tunnel ID and client ID.
	u, _ := url.Parse(serverAddr)
	dataURL := fmt.Sprintf("%s?tunnel_id=%s&client_id=%s", u.String(), tunnelID, clientID)

	// Establish the data WebSocket connection.
	dataConn, _, err := websocket.DefaultDialer.Dial(dataURL, nil)
	if err != nil {
		log.Printf("[%s] Failed to establish data tunnel: %v", tunnelID, err)
		return
	}
	defer dataConn.Close()

	log.Printf("[%s] Data tunnel established. Proxying data...", tunnelID)

	// Start proxying data between the local service and the data tunnel.
	common.Proxy(localConn, dataConn)

	log.Printf("[%s] Tunnel closed.", tunnelID)
}
