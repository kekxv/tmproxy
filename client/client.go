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

// WebSocketConn interface abstracts the websocket.Conn methods we use
type WebSocketConn interface {
	WriteJSON(v interface{}) error
	ReadJSON(v interface{}) error
	Close() error
	WriteMessage(messageType int, data []byte) error
	ReadMessage() (messageType int, p []byte, err error)
	SetReadDeadline(t time.Time) error
	SetPongHandler(h func(appData string) error)
	WriteControl(messageType int, data []byte, deadline time.Time) error
	RemoteAddr() net.Addr
}

const (
	reconnectDelay = 5 * time.Second
	readTimeout    = 30 * time.Second
	pingInterval   = (readTimeout * 9) / 10 // Ping more frequently than timeout
)

// ClientState holds the dynamic state of the client's forwarding configuration.
type ClientState struct {
	mu       sync.RWMutex
	Forwards []common.ForwardConfig // Array of forward configurations
	ClientID string                 // Client's unique ID, assigned by server
}

// Run starts the client mode of the application.
// It parses command-line arguments, connects to the server, handles the proxying,
// and implements an auto-reconnect mechanism.
func Run(args []string) {
	// Define and parse command-line flags.
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	configFile := fs.String("config", "config.json", "Path to the configuration file")
	serverAddr := fs.String("server", "", "Server WebSocket URL (e.g., ws://localhost:8001/proxy_ws)")
	proxyUser := fs.String("proxy_user", "", "Proxy username for authentication")
	proxyPasswd := fs.String("proxy_passwd", "", "Proxy password for authentication")
	localAddr := fs.String("local", "", "Local address to forward to (e.g., localhost:3000)")
	remotePort := fs.Int("remote", 0, "Remote port to listen on")

	totpSecret := fs.String("totp-secret", "", "TOTP secret key for long-term authentication")
	fs.Parse(args)

	// Load configuration from file if it exists
	var config *common.ClientConfig
	if _, err := os.Stat(*configFile); err == nil {
		config, err = common.LoadClientConfig(*configFile)
		if err != nil {
			log.Printf("Warning: Failed to load config file: %v", err)
		}
	} else {
		log.Printf("Config file '%s' not found, using command line arguments only.", *configFile)
	}

	// Command line arguments take precedence over config file
	if *serverAddr == "" {
		if config != nil && config.ServerAddr != "" {
			*serverAddr = config.ServerAddr
		} else {
			log.Fatal("Server URL is required. Use the --server flag or define it in the config file.")
		}
	}

	// Use config values if command line arguments are not provided
	if *proxyUser == "" && config != nil && config.ProxyUser != "" {
		*proxyUser = config.ProxyUser
	}
	if *proxyPasswd == "" && config != nil && config.ProxyPasswd != "" {
		*proxyPasswd = config.ProxyPasswd
	}
	if *totpSecret == "" && config != nil && config.TOTPSecretKey != "" {
		*totpSecret = config.TOTPSecretKey
	}

	clientState := &ClientState{
		Forwards: []common.ForwardConfig{},
		ClientID: "", // Initialize with empty ID
	}

	// If local and remote are provided, add them to the forwards list
	if *localAddr != "" && *remotePort != 0 {
		clientState.Forwards = append(clientState.Forwards, common.ForwardConfig{LOCAL_ADDR: *localAddr, REMOTE_PORT: *remotePort})
	}

	// Prompt for the TOTP token if no secret is provided. This is done once.
	token := ""
	if *totpSecret == "" {
		fmt.Print("Enter 6-digit TOTP token: ")
		reader := bufio.NewReader(os.Stdin)
		readToken, _ := reader.ReadString('\n')
		token = strings.TrimSpace(readToken)
	}

	// Set up a context to manage graceful shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Goroutine to handle OS signals.
	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v. Shutting down client gracefully...", sig)
		cancel()
	}()

	// Main reconnection loop.
	for {
		// Check for shutdown signal before attempting to connect.
		select {
		case <-ctx.Done():
			log.Println("Client shutdown complete.")
			return
		default:
		}

		log.Printf("Attempting to connect to server at %s...", *serverAddr)
		controlConn, _, err := websocket.DefaultDialer.Dial(*serverAddr, nil)
		if err != nil {
			log.Printf("Failed to connect to server: %v. Retrying in %v...", err, reconnectDelay)
			timer := time.NewTimer(reconnectDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}

		log.Println("Connected to server. Authenticating...")
		// Pass clientState.ClientID to authenticate and update it from the response
		newClientID, err := authenticate(controlConn, token, *totpSecret, clientState.ClientID, *proxyUser, *proxyPasswd, clientState)
		if err != nil {
			log.Printf("Authentication failed: %v", err)
			// If the server explicitly rejected the authentication (e.g., bad token), exit.
			if strings.Contains(err.Error(), "server rejected authentication") {
				log.Println("Exiting due to authentication rejection.")
				controlConn.Close()
				return
			}
			// For other auth errors (e.g., network issues), retry.
			log.Println("Retrying in 5 seconds...")
			controlConn.Close()
			timer := time.NewTimer(reconnectDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}
		clientState.ClientID = newClientID

		log.Println("Authentication successful.")

		// Request proxy for each forward config
		for _, forward := range clientState.Forwards {
			if err := requestProxy(controlConn, forward.REMOTE_PORT, forward.LOCAL_ADDR, clientState.ClientID); err != nil {
				log.Printf("Failed to request proxy for %s:%d: %v", forward.LOCAL_ADDR, forward.REMOTE_PORT, err)
			}
		}

		// This function blocks until the connection is lost or the context is cancelled.
		listenForNewConnections(ctx, controlConn, *serverAddr, clientState)

		// After listenForNewConnections returns, the connection is considered lost.
		controlConn.Close()

		// Check if the shutdown was initiated by a signal. If not, it was a connection loss.
		select {
		case <-ctx.Done():
			// Context was cancelled, the loop will terminate on the next iteration.

		default:
			log.Printf("Connection to server lost. Attempting to reconnect in %v...", reconnectDelay)
			timer := time.NewTimer(reconnectDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
}

// authenticate sends the TOTP token and ClientID to the server and waits for a successful response.
func authenticate(conn WebSocketConn, token, totpSecret, clientID, proxyUser, proxyPasswd string, state *ClientState) (string, error) {
	// If a TOTP secret is provided, generate the token from it.
	if totpSecret != "" {
		generatedToken, err := common.GenerateTOTP(totpSecret)
		if err != nil {
			return "", fmt.Errorf("failed to generate TOTP token from secret: %w", err)
		}
		token = generatedToken
	}

	// Send authentication request.
	req := common.Message{Type: "auth_request", Payload: common.AuthRequest{Token: token, ClientID: clientID, ProxyUser: proxyUser, ProxyPasswd: proxyPasswd}}
	if err := conn.WriteJSON(req); err != nil {
		return "", fmt.Errorf("failed to send auth request: %w", err)
	}

	// Wait for authentication response.
	var resp common.Message
	if err := conn.ReadJSON(&resp); err != nil {
		return "", fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp.Type != "auth_response" {
		return "", fmt.Errorf("unexpected message type: %s", resp.Type)
	}

	// Unmarshal the payload into an AuthResponse struct.
	var authResp common.AuthResponse
	payloadBytes, _ := json.Marshal(resp.Payload)
	json.Unmarshal(payloadBytes, &authResp)

	if !authResp.Success {
		return "", fmt.Errorf("server rejected authentication: %s", authResp.Message)
	}

	// Update client's forwards with data from server
	state.mu.Lock()
	state.Forwards = authResp.Forwards
	state.mu.Unlock()

	return authResp.ClientID, nil
}

// requestProxy sends a request to the server to open a public port.
func requestProxy(conn WebSocketConn, remotePort int, localAddr string, clientID string) error {
	req := common.Message{Type: "proxy_request", Payload: common.ProxyRequest{RemotePort: remotePort, LocalAddr: localAddr, ClientID: clientID}}
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

// listenForNewConnections waits for messages from the server and handles them.
func listenForNewConnections(ctx context.Context, controlConn WebSocketConn, serverAddr string, state *ClientState) {
	msgChan := make(chan common.Message)
	errChan := make(chan error, 1)

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
			if err := controlConn.ReadJSON(&msg); err != nil {
				select {
				case <-ctx.Done():
					errChan <- nil // Graceful shutdown
				default:
					errChan <- err // Real error
				}
				return
			}
			msgChan <- msg
		}
	}()

	// 使用 Pinger 替代内联的 ping goroutine，使得在断开/重连时可以可靠停止旧定时任务。
	p := NewPinger(pingInterval)
	// 在本函数返回时确保停止 pinger，避免残留定时任务写入已关闭的连接。
	defer p.Stop()
	p.Start(controlConn)

	// Main loop to process messages and errors.
	for {
		select {
		case <-ctx.Done():
			log.Println("listenForNewConnections: Context cancelled. Shutting down.")
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
			switch msg.Type {
			case "new_conn":
				var newConnPayload common.NewConnection
				if err := unmarshalPayload(msg.Payload, &newConnPayload); err != nil {
					log.Printf("Error unmarshalling new_conn payload: %v", err)
					continue
				}

				log.Printf("Received new connection for remote port %d -> tunnel %s", newConnPayload.RemotePort, newConnPayload.TunnelID)
				go handleNewTunnel(controlConn, serverAddr, state, newConnPayload.TunnelID, state.ClientID, newConnPayload.RemotePort)

			case "add_proxy":
				var addProxyPayload common.AddProxy
				if err := unmarshalPayload(msg.Payload, &addProxyPayload); err != nil {
					log.Printf("Error unmarshalling add_proxy payload: %v", err)
					continue
				}

				state.mu.Lock()
				// Check if the forward already exists and if the local address has changed
				found := false
				for i, forward := range state.Forwards {
					if forward.REMOTE_PORT == addProxyPayload.RemotePort {
						state.Forwards[i].LOCAL_ADDR = addProxyPayload.LocalAddr
						found = true
						break
					}
				}
				if !found {
					state.Forwards = append(state.Forwards, common.ForwardConfig{REMOTE_PORT: addProxyPayload.RemotePort, LOCAL_ADDR: addProxyPayload.LocalAddr})
				}
				state.mu.Unlock()
				log.Printf("Dynamically added new forward: remote port %d -> local %s", addProxyPayload.RemotePort, addProxyPayload.LocalAddr)

			case "forwards_updated": // Handle updated forwards from server
				var updatedForwards []common.ForwardConfig
				if err := unmarshalPayload(msg.Payload, &updatedForwards); err != nil {
					log.Printf("Error unmarshalling forwards_updated payload: %v", err)
					continue
				}
				state.mu.Lock()
				state.Forwards = updatedForwards
				state.mu.Unlock()
				log.Printf("Client received updated forwards from server: %+v", updatedForwards)

			case "http_request":
				var req common.HttpRequest
				if err := unmarshalPayload(msg.Payload, &req); err != nil {
					log.Printf("Error unmarshalling http_request payload: %v", err)
					continue
				}
				go handleHttpRequest(controlConn, &req)

			case "connect_request":
				var req common.ConnectRequest
				if err := unmarshalPayload(msg.Payload, &req); err != nil {
					log.Printf("Error unmarshalling connect_request payload: %v", err)
					continue
				}
				go handleConnectRequest(controlConn, serverAddr, state.ClientID, &req)

			default:
				log.Printf("Received unknown message type: %s", msg.Type)
			}
		}
	}
}

// unmarshalPayload is a helper function to decode a message payload into a struct.
func unmarshalPayload(payload interface{}, v interface{}) error {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}
	if err := json.Unmarshal(payloadBytes, v); err != nil {
		return fmt.Errorf("failed to unmarshal payload: %w", err)
	}
	return nil
}

// handleNewTunnel connects to the local service and establishes a new data WebSocket connection.
func handleNewTunnel(controlConn WebSocketConn, serverAddr string, state *ClientState, tunnelID string, clientID string, remotePort int) {
	if controlConn == nil {
		log.Printf("[%s] controlConn is nil, cannot handle new tunnel.", tunnelID)
		return
	}
	state.mu.RLock()
	var localAddr string
	var found bool
	for _, forward := range state.Forwards {
		if forward.REMOTE_PORT == remotePort {
			localAddr = forward.LOCAL_ADDR
			found = true
			break
		}
	}
	state.mu.RUnlock()

	if !found {
		log.Printf("[%s] No local address configured for remote port %d", tunnelID, remotePort)
		return
	}

	// Connect to the local service.
	localConn, err := net.Dial("tcp", localAddr)
	if err != nil {
		log.Printf("Failed to connect to local service at %s: %v", localAddr, err)
		msg := common.Message{Type: "local_connect_failed", Payload: common.LocalConnectFailed{TunnelID: tunnelID}}
		if err := controlConn.WriteJSON(msg); err != nil {
			log.Printf("Failed to send local connect failed message to server: %v", err)
		}
		return
	}
	defer localConn.Close()

	log.Printf("[%s] Connected to local service %s. Establishing data tunnel...", tunnelID, localAddr)

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
