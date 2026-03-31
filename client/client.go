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
	pingInterval = (common.ReadTimeout * 9) / 10 // Ping more frequently than timeout
)

// ConnInfo represents an active connection's metadata.
type ConnInfo struct {
	ID          string    `json:"id"`
	LocalAddr   string    `json:"local_addr"`
	RemotePort  int       `json:"remote_port"`
	Type        string    `json:"type"` // "forward" or "connect"
	ConnectedAt time.Time `json:"connected_at"`
}

// ClientState holds the dynamic state of the client's forwarding configuration.
type ClientState struct {
	mu          sync.RWMutex
	Forwards    []common.ForwardConfig // Array of forward configurations
	ClientID    string                 // Client's unique ID, assigned by server
	ActiveConns map[string]ConnInfo    `json:"active_conns"` // Track active tunnels
}

// Client represents the proxy client instance.
type Client struct {
	Config     *common.ClientConfig
	State      *ClientState
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	isRunning  bool
	configPath string
}

// NewClient creates a new Client instance.
func NewClient(config *common.ClientConfig, configPath string) *Client {
	return &Client{
		Config: config,
		State: &ClientState{
			Forwards:    []common.ForwardConfig{},
			ActiveConns: make(map[string]ConnInfo),
		},
		configPath: configPath,
	}
}

// Run starts the client mode of the application.
func Run(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	configFile := fs.String("config", "config.json", "Path to the configuration file")
	serverAddr := fs.String("server", "", "Server WebSocket URL (e.g., ws://localhost:8001/proxy_ws)")
	proxyUser := fs.String("proxy_user", "", "Proxy username for authentication")
	proxyPasswd := fs.String("proxy_passwd", "", "Proxy password for authentication")
	localAddr := fs.String("local", "", "Local address to forward to (e.g., localhost:3000)")
	remotePort := fs.Int("remote", 0, "Remote port to listen on")
	totpSecret := fs.String("totp-secret", "", "TOTP secret key for long-term authentication")

	// Web mode flags
	webMode := fs.Bool("web", false, "Enable web management interface")
	webAddr := fs.String("web_addr", "127.0.0.1:8080", "Address for web management interface")
	webPassword := fs.String("web_password", "", "Password for web management interface")

	fs.Parse(args)

	// Load configuration
	var config *common.ClientConfig
	if _, err := os.Stat(*configFile); err == nil {
		config, _ = common.LoadClientConfig(*configFile)
	}
	if config == nil {
		config = &common.ClientConfig{}
	}

	// Override with flags
	if *serverAddr != "" {
		config.ServerAddr = *serverAddr
	}
	if *proxyUser != "" {
		config.ProxyUser = *proxyUser
	}
	if *proxyPasswd != "" {
		config.ProxyPasswd = *proxyPasswd
	}
	if *totpSecret != "" {
		config.TOTPSecretKey = *totpSecret
	}
	if *webPassword != "" {
		config.WebPassword = *webPassword
	}

	c := NewClient(config, *configFile)

	if *localAddr != "" {
		c.State.mu.Lock()
		c.State.Forwards = append(c.State.Forwards, common.ForwardConfig{LOCAL_ADDR: *localAddr, REMOTE_PORT: *remotePort})
		c.State.mu.Unlock()
	}

	if *webMode {
		log.Printf("Starting web management interface at http://%s", *webAddr)
		RunWebMode(c, *webAddr, config.WebPassword)
		return
	}

	// CLI mode
	if config.ServerAddr == "" {
		log.Fatal("Server URL is required. Use the --server flag or define it in the config file.")
	}

	token := ""
	if config.TOTPSecretKey == "" {
		fmt.Print("Enter 6-digit TOTP token: ")
		reader := bufio.NewReader(os.Stdin)
		readToken, _ := reader.ReadString('\n')
		token = strings.TrimSpace(readToken)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Shutting down...")
		cancel()
	}()

	c.Start(ctx, token)
}

// Start initiates the connection loop.
func (c *Client) Start(ctx context.Context, manualToken string) {
	c.mu.Lock()
	if c.isRunning {
		c.mu.Unlock()
		return
	}
	c.ctx, c.cancel = context.WithCancel(ctx)
	c.isRunning = true
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.isRunning = false
		c.mu.Unlock()
	}()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		log.Printf("Connecting to %s...", c.Config.ServerAddr)
		conn, _, err := websocket.DefaultDialer.Dial(c.Config.ServerAddr, nil)
		if err != nil {
			log.Printf("Connect failed: %v. Retry in %v...", err, common.ReconnectDelay)
			select {
			case <-c.ctx.Done():
				return
			case <-time.After(common.ReconnectDelay):
				continue
			}
		}

		newID, err := authenticate(conn, manualToken, c.Config.TOTPSecretKey, c.State.ClientID, c.Config.ProxyUser, c.Config.ProxyPasswd, c.State)
		if err != nil {
			log.Printf("Auth failed: %v", err)
			conn.Close()
			if strings.Contains(err.Error(), "server rejected authentication") {
				return
			}
			select {
			case <-c.ctx.Done():
				return
			case <-time.After(common.ReconnectDelay):
				continue
			}
		}
		c.State.ClientID = newID

		for i, forward := range c.State.Forwards {
			actualPort, err := requestProxy(conn, forward.REMOTE_PORT, forward.LOCAL_ADDR, c.State.ClientID)
			if err != nil {
				log.Printf("Failed to request proxy for %s:%d: %v", forward.LOCAL_ADDR, forward.REMOTE_PORT, err)
			} else if actualPort > 0 && forward.REMOTE_PORT == 0 {
				c.State.mu.Lock()
				c.State.Forwards[i].REMOTE_PORT = actualPort
				c.State.mu.Unlock()
				log.Printf("Server assigned random port %d for local %s", actualPort, forward.LOCAL_ADDR)
			}
		}

		listenForNewConnections(c.ctx, conn, c.Config.ServerAddr, c.State)
		conn.Close()

		select {
		case <-c.ctx.Done():
			return
		default:
			log.Printf("Lost connection. Reconnecting in %v...", common.ReconnectDelay)
			select {
			case <-c.ctx.Done():
				return
			case <-time.After(common.ReconnectDelay):
			}
		}
	}
}

// Stop stops the client.
func (c *Client) Stop() {
	c.mu.Lock()
	if c.cancel != nil {
		c.cancel()
	}
	c.isRunning = false
	c.mu.Unlock()
}

// IsRunning returns true if the client is currently running.
func (c *Client) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isRunning
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

	// If no forwards were specified on the command line, use the list from the server.
	// Otherwise, the command-line forwards take precedence.
	state.mu.Lock()
	if len(state.Forwards) == 0 {
		state.Forwards = authResp.Forwards
	}
	state.mu.Unlock()

	return authResp.ClientID, nil
}

// requestProxy sends a request to the server to open a public port.
// Returns the actual remote port assigned by the server.
func requestProxy(conn WebSocketConn, remotePort int, localAddr string, clientID string) (int, error) {
	req := common.Message{Type: "proxy_request", Payload: common.ProxyRequest{RemotePort: remotePort, LocalAddr: localAddr, ClientID: clientID}}
	if err := conn.WriteJSON(req); err != nil {
		return 0, fmt.Errorf("failed to send proxy request: %w", err)
	}

	// Wait for proxy response.
	var resp common.Message
	if err := conn.ReadJSON(&resp); err != nil {
		return 0, fmt.Errorf("failed to read proxy response: %w", err)
	}

	if resp.Type != "proxy_response" {
		return 0, fmt.Errorf("unexpected message type: %s", resp.Type)
	}

	var proxyResp common.ProxyResponse
	payloadBytes, _ := json.Marshal(resp.Payload)
	json.Unmarshal(payloadBytes, &proxyResp)

	if !proxyResp.Success {
		return 0, fmt.Errorf("server failed to set up proxy: %s", proxyResp.Message)
	}

	log.Printf("Server confirmed proxy. Public URL: %s", proxyResp.PublicURL)
	return proxyResp.RemotePort, nil
}

// listenForNewConnections waits for messages from the server and handles them.
func listenForNewConnections(ctx context.Context, controlConn WebSocketConn, serverAddr string, state *ClientState) {
	msgChan := make(chan common.Message)
	errChan := make(chan error, 1)

	// Set a pong handler to extend the read deadline upon receiving a pong.
	controlConn.SetReadDeadline(time.Now().Add(common.ReadTimeout))
	controlConn.SetPongHandler(func(string) error {
		controlConn.SetReadDeadline(time.Now().Add(common.ReadTimeout))
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

	// Register connection
	state.mu.Lock()
	state.ActiveConns[tunnelID] = ConnInfo{
		ID:          tunnelID,
		LocalAddr:   localAddr,
		RemotePort:  remotePort,
		Type:        "forward",
		ConnectedAt: time.Now(),
	}
	state.mu.Unlock()

	// Start proxying data between the local service and the data tunnel.
	common.Proxy(localConn, dataConn)

	// Unregister connection
	state.mu.Lock()
	delete(state.ActiveConns, tunnelID)
	state.mu.Unlock()

	log.Printf("[%s] Tunnel closed.", tunnelID)
}
