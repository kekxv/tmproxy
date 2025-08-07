package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gemini-cli/tmproxy/common"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pquerna/otp/totp"
)

//go:embed all:frontend
var frontendFS embed.FS

// Server holds the state for the proxy server.
type Server struct {
	config               *common.Config
	upgrader             websocket.Upgrader
	clients              map[string]*ClientInfo     // Map of client ID to ClientInfo
	connToClientID       map[*websocket.Conn]string // Reverse map for quick lookup
	activeTunnels        map[string]chan net.Conn
	mu                   sync.Mutex
	activeTCPConnections map[string]*TCPConnectionInfo
	adminSessions        map[string]bool
	disconnectedClients  map[string]*DisconnectedClientInfo // Map of client ID to DisconnectedClientInfo
}

// DisconnectedClientInfo stores information about a disconnected client for re-connection purposes.
type DisconnectedClientInfo struct {
	ClientInfo     *ClientInfo
	DisconnectedAt time.Time
}

// ClientInfo stores information about a connected client.
type ClientInfo struct {
	ID          string                 `json:"id"`
	RemoteAddr  string                 `json:"remote_addr"`
	ConnectedAt time.Time              `json:"connected_at"`
	Conn        *websocket.Conn        `json:"-"`
	Listeners   map[int]net.Listener   `json:"-"`        // Map of remote port to listener
	Forwards    []common.ForwardConfig `json:"forwards"` // Array of forward configurations
	sendChan    chan common.Message    // Channel for sending messages to this client
	done        chan struct{}          // Channel to signal client disconnection
	mu          sync.Mutex             // Mutex to protect access to Listeners and Forwards
	cleanupOnce sync.Once              // Ensures cleanup is performed only once
}

// TCPConnectionInfo stores information about an active TCP connection.
type TCPConnectionInfo struct {
	ID          string    `json:"id"`
	TunnelID    string    `json:"tunnel_id"`
	ClientID    string    `json:"client_id"`
	ClientAddr  string    `json:"client_addr"`
	ServerAddr  string    `json:"server_addr"`
	ConnectedAt time.Time `json:"connected_at"`
	PublicConn  net.Conn  `json:"-"`
}

// NewServer creates and initializes a new server instance.
func NewServer(config *common.Config) *Server {
	return &Server{
		config:               config,
		clients:              make(map[string]*ClientInfo),
		connToClientID:       make(map[*websocket.Conn]string),
		activeTunnels:        make(map[string]chan net.Conn),
		activeTCPConnections: make(map[string]*TCPConnectionInfo),
		adminSessions:        make(map[string]bool),
		disconnectedClients:  make(map[string]*DisconnectedClientInfo),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin:     func(r *http.Request) bool { return true },
		},
	}
}

// Run is the entry point for the server mode.
func Run(args []string) {
	config, err := common.LoadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	server := NewServer(config)

	// Serve static files from the embedded filesystem
	staticFS, _ := fs.Sub(frontendFS, "frontend")
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	http.HandleFunc("/", server.handleHomePage)
	http.HandleFunc("/client", server.handleClientDownload)
	http.HandleFunc(config.WEBSOCKET_PATH, server.handleWebSocket)

	http.HandleFunc("/admin/", server.requireAdminAuth(server.handleAdminDashboard))
	http.HandleFunc("/admin/login", server.handleAdminLoginPage)
	http.HandleFunc("/api/admin/login", server.handleAdminLogin)
	http.HandleFunc("/api/admin/clients", server.requireAdminAuth(server.handleApiClients))
	http.HandleFunc("/api/admin/connections", server.requireAdminAuth(server.handleApiConnections))
	http.HandleFunc("/api/admin/disconnect", server.requireAdminAuth(server.handleApiDisconnect))
	http.HandleFunc("/api/admin/forwards", server.requireAdminAuth(server.handleAddForward))
	http.HandleFunc("/api/admin/delete_forward", server.requireAdminAuth(server.handleApiDeleteForward))

	// Start a goroutine to clean up disconnected clients
	go server.cleanupDisconnectedClients()

	log.Printf("Server starting on %s...", config.LISTEN_ADDR)
	if config.TLS_CERT_FILE != "" && config.TLS_KEY_FILE != "" {
		log.Printf("Using TLS certificates: %s and %s", config.TLS_CERT_FILE, config.TLS_KEY_FILE)
		if err := http.ListenAndServeTLS(config.LISTEN_ADDR, config.TLS_CERT_FILE, config.TLS_KEY_FILE, nil); err != nil {
			log.Fatalf("Server failed to start with TLS: %v", err)
		}
	} else {
		if err := http.ListenAndServe(config.LISTEN_ADDR, nil); err != nil {
			log.Fatalf("Server failed to start: %v", err)
		}
	}
}

func (s *Server) cleanupDisconnectedClients() {
	for {
		time.Sleep(10 * time.Second) // Check every 10 seconds
		s.mu.Lock()
		for clientID, info := range s.disconnectedClients {
			if time.Since(info.DisconnectedAt) > 30*time.Second {
				log.Printf("Cleaning up expired disconnected client: %s", clientID)
				delete(s.disconnectedClients, clientID)
			}
		}
		s.mu.Unlock()
	}
}

func (s *Server) handleHomePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	host, _, _ := net.SplitHostPort(r.Host)
	if host == "" {
		host = "localhost"
	}
	_, port, _ := net.SplitHostPort(s.config.LISTEN_ADDR)
	serverWsURL := fmt.Sprintf("ws://%s:%s%s", host, port, s.config.WEBSOCKET_PATH)
	if s.config.TLS_CERT_FILE != "" && s.config.TLS_KEY_FILE != "" {
		serverWsURL = fmt.Sprintf("wss://%s:%s%s", host, port, s.config.WEBSOCKET_PATH)
	}
	serverHTTPURL := fmt.Sprintf("http://%s:%s", host, port)
	if s.config.TLS_CERT_FILE != "" && s.config.TLS_KEY_FILE != "" {
		serverHTTPURL = fmt.Sprintf("https://%s:%s", host, port)
	}

	tmpl, err := template.ParseFS(frontendFS, "frontend/index.html")
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		ServerHTTPURL string
		ServerWsURL   string
		Forwards      []common.ForwardConfig
	}{
		ServerHTTPURL: serverHTTPURL,
		ServerWsURL:   serverWsURL,
		Forwards:      s.config.FORWARD,
	}

	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (s *Server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(frontendFS, "frontend/admin.html")
	if err != nil {
		log.Printf("Error parsing admin template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := tmpl.Execute(w, nil); err != nil {
		log.Printf("Error executing admin template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	tunnelID := r.URL.Query().Get("tunnel_id")
	clientID := r.URL.Query().Get("client_id")

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection: %v", err)
		return
	}

	if tunnelID != "" && clientID != "" {
		s.handleDataTunnel(conn, tunnelID, clientID)
	} else {
		s.handleControlChannel(conn)
	}
}

func (s *Server) handleControlChannel(conn *websocket.Conn) {
	defer conn.Close()

	var clientInfo *ClientInfo

	// Authenticate the client and get the AuthRequest which contains the ClientID
	authSuccess, authReq := s.authenticateClient(conn)
	if !authSuccess {
		// Authentication failed, send error response and close connection
		return
	}

	// Acquire lock for client management
	s.mu.Lock()

	// Check if a client ID was provided and if it's a re-connection
	var disconnectedInfo *DisconnectedClientInfo
	if authReq.ClientID != "" {
		if info, ok := s.disconnectedClients[authReq.ClientID]; ok {
			disconnectedInfo = info
			if time.Since(disconnectedInfo.DisconnectedAt) <= 30*time.Second {
				// Re-connecting client within the 30-second window
				clientInfo = disconnectedInfo.ClientInfo
				clientInfo.Conn = conn // Update with new connection
				clientInfo.RemoteAddr = conn.RemoteAddr().String()
				clientInfo.ConnectedAt = time.Now()
				clientInfo.sendChan = make(chan common.Message, 100) // Re-initialize send channel
				clientInfo.done = make(chan struct{})                // Re-initialize done channel
				delete(s.disconnectedClients, authReq.ClientID)
				log.Printf("Client reconnected: %s (ID: %s)", conn.RemoteAddr(), authReq.ClientID)

				// Reactivate existing forwards for the reconnected client
				// Reactivate existing forwards for the reconnected client
				for _, forward := range clientInfo.Forwards {
					log.Printf("Reactivating forward for client %s: remote %d -> local %s", clientInfo.ID, forward.REMOTE_PORT, forward.LOCAL_ADDR)
					go s.startProxyListener(clientInfo, forward.REMOTE_PORT, forward.LOCAL_ADDR)
				}
			} else {
				// Client ID expired, remove it
				delete(s.disconnectedClients, authReq.ClientID)
				log.Printf("Client ID expired: %s. Assigning new ID.", authReq.ClientID)
			}
		}
	}

	if clientInfo == nil {
		// New client or expired client ID, generate a new one
		clientInfo = &ClientInfo{
			ID:          uuid.New().String(),
			RemoteAddr:  conn.RemoteAddr().String(),
			ConnectedAt: time.Now(),
			Conn:        conn,
			Listeners:   make(map[int]net.Listener),
			Forwards:    []common.ForwardConfig{},
			sendChan:    make(chan common.Message, 100), // Buffered channel for sending messages
			done:        make(chan struct{}),            // Initialize done channel
		}
		log.Printf("New client connected: %s (ID: %s)", conn.RemoteAddr(), clientInfo.ID)
	}

	if len(s.clients) >= s.config.MAX_CLIENTS {
		log.Println("Max clients reached. Rejecting new connection.")
		conn.WriteJSON(common.Message{Type: "auth_response", Payload: common.AuthResponse{Success: false, Message: "Server is full"}})
		return
	}

	s.clients[clientInfo.ID] = clientInfo
	s.connToClientID[conn] = clientInfo.ID

	// Send AuthResponse with the assigned ClientID
	clientInfo.sendChan <- common.Message{Type: "auth_response", Payload: common.AuthResponse{Success: true, ClientID: clientInfo.ID, Forwards: clientInfo.Forwards}}

	s.mu.Unlock() // Release lock after client management

	log.Printf("handleControlChannel: Client %s connected from %s", clientInfo.ID, conn.RemoteAddr())

	// Start a goroutine to handle sending messages to the client
	go func() {
		for msg := range clientInfo.sendChan {
			if err := clientInfo.Conn.WriteJSON(msg); err != nil {
				log.Printf("Error writing JSON to client %s: %v", clientInfo.ID, err)
				return
			}
		}
	}()

	// Loop to read messages from the client
	for {
		var msg common.Message
		log.Printf("handleControlChannel: Client %s waiting for message...", clientInfo.ID)
		if err := conn.ReadJSON(&msg); err != nil {
			log.Printf("handleControlChannel: Error reading JSON from client %s: %v", clientInfo.ID, err)
			break // Exit loop on error
		}
		log.Printf("handleControlChannel: Client %s received message type: %s", clientInfo.ID, msg.Type)

		switch msg.Type {
		case "proxy_request":
			var req common.ProxyRequest
			payloadBytes, _ := json.Marshal(msg.Payload)
			json.Unmarshal(payloadBytes, &req)
			log.Printf("handleControlChannel: Client %s requested proxy for remote port %d to local %s", clientInfo.ID, req.RemotePort, req.LocalAddr)

			s.mu.Lock() // Acquire lock for modifying clientInfo.Forwards and Listeners
			// Check if the forward already exists and if the local address has changed
			found := false
			for i, forward := range clientInfo.Forwards {
				if forward.REMOTE_PORT == req.RemotePort {
					// Update existing forward
					clientInfo.Forwards[i].LOCAL_ADDR = req.LocalAddr
					found = true
					log.Printf("handleControlChannel: Local address for remote port %d changed to %s. Restarting listener.", req.RemotePort, req.LocalAddr)
					if listener, listenerOk := clientInfo.Listeners[req.RemotePort]; listenerOk {
						listener.Close() // Close the old listener
						delete(clientInfo.Listeners, req.RemotePort)
						log.Printf("handleControlChannel: Closed existing listener for remote port %d.", req.RemotePort)
					}
					break
				}
			}
			if !found {
				// Add new forward
				clientInfo.Forwards = append(clientInfo.Forwards, common.ForwardConfig{REMOTE_PORT: req.RemotePort, LOCAL_ADDR: req.LocalAddr})
			}
			s.mu.Unlock() // Release lock
			go s.startProxyListener(clientInfo, req.RemotePort, req.LocalAddr)
		case "local_connect_failed":
			var failedConn common.LocalConnectFailed
			payloadBytes, _ := json.Marshal(msg.Payload)
			json.Unmarshal(payloadBytes, &failedConn)
			log.Printf("handleControlChannel: Client %s reported local connection failed for tunnel: %s. Cleaning up.", clientInfo.ID, failedConn.TunnelID)

			if tunnelChan, ok := s.activeTunnels[failedConn.TunnelID]; ok {
				select {
				case publicConn := <-tunnelChan:
					publicConn.Close()
				default:
				}
			}
			s.mu.Lock() // Acquire lock for modifying activeTunnels and activeTCPConnections
			delete(s.activeTunnels, failedConn.TunnelID)
			delete(s.activeTCPConnections, failedConn.TunnelID)
			s.mu.Unlock() // Release lock
		}
	}

	// Cleanup after the loop exits
	s.mu.Lock()
	clientInfo.cleanupOnce.Do(func() {
		// Close all listeners associated with this client immediately
		for _, listener := range clientInfo.Listeners {
			listener.Close()
		}
		// Close the send channel to stop the write goroutine
		close(clientInfo.sendChan)
		// Close the done channel to signal all related goroutines to stop
		close(clientInfo.done)
	})

	// Move client to disconnectedClients map with timestamp
	s.disconnectedClients[clientInfo.ID] = &DisconnectedClientInfo{
		ClientInfo:     clientInfo,
		DisconnectedAt: time.Now(),
	}
	delete(s.clients, clientInfo.ID)
	delete(s.connToClientID, conn)
	s.mu.Unlock()
	log.Printf("handleControlChannel: Client %s disconnected from %s", clientInfo.ID, conn.RemoteAddr())
}

func (s *Server) authenticateClient(conn *websocket.Conn) (bool, common.AuthRequest) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	var msg common.Message
	if err := conn.ReadJSON(&msg); err != nil {
		log.Printf("Authentication failed for %s: %v", conn.RemoteAddr(), err)
		conn.WriteJSON(common.Message{Type: "auth_response", Payload: common.AuthResponse{Success: false, Message: "Authentication failed: Invalid message format or timeout"}})
		return false, common.AuthRequest{}
	}

	if msg.Type != "auth_request" {
		conn.WriteJSON(common.Message{Type: "auth_response", Payload: common.AuthResponse{Success: false, Message: "Authentication failed: Expected auth_request"}})
		return false, common.AuthRequest{}
	}

	var authReq common.AuthRequest
	payloadBytes, _ := json.Marshal(msg.Payload)
	json.Unmarshal(payloadBytes, &authReq)

	valid := totp.Validate(authReq.Token, s.config.TOTP_SECRET_KEY)
	if !valid {
		log.Printf("Invalid TOTP token from %s", conn.RemoteAddr())
		conn.WriteJSON(common.Message{Type: "auth_response", Payload: common.AuthResponse{Success: false, Message: "Authentication failed: Invalid TOTP token"}})
		return false, authReq
	}

	log.Printf("Authentication successful for %s", conn.RemoteAddr())
	return true, authReq
}

func (s *Server) startProxyListener(client *ClientInfo, remotePort int, localAddr string) {
	s.mu.Lock()
	// If a listener for this remotePort already exists, close it and remove it.
	// This ensures that a new listener is always created if startProxyListener is called.
	if listener, ok := client.Listeners[remotePort]; ok {
		listener.Close()
		delete(client.Listeners, remotePort)
		log.Printf("Closed existing (possibly stale) listener for port %d for client %s.", remotePort, client.ID)
	}
	s.mu.Unlock()

	listenAddr := fmt.Sprintf("0.0.0.0:%d", remotePort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Printf("Failed to start listener on %s for client %s: %v", listenAddr, client.ID, err)
		// Send error response to client if possible, and then return
		select {
		case client.sendChan <- common.Message{Type: "proxy_response", Payload: common.ProxyResponse{Success: false, Message: err.Error()}}:
		case <-client.done:
			// Client disconnected, do nothing
		}
		return
	}

	s.mu.Lock()
	client.Listeners[remotePort] = listener
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(client.Listeners, remotePort)
		s.mu.Unlock()
		listener.Close()
		log.Printf("Closed listener on %s for client %s", listenAddr, client.ID)
	}()

	publicURL := fmt.Sprintf("http://<your-server-ip>:%d", remotePort)
	log.Printf("Started public listener for client %s on %s, forwarding to %s", client.RemoteAddr, listenAddr, localAddr)
	select {
	case client.sendChan <- common.Message{Type: "proxy_response", Payload: common.ProxyResponse{Success: true, PublicURL: publicURL}}:
	case <-client.done:
		// Client disconnected, do nothing
		return
	}

	for {
		select {
		case <-client.done:
			log.Printf("Client %s disconnected, stopping listener for port %d.", client.ID, remotePort)
			return // Exit goroutine if client disconnected
		default:
			// Continue to accept connections
		}

		publicConn, err := listener.Accept()
		if err != nil {
			// If the listener was closed, return from the goroutine
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				log.Printf("Listener for port %d closed, stopping accept loop.", remotePort)
				return
			}
			log.Printf("Error accepting connection on port %d for client %s: %v", remotePort, client.ID, err)
			continue // Continue to accept new connections despite the error
		}

		tunnelID := uuid.New().String()
		s.activeTunnels[tunnelID] = make(chan net.Conn, 1)
		s.activeTunnels[tunnelID] <- publicConn

		msg := common.Message{Type: "new_conn", Payload: common.NewConnection{TunnelID: tunnelID, ClientID: client.ID, RemotePort: remotePort}}
		select {
		case client.sendChan <- msg:
		case <-client.done:
			// Client disconnected, close publicConn and return
			publicConn.Close()
			log.Printf("Client %s disconnected while sending new_conn message, closing public connection for tunnel %s.", client.ID, tunnelID)
			return
		}
	}
}

func (s *Server) handleDataTunnel(dataConn *websocket.Conn, tunnelID string, clientID string) {
	log.Printf("handleDataTunnel: Starting for tunnel %s, client %s", tunnelID, clientID)
	tunnelChan, ok := s.activeTunnels[tunnelID]
	if !ok {
		log.Printf("handleDataTunnel: Tunnel %s not found for client %s, closing data connection.", tunnelID, clientID)
		dataConn.Close()
		return
	}

	select {
	case publicConn := <-tunnelChan:
		log.Printf("handleDataTunnel: Received public connection for tunnel %s", tunnelID)
		s.mu.Lock()
		delete(s.activeTunnels, tunnelID)
		s.activeTCPConnections[tunnelID] = &TCPConnectionInfo{
			ID:          uuid.New().String(),
			TunnelID:    tunnelID,
			ClientID:    clientID,
			ClientAddr:  dataConn.RemoteAddr().String(),
			ServerAddr:  publicConn.LocalAddr().String(),
			ConnectedAt: time.Now(),
			PublicConn:  publicConn,
		}
		s.mu.Unlock()

		log.Printf("handleDataTunnel: Starting proxy for tunnel %s", tunnelID)
		common.Proxy(publicConn, dataConn)

		s.mu.Lock()
		delete(s.activeTCPConnections, tunnelID)
		s.mu.Unlock()
		log.Printf("handleDataTunnel: Tunnel %s closed.", tunnelID)
	case <-time.After(10 * time.Second):
		log.Printf("handleDataTunnel: Timeout waiting for public connection for tunnel %s", tunnelID)
		select {
		case publicConn := <-tunnelChan:
			publicConn.Close()
		default:
		}
		s.mu.Lock()
		delete(s.activeTunnels, tunnelID)
		s.mu.Unlock()
	}
}

func (s *Server) handleClientDownload(w http.ResponseWriter, r *http.Request) {
	clientOS := strings.ToLower(r.URL.Query().Get("os"))
	clientArch := strings.ToLower(r.URL.Query().Get("arch"))

	switch clientArch {
	case "x86_64":
		clientArch = "amd64"
	case "aarch64":
		clientArch = "arm64"
	}

	if clientOS == "" || clientArch == "" {
		clientOS = runtime.GOOS
		clientArch = runtime.GOARCH
	}

	binaryName := fmt.Sprintf("tmproxy-%s-%s", clientOS, clientArch)
	if clientOS == "windows" {
		binaryName += ".exe"
	}

	clientPath := filepath.Join("clients", binaryName)

	if _, err := os.Stat(clientPath); os.IsNotExist(err) {
		exePath, err := os.Executable()
		if err != nil {
			http.Error(w, "Could not determine executable path.", http.StatusInternalServerError)
			return
		}
		clientPath = exePath
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", binaryName))
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, clientPath)
}

// DisconnectRequest can be used to disconnect either a client or a specific TCP connection.
type DisconnectRequest struct {
	ClientID     string `json:"client_id,omitempty"`
	ConnectionID string `json:"connection_id,omitempty"` // This will be the TunnelID
}

func (s *Server) handleApiDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DisconnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if req.ClientID != "" {
		// Handle client disconnection
		client, ok := s.clients[req.ClientID]
		if !ok {
			json.NewEncoder(w).Encode(common.DisconnectResponse{Success: false, Message: "Client not found"})
			return
		}

		client.cleanupOnce.Do(func() {
			// Close all listeners associated with this client
			for _, listener := range client.Listeners {
				listener.Close()
			}
			// Close the send channel to stop the write goroutine
			close(client.sendChan)
			// Close the done channel to signal all related goroutines to stop
			close(client.done)
		})

		// Move client to disconnectedClients map with timestamp
		s.disconnectedClients[client.ID] = &DisconnectedClientInfo{
			ClientInfo:     client,
			DisconnectedAt: time.Now(),
		}
		delete(s.clients, client.ID)
		// Find and delete from connToClientID map
		for conn, id := range s.connToClientID {
			if id == client.ID {
				delete(s.connToClientID, conn)
				conn.Close() // Close the websocket connection
				break
			}
		}

		log.Printf("Client %s disconnected by admin.", client.ID)
		json.NewEncoder(w).Encode(common.DisconnectResponse{Success: true, Message: "Client disconnected successfully"})
		return
	} else if req.ConnectionID != "" {
		// Handle TCP connection disconnection
		connInfo, ok := s.activeTCPConnections[req.ConnectionID]
		if !ok {
			json.NewEncoder(w).Encode(common.DisconnectResponse{Success: false, Message: "TCP connection not found"})
			return
		}

		connInfo.PublicConn.Close() // Close the public facing TCP connection
		delete(s.activeTCPConnections, req.ConnectionID)
		log.Printf("TCP connection %s (TunnelID: %s) disconnected by admin.", connInfo.ID, connInfo.TunnelID)
		json.NewEncoder(w).Encode(common.DisconnectResponse{Success: true, Message: "TCP connection disconnected successfully"})
		return
	} else {
		http.Error(w, "Invalid request: either client_id or connection_id must be provided", http.StatusBadRequest)
		return
	}
}

func (s *Server) handleApiDeleteForward(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var req common.DelForwardRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	client, ok := s.clients[req.ClientID]
	if !ok {
		json.NewEncoder(w).Encode(common.DelForwardResponse{Success: false, Message: "Client not found"})
		return
	}

	if err := client.RemoveForward(req.RemotePort); err != nil {
		json.NewEncoder(w).Encode(common.DelForwardResponse{Success: false, Message: err.Error()})
		return
	}

	json.NewEncoder(w).Encode(common.DelForwardResponse{Success: true, Message: "Forward deleted successfully"})
}

// RemoveForward safely closes the listener and removes the forward from the client.
func (c *ClientInfo) RemoveForward(remotePort int) error {
	c.mu.Lock() // ClientInfo also needs a mutex for concurrent access to Listeners and Forwards
	defer c.mu.Unlock()

	listener, ok := c.Listeners[remotePort]
	if !ok {
		return fmt.Errorf("no listener found for remote port %d", remotePort)
	}

	listener.Close()
	delete(c.Listeners, remotePort)

	// Find and remove the forward configuration from the slice
	found := false
	for i, forward := range c.Forwards {
		if forward.REMOTE_PORT == remotePort {
			c.Forwards = append(c.Forwards[:i], c.Forwards[i+1:]...)
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("no forward configuration found for remote port %d", remotePort)
	}

	log.Printf("Forward for client %s on remote port %d removed.", c.ID, remotePort)
	return nil
}
