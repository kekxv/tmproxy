package server

import (
	"encoding/json"
	"fmt"
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
	ID          string               `json:"id"`
	RemoteAddr  string               `json:"remote_addr"`
	ConnectedAt time.Time            `json:"connected_at"`
	Conn        *websocket.Conn      `json:"-"`
	Listeners   map[int]net.Listener `json:"-"`        // Map of remote port to listener
	Forwards    map[int]string       `json:"forwards"` // Map of remote port to local address
	sendChan    chan common.Message  // Channel for sending messages to this client
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

	// Start a goroutine to clean up disconnected clients
	go func(s *Server) {
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
	}(server)

	select {}
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

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>tmproxy Server</title>
		<style>
			body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background-color: #f0f2f5; color: #333; line-height: 1.6; }
			.container { max-width: 900px; margin: 2em auto; padding: 30px; background-color: #fff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
			h1 { color: #0056b3; text-align: center; margin-bottom: 1em; }
			h2 { color: #0056b3; border-bottom: 2px solid #eee; padding-bottom: 8px; margin-top: 2em; }
			p { margin-bottom: 1em; }
			.code-block { background-color: #e9ecef; border: 1px solid #dee2e6; border-radius: 5px; padding: 15px; margin-bottom: 1.5em; position: relative; }
			.code-block pre { margin: 0; overflow-x: auto; font-size: 0.9em; color: #343a40; }
			.copy-btn { position: absolute; top: 10px; right: 10px; background-color: #007bff; color: white; border: none; padding: 8px 12px; border-radius: 5px; cursor: pointer; font-size: 0.8em; transition: background-color 0.2s ease; }
			.copy-btn:hover { background-color: #0056b3; }
			.copy-feedback { position: absolute; top: 10px; right: 80px; background-color: #28a745; color: white; padding: 8px 12px; border-radius: 5px; font-size: 0.8em; opacity: 0; transition: opacity 0.3s ease; }
			.copy-feedback.show { opacity: 1; }
		</style>
	</head>
	<body>
		<div class="container">
		<h1>tmproxy Server</h1>
		<p>Your proxy server is running. Use the client to connect.</p>
		<h2>Download Client</h2>
		<p><b>Linux & macOS:</b></p>
		<div class="code-block">
			<pre id="linux-mac-cmd">curl -o tmproxy "%s/client?os=$(uname -s)&arch=$(uname -m)" && chmod +x ./tmproxy</pre>
			<button class="copy-btn" onclick="copyToClipboard('linux-mac-cmd', this)">Copy</button>
			<span class="copy-feedback">Copied!</span>
		</div>
		<p><b>Windows (PowerShell):</b></p>
		<div class="code-block">
			<pre id="windows-cmd">Invoke-WebRequest -Uri "%s/client?os=windows&arch=amd64" -OutFile tmproxy.exe</pre>
			<button class="copy-btn" onclick="copyToClipboard('windows-cmd', this)">Copy</button>
			<span class="copy-feedback">Copied!</span>
		</div>
		<p><b>Usage</b></p>
		<div class="code-block">
			<pre id="usage-cmd">./tmproxy client --server %s --local localhost:%d --remote %d</pre>
			<button class="copy-btn" onclick="copyToClipboard('usage-cmd', this)">Copy</button>
			<span class="copy-feedback">Copied!</span>
		</div>
		</div>

		<script>
			async function copyToClipboard(elementId, button) {
				const text = document.getElementById(elementId).textContent;
				try {
					await navigator.clipboard.writeText(text);
					const feedback = button.nextElementSibling;
					feedback.classList.add('show');
					setTimeout(() => {
						feedback.classList.remove('show');
					}, 2000);
				} catch (err) {
					console.error('Failed to copy: ', err);
					alert('Failed to copy command. Please copy manually.');
				}
			}
		</script>
	</body>
	</html>
	`, serverHTTPURL, serverHTTPURL, serverWsURL, s.config.DEFAULT_LOCAL_PORT, s.config.DEFAULT_REMOTE_PORT)
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
	if authReq.ClientID != "" {
		if disconnectedInfo, ok := s.disconnectedClients[authReq.ClientID]; ok {
			if time.Since(disconnectedInfo.DisconnectedAt) <= 30*time.Second {
				// Re-connecting client within the 30-second window
				clientInfo = disconnectedInfo.ClientInfo
				clientInfo.Conn = conn // Update with new connection
				clientInfo.RemoteAddr = conn.RemoteAddr().String()
				clientInfo.ConnectedAt = time.Now()
				clientInfo.sendChan = make(chan common.Message, 100) // Re-initialize send channel
				delete(s.disconnectedClients, authReq.ClientID)
				log.Printf("Client reconnected: %s (ID: %s)", conn.RemoteAddr(), authReq.ClientID)

				// Reactivate existing forwards for the reconnected client
				for remotePort, localAddr := range clientInfo.Forwards {
					log.Printf("Reactivating forward for client %s: remote %d -> local %s", clientInfo.ID, remotePort, localAddr)
					go s.startProxyListener(clientInfo, remotePort)
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
			Forwards:    make(map[int]string),
			sendChan:    make(chan common.Message, 100), // Buffered channel for sending messages
		}
		log.Printf("New client connected: %s (ID: %s)", conn.RemoteAddr(), clientInfo.ID)
	}

	if len(s.clients) >= s.config.MAX_CLIENTS {
		log.Println("Max clients reached. Rejecting new connection.")
		conn.WriteJSON(common.Message{Type: "auth_response", Payload: common.AuthResponse{Success: false, Message: "Server is full"}})
		s.mu.Unlock() // Explicit unlock before returning
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

	defer func() {
		s.mu.Lock()
		// Close all listeners associated with this client immediately
		for _, listener := range clientInfo.Listeners {
			listener.Close()
		}
		// Close the send channel to stop the write goroutine
		close(clientInfo.sendChan)

		// Move client to disconnectedClients map with timestamp
		s.disconnectedClients[clientInfo.ID] = &DisconnectedClientInfo{
			ClientInfo:     clientInfo,
			DisconnectedAt: time.Now(),
		}
		delete(s.clients, clientInfo.ID)
		delete(s.connToClientID, conn)
		s.mu.Unlock()
		log.Printf("handleControlChannel: Client %s disconnected from %s", clientInfo.ID, conn.RemoteAddr())
	}()

	for {
		var msg common.Message
		log.Printf("handleControlChannel: Client %s waiting for message...", clientInfo.ID)
		if err := conn.ReadJSON(&msg); err != nil {
			log.Printf("handleControlChannel: Error reading JSON from client %s: %v", clientInfo.ID, err)
			break
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
			if existingLocalAddr, ok := clientInfo.Forwards[req.RemotePort]; ok && existingLocalAddr != req.LocalAddr {
				log.Printf("handleControlChannel: Local address for remote port %d changed from %s to %s. Restarting listener.", req.RemotePort, existingLocalAddr, req.LocalAddr)
				if listener, listenerOk := clientInfo.Listeners[req.RemotePort]; listenerOk {
					listener.Close() // Close the old listener
					delete(clientInfo.Listeners, req.RemotePort)
					log.Printf("handleControlChannel: Closed existing listener for remote port %d.", req.RemotePort)
				}
			}
			clientInfo.Forwards[req.RemotePort] = req.LocalAddr
			s.mu.Unlock() // Release lock
			go s.startProxyListener(clientInfo, req.RemotePort)
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
}

func (s *Server) authenticateClient(conn *websocket.Conn) (bool, common.AuthRequest) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	var msg common.Message
	if err := conn.ReadJSON(&msg); err != nil {
		log.Printf("Authentication failed for %s: %v", conn.RemoteAddr(), err)
		return false, common.AuthRequest{}
	}

	if msg.Type != "auth_request" {
		return false, common.AuthRequest{}
	}

	var authReq common.AuthRequest
	payloadBytes, _ := json.Marshal(msg.Payload)
	json.Unmarshal(payloadBytes, &authReq)

	valid := totp.Validate(authReq.Token, s.config.TOTP_SECRET_KEY)
	if !valid {
		log.Printf("Invalid TOTP token from %s", conn.RemoteAddr())
		return false, authReq
	}

	log.Printf("Authentication successful for %s", conn.RemoteAddr())
	return true, authReq
}

func (s *Server) startProxyListener(client *ClientInfo, remotePort int) {
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
		client.sendChan <- common.Message{Type: "proxy_response", Payload: common.ProxyResponse{Success: false, Message: err.Error()}}
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
	log.Printf("Started public listener for client %s on %s", client.RemoteAddr, listenAddr)
	client.sendChan <- common.Message{Type: "proxy_response", Payload: common.ProxyResponse{Success: true, PublicURL: publicURL}}

	for {
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
		client.sendChan <- msg
	}
}

func (s *Server) handleDataTunnel(dataConn *websocket.Conn, tunnelID string, clientID string) {
	log.Printf("handleDataTunnel: Starting for tunnel %s, client %s", tunnelID, clientID)
	tunnelChan, ok := s.activeTunnels[tunnelID]
	if !ok {
		log.Printf("handleDataTunnel: Tunnel %s not found, closing data connection.", tunnelID)
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
