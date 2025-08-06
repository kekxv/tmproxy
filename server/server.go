package server

import (
	"context"
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
// It includes the configuration, a registry of connected clients, and a map of active tunnels.
type Server struct {
	config               *common.Config
	upgrader             websocket.Upgrader
	clients              map[string]*websocket.Conn // Map of client ID to WebSocket connection
	connToClientID       map[*websocket.Conn]string // Reverse map for quick lookup
	activeTunnels        map[string]chan net.Conn
	mu                   sync.Mutex                    // Mutex to protect concurrent access to maps
	connectedClients     map[string]*ClientInfo        // Map of client ID to ClientInfo
	activeTCPConnections map[string]*TCPConnectionInfo // Map of tunnel ID to TCPConnectionInfo
	adminSessions        map[string]bool               // Stores valid admin session tokens
}

// ClientInfo stores information about a connected client.
type ClientInfo struct {
	ID          string    `json:"id"`
	RemoteAddr  string    `json:"remote_addr"`
	ConnectedAt time.Time `json:"connected_at"`
}

// TCPConnectionInfo stores information about an active TCP connection.
type TCPConnectionInfo struct {
	ID          string    `json:"id"`
	TunnelID    string    `json:"tunnel_id"`
	ClientAddr  string    `json:"client_addr"`
	ServerAddr  string    `json:"server_addr"`
	ConnectedAt time.Time `json:"connected_at"`
	PublicConn  net.Conn  `json:"-"` // Store the actual connection for closing
}

// NewServer creates and initializes a new server instance.
func NewServer(config *common.Config) *Server {
	return &Server{
		config:         config,
		clients:        make(map[string]*websocket.Conn),
		connToClientID: make(map[*websocket.Conn]string),
		// A buffered channel to hold incoming connections for a tunnel before the client connects.
		activeTunnels:        make(map[string]chan net.Conn),
		connectedClients:     make(map[string]*ClientInfo),
		activeTCPConnections: make(map[string]*TCPConnectionInfo),
		adminSessions:        make(map[string]bool),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			// Allow any origin for simplicity. In production, this should be restricted.
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

// Run is the entry point for the server mode.
// It loads the configuration and starts the HTTP server.
func Run(args []string) {
	config, err := common.LoadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	server := NewServer(config)

	http.HandleFunc("/", server.handleHomePage)
	http.HandleFunc("/client", server.handleClientDownload)
	http.HandleFunc(config.WEBSOCKET_PATH, server.handleWebSocket)

	http.HandleFunc("/admin/", server.handleAdminDashboard)
	http.HandleFunc("/api/admin/login", server.handleAdminLogin)
	http.HandleFunc("/api/admin/clients", server.requireAdminAuth(server.handleApiClients))
	http.HandleFunc("/api/admin/connections", server.requireAdminAuth(server.handleApiConnections))
	http.HandleFunc("/api/admin/disconnect", server.requireAdminAuth(server.handleApiDisconnect))
	http.HandleFunc("/api/admin/control", server.requireAdminAuth(server.handleApiClientControl))
	http.HandleFunc("/api/admin/userinfo", server.requireAdminAuth(server.handleApiUserInfo))

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

	// Keep the main goroutine alive
	select {}
}

// handleHomePage serves a simple HTML page with instructions for the client.

// handleHomePage serves a simple HTML page with instructions for the client.
func (s *Server) handleHomePage(w http.ResponseWriter, r *http.Request) {
	// Basic security: prevent path traversal attacks.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Dynamically determine the server address for the instructions.
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
			body {
				font-family: 'Inter', 'Segoe UI', Roboto, Helvetica, Arial, sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol';
				margin: 0;
				padding: 0;
				background-color: #f0f2f5; /* Light gray background */
				color: #333;
				line-height: 1.6;
			}
			.container {
				max-width: 1200px;
				width: 95%%; /* Responsive width */
				margin: 20px auto;
				padding: 30px;
				background: #ffffff;
				border-radius: 12px;
				box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
				box-sizing: border-box;
			}
			h1 {
				text-align: center;
				color: #2c3e50;
				margin-bottom: 40px;
				font-size: 2.5em;
				font-weight: 700;
			}

			/* Login Form Styles */
			#login-section {
				display: flex;
				justify-content: center;
				align-items: center;
				position: fixed; /* Keep fixed for full viewport coverage */
				top: 0;
				left: 0;
				width: 100%%;
				height: 100%%; /* Use height: 100% for full viewport height */
				background-color: #f0f2f5;
				z-index: 1000;
			}
			.login-form {
				background: #ffffff;
				padding: 40px;
				border-radius: 12px;
				box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
				width: 100%%;
				max-width: 400px; /* Fixed width for card */
				text-align: center;
				box-sizing: border-box;
			}
			.login-form h1 {
				color: #34495e;
				margin-bottom: 30px;
				font-size: 2.2em;
				font-weight: 600;
			}
			.input-group {
				margin-bottom: 20px;
				text-align: left;
				display: block; /* Ensure each input group is on its own line */
			}
			.input-group label {
				display: block;
				margin-bottom: 8px;
				color: #555;
				font-size: 0.95em;
				font-weight: 500;
			}
			.input-group input[type="text"], .input-group input[type="password"] {
				width: 100%%;
				padding: 12px 15px;
				border: 1px solid #ddd;
				border-radius: 8px; /* Slightly more rounded */
				box-sizing: border-box;
				font-size: 1em;
				transition: border-color 0.3s ease, box-shadow 0.3s ease;
			}
			.input-group input[type="text"]:focus, .input-group input[type="password"]:focus {
				border-color: #007bff;
				box-shadow: 0 0 0 3px rgba(0, 123, 255, 0.25);
				outline: none;
			}
			.login-form button {
				background-color: #007bff;
				color: white;
				padding: 12px 25px;
				border: none;
				border-radius: 8px; /* Slightly more rounded */
				cursor: pointer;
				font-size: 1.1em;
				font-weight: 600;
				transition: background-color 0.3s ease, transform 0.2s ease;
				width: 100%%; /* Full width button */
				margin-top: 10px;
			}
			.login-form button:hover {
				background-color: #0056b3;
				transform: translateY(-2px);
			}
			.error-message {
				color: #e74c3c;
				margin-bottom: 15px;
				font-weight: bold;
				font-size: 0.9em;
			}

			/* Dashboard Styles */
			#dashboard-content {
				display: none; /* Hidden by default */
			}
			.dashboard-section {
				margin-top: 40px;
				padding-top: 30px;
				border-top: 1px solid #eee;
			}
			.dashboard-section h2 {
				color: #34495e;
				margin-bottom: 25px;
				font-size: 1.8em;
				font-weight: 600;
				border-bottom: 3px solid #007bff; /* Thicker underline */
				display: inline-block;
				padding-bottom: 8px;
			}
			table {
				width: 100%%;
				border-collapse: separate; /* Use separate for rounded corners */
				border-spacing: 0;
				margin-top: 20px;
				box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
				border-radius: 10px;
				overflow: hidden; /* Ensures rounded corners apply to table */
			}
			th, td {
				border: none; /* Remove individual cell borders */
				padding: 15px 20px; /* More padding */
				text-align: left;
			}
			th {
				background-color: #e9ecef; /* Lighter header background */
				color: #495057;
				font-weight: 600;
				text-transform: uppercase;
				font-size: 0.9em;
				border-bottom: 1px solid #dee2e6;
			}
			td {
				border-bottom: 1px solid #f0f2f5; /* Lighter row separator */
			}
			tr:last-child td {
				border-bottom: none; /* No border for the last row */
			}
			tr:nth-child(even) {
				background-color: #f8f9fa; /* Very light alternate row */
			}
			tr:hover {
				background-color: #e2e6ea; /* Subtle hover effect */
			}
			.action-button {
				background-color: #dc3545; /* Red for disconnect */
				color: white;
				border: none;
				padding: 8px 15px;
				border-radius: 6px;
				cursor: pointer;
				font-size: 0.9em;
				font-weight: 500;
				transition: background-color 0.3s ease, transform 0.2s ease;
			}
			.action-button:hover {
				background-color: #c82333;
				transform: translateY(-1px);
			}
			/* Responsive adjustments */
			@media (max-width: 768px) {
				.container {
					margin: 10px auto;
					padding: 20px;
				}
				.login-form {
					padding: 30px;
				}
				.dashboard-section h2 {
					font-size: 1.5em;
				}
				th, td {
					padding: 10px 12px;
					font-size: 0.85em;
				}
				.action-button {
					padding: 6px 10px;
					font-size: 0.8em;
				}
			}
		</style>
	</head>
	<body>
		<div class="container">
			<h1>tmproxy Server</h1>
			<p>Your proxy server is running. Use the client to connect.</p>

			<h2>Download Client</h2>
			<p><b>Linux & macOS:</b></p>
			<p>Copy and paste this command into your terminal to download and install the correct client for your system:</p>
			<pre>curl -o tmproxy "%s/client?os=$(uname -s)&arch=$(uname -m)" && chmod +x ./tmproxy</pre>

			<p><b>Windows (PowerShell):</b></p>
			<pre>Invoke-WebRequest -Uri "%s/client?os=windows&arch=amd64" -OutFile tmproxy.exe</pre>

			<p><b>Usage</b></p>
			<p>Run the following command in your terminal:</p>
			<pre>./tmproxy client --server %s --local localhost:%d --remote %d</pre>
		</div>
	</body>
	</html>
	`, serverHTTPURL, serverHTTPURL, serverWsURL, s.config.DEFAULT_LOCAL_PORT, s.config.DEFAULT_REMOTE_PORT)
}

// handleWebSocket handles incoming WebSocket connections.
// It distinguishes between control channels and data tunnels based on the presence of a tunnel_id.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	tunnelID := r.URL.Query().Get("tunnel_id")

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade connection: %v", err)
		return
	}

	if tunnelID != "" {
		// This is a data tunnel connection.
		s.handleDataTunnel(conn, tunnelID)
	} else {
		// This is a new control channel connection.
		s.handleControlChannel(conn)
	}
}

// handleControlChannel manages the lifecycle of a client's main communication channel.
func (s *Server) handleControlChannel(conn *websocket.Conn) {
	defer conn.Close()

	clientID := uuid.New().String()

	// Authenticate the client within a timeout.
	// IMPORTANT: Do NOT hold s.mu.Lock() during network I/O (authenticateClient)
	if !s.authenticateClient(conn) {
		return // Authentication failed, connection closed.
	}

	// Now that authentication is successful, acquire lock to modify shared state
	s.mu.Lock()

	// Enforce connection limit AFTER authentication
	if len(s.clients) >= s.config.MAX_CLIENTS {
		log.Println("Max clients reached. Rejecting new connection after authentication.")
		conn.WriteJSON(common.Message{Type: "auth_response", Payload: common.AuthResponse{Success: false, Message: "Server is full"}})
		s.mu.Unlock() // Release lock before returning
		return
	}

	s.clients[clientID] = conn
	s.connToClientID[conn] = clientID
	s.connectedClients[clientID] = &ClientInfo{
		ID:          clientID,
		RemoteAddr:  conn.RemoteAddr().String(),
		ConnectedAt: time.Now(),
	}
	s.mu.Unlock() // Release lock after modifying shared state

	log.Printf("Client authenticated: %s (ID: %s)", conn.RemoteAddr(), clientID)

	defer func() {
		s.mu.Lock()
		delete(s.clients, clientID)
		delete(s.connToClientID, conn)
		delete(s.connectedClients, clientID)
		s.mu.Unlock()
		log.Printf("Client disconnected: %s (ID: %s)", conn.RemoteAddr(), clientID)
	}()

	// Process messages from the client on the control channel.
	for {
		var msg common.Message
		if err := conn.ReadJSON(&msg); err != nil {
			log.Printf("Error reading message from client %s (ID: %s): %v", conn.RemoteAddr(), clientID, err)
			break
		}

		if msg.Type == "proxy_request" {
			var req common.ProxyRequest
			payloadBytes, _ := json.Marshal(msg.Payload)
			json.Unmarshal(payloadBytes, &req)
			go s.startProxyListener(conn, req.RemotePort)
		} else if msg.Type == "local_connect_failed" {
			var failedConn common.LocalConnectFailed
			payloadBytes, _ := json.Marshal(msg.Payload)
			json.Unmarshal(payloadBytes, &failedConn)
			log.Printf("Client reported local connection failed for tunnel: %s. Cleaning up.", failedConn.TunnelID)

			// Retrieve and close the public connection if it's still in the channel.
			if tunnelChan, ok := s.activeTunnels[failedConn.TunnelID]; ok {
				select {
				case publicConn := <-tunnelChan:
					publicConn.Close()
					log.Printf("Closed public connection for tunnel %s due to client local connect failure.", failedConn.TunnelID)
				default:
					// Channel was empty, connection already handled or never put in.
				}
			}
			s.mu.Lock()
			delete(s.activeTunnels, failedConn.TunnelID)
			delete(s.activeTCPConnections, failedConn.TunnelID)
			s.mu.Unlock()
			log.Printf("Tunnel %s deleted due to local connection failure.", failedConn.TunnelID)
		}
	}
}

// authenticateClient handles the TOTP authentication process.
func (s *Server) authenticateClient(conn *websocket.Conn) bool {
	// Set a deadline for authentication.
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{}) // Clear the deadline.

	var msg common.Message
	log.Printf("Authenticating client %s: Waiting for auth_request...", conn.RemoteAddr())
	if err := conn.ReadJSON(&msg); err != nil {
		log.Printf("Authentication failed for %s (timeout or error reading JSON): %v", conn.RemoteAddr(), err)
		return false
	}

	log.Printf("Authenticating client %s: Received message type %s", conn.RemoteAddr(), msg.Type)
	if msg.Type != "auth_request" {
		log.Printf("Authentication failed for %s: unexpected message type %s", conn.RemoteAddr(), msg.Type)
		conn.WriteJSON(common.Message{Type: "auth_response", Payload: common.AuthResponse{Success: false, Message: "Unexpected message type"}})
		return false
	}

	var authReq common.AuthRequest
	payloadBytes, _ := json.Marshal(msg.Payload)
	json.Unmarshal(payloadBytes, &authReq)

	valid := totp.Validate(authReq.Token, s.config.TOTP_SECRET_KEY)
	log.Printf("Authenticating client %s: TOTP validation result: %t", conn.RemoteAddr(), valid)
	if !valid {
		log.Printf("Invalid TOTP token from %s", conn.RemoteAddr())
		conn.WriteJSON(common.Message{Type: "auth_response", Payload: common.AuthResponse{Success: false, Message: "Invalid token"}})
		return false
	}

	// Send success response.
	conn.WriteJSON(common.Message{Type: "auth_response", Payload: common.AuthResponse{Success: true}})
	log.Printf("Authentication successful for %s", conn.RemoteAddr())
	return true
}

// startProxyListener creates a new public TCP listener for a client.
func (s *Server) startProxyListener(controlConn *websocket.Conn, remotePort int) {
	listenAddr := fmt.Sprintf("0.0.0.0:%d", remotePort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Printf("Failed to start listener on %s: %v", listenAddr, err)
		controlConn.WriteJSON(common.Message{Type: "proxy_response", Payload: common.ProxyResponse{Success: false, Message: err.Error()}})
		return
	}
	defer listener.Close()

	publicURL := fmt.Sprintf("http://<your-server-ip>:%d", remotePort)
	log.Printf("Started public listener for client %s on %s", controlConn.RemoteAddr(), listenAddr)
	controlConn.WriteJSON(common.Message{Type: "proxy_response", Payload: common.ProxyResponse{Success: true, PublicURL: publicURL}})

	// Accept connections on the public listener.
	for {
		publicConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept public connection: %v", err)
			return
		}

		tunnelID := uuid.New().String()
		s.activeTunnels[tunnelID] = make(chan net.Conn, 1)
		s.activeTunnels[tunnelID] <- publicConn

		log.Printf("New public connection. Tunnel ID: %s. Notifying client...", tunnelID)

		// Notify the client to create a new data tunnel.
		msg := common.Message{Type: "new_conn", Payload: common.NewConnection{TunnelID: tunnelID}}
		if err := controlConn.WriteJSON(msg); err != nil {
			log.Printf("Failed to notify client: %v", err)
			delete(s.activeTunnels, tunnelID)
			publicConn.Close()
		}
	}
}

// handleDataTunnel pairs a new data WebSocket with a waiting TCP connection.
func (s *Server) handleDataTunnel(dataConn *websocket.Conn, tunnelID string) {
	// Look up the waiting TCP connection for this tunnel.
	tunnelChan, ok := s.activeTunnels[tunnelID]
	if !ok {
		log.Printf("Data tunnel connection for unknown tunnel ID: %s", tunnelID)
		dataConn.Close()
		return
	}

	select {
	case publicConn := <-tunnelChan:
		log.Printf("Pairing data tunnel %s with waiting connection.", tunnelID)
		// Clean up the tunnel from the map.
		s.mu.Lock()
		delete(s.activeTunnels, tunnelID)
		s.activeTCPConnections[tunnelID] = &TCPConnectionInfo{
			ID:          uuid.New().String(),
			TunnelID:    tunnelID,
			ClientAddr:  dataConn.RemoteAddr().String(),
			ServerAddr:  publicConn.LocalAddr().String(),
			ConnectedAt: time.Now(),
			PublicConn:  publicConn,
		}
		s.mu.Unlock()

		// Start proxying data.
		common.Proxy(publicConn, dataConn)

		s.mu.Lock()
		delete(s.activeTCPConnections, tunnelID)
		s.mu.Unlock()
		log.Printf("Tunnel %s closed.", tunnelID)
	case <-time.After(10 * time.Second):
		// Timeout if the client doesn't connect the data tunnel in time.
		log.Printf("Timeout waiting for data tunnel connection for ID: %s", tunnelID)
		// Attempt to retrieve and close the public connection if it's still in the channel.
		select {
		case publicConn := <-tunnelChan:
			publicConn.Close()
			log.Printf("Closed timed-out public connection for tunnel %s.", tunnelID)
		default:
			// Channel was empty, connection already handled or never put in.
		}
		s.mu.Lock()
		delete(s.activeTunnels, tunnelID)
		delete(s.activeTCPConnections, tunnelID)
		s.mu.Unlock()
	}
}

// Run starts the server with the given arguments.
func RunWithContext(ctx context.Context, args []string) {
	// This function is a placeholder for a more graceful shutdown mechanism.
	// For this implementation, we will just call the existing Run function.
	Run(args)
}

// handleClientDownload serves the correct client binary based on the os and arch query parameters.
func (s *Server) handleClientDownload(w http.ResponseWriter, r *http.Request) {
	clientOS := strings.ToLower(r.URL.Query().Get("os"))
	clientArch := strings.ToLower(r.URL.Query().Get("arch"))

	// Normalize architecture names
	switch clientArch {
	case "x86_64":
		clientArch = "amd64"
	case "aarch64":
		clientArch = "arm64"
	}

	if clientOS == "" || clientArch == "" {
		// If os or arch is not specified, default to the server's platform.
		clientOS = runtime.GOOS
		clientArch = runtime.GOARCH
	}

	// Construct the binary name.
	binaryName := fmt.Sprintf("tmproxy-%s-%s", clientOS, clientArch)
	if clientOS == "windows" {
		binaryName += ".exe"
	}

	// Look for the binary in the 'clients' directory.
	clientPath := filepath.Join("clients", binaryName)

	if _, err := os.Stat(clientPath); os.IsNotExist(err) {
		// If the specific binary doesn't exist, fall back to serving the current executable.
		// This maintains the single-file distribution capability.
		log.Printf("Client binary not found: %s. Serving current executable as fallback.", clientPath)
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

// handleAdminLogin handles administrator login requests.
func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// IMPORTANT: In a real application, you should hash and compare passwords securely.
	// For simplicity, we are comparing plain text here. Use bcrypt or similar.
	if creds.Username != s.config.ADMIN_USERNAME || creds.Password != s.config.ADMIN_PASSWORD_HASH {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if s.config.ENABLE_ADMIN_TOTP {
		if !totp.Validate(creds.TOTP, s.config.ADMIN_TOTP_SECRET_KEY) {
			http.Error(w, "Invalid TOTP token", http.StatusUnauthorized)
			return
		}
	}

	// Generate a session token and set it as a cookie.
	sessionToken := uuid.New().String()
	s.mu.Lock()
	s.adminSessions[sessionToken] = true
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Use true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
	})

	log.Printf("Admin login successful. Session token: %s", sessionToken)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// handleApiUserInfo returns basic user information if authenticated.
func (s *Server) handleApiUserInfo(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "username": s.config.ADMIN_USERNAME})
}

// requireAdminAuth is a middleware to check for admin authentication.
func (s *Server) requireAdminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("admin_session")
		if err != nil || cookie.Value == "" {
			log.Printf("Unauthorized: No admin_session cookie or empty value. Error: %v", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		s.mu.Lock()
		if !s.adminSessions[cookie.Value] {
			log.Printf("Unauthorized: Invalid session token: %s", cookie.Value)
			s.mu.Unlock() // Release lock before returning
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		s.mu.Unlock() // Release lock before calling next handler
		log.Printf("Authorized: Session token %s is valid.", cookie.Value)

		next.ServeHTTP(w, r)
	}
}

// handleAdminDashboard serves the admin dashboard HTML page.
func (s *Server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Admin Dashboard</title>
		<style>
			body {
				font-family: 'Inter', 'Segoe UI', Roboto, Helvetica, Arial, sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol';
				margin: 0;
				padding: 0;
				background-color: #f0f2f5; /* Light gray background */
				color: #333;
				line-height: 1.6;
			}
			.container {
				max-width: 1200px;
				width: 95%%; /* Responsive width */
				margin: 20px auto;
				padding: 30px;
				background: #ffffff;
				border-radius: 12px;
				box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
				box-sizing: border-box;
			}
			h1 {
				text-align: center;
				color: #2c3e50;
				margin-bottom: 40px;
				font-size: 2.5em;
				font-weight: 700;
			}

			/* Login Form Styles */
			#login-section {
				display: flex;
				justify-content: center;
				align-items: center;
				min-height: 100vh; /* Full viewport height for login */
				width: 100%%; /* Take full width */
				position: fixed; /* Position fixed to cover entire screen */
				top: 0;
				left: 0;
				background-color: #f0f2f5; /* Match body background */
				z-index: 1000; /* Ensure it's on top */
			}
			.login-form {
				background: #ffffff;
				padding: 40px;
				border-radius: 12px;
				box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
				width: 25em;
				height: 33em;
				text-align: center;
				box-sizing: border-box;
				margin: auto;
				left: 0;
				right: 0;
				top: 0;
				bottom: 0;
				position: fixed;
			}
			.login-form h1 {
				color: #34495e;
				margin-bottom: 30px;
				font-size: 2.2em;
				font-weight: 600;
			}
			.input-group {
				margin-bottom: 20px;
				text-align: left;
				display: block; /* Ensure each input group is on its own line */
			}
			.input-group label {
				display: block;
				margin-bottom: 8px;
				color: #555;
				font-size: 0.95em;
				font-weight: 500;
			}
			.input-group input[type="text"], .input-group input[type="password"] {
				width: 100%%;
				padding: 12px 15px;
				border: 1px solid #ddd;
				border-radius: 8px; /* Slightly more rounded */
				box-sizing: border-box;
				font-size: 1em;
				transition: border-color 0.3s ease, box-shadow 0.3s ease;
			}
			.input-group input[type="text"]:focus, .input-group input[type="password"]:focus {
				border-color: #007bff;
				box-shadow: 0 0 0 3px rgba(0, 123, 255, 0.25);
				outline: none;
			}
			.login-form button {
				background-color: #007bff;
				color: white;
				padding: 12px 25px;
				border: none;
				border-radius: 8px; /* Slightly more rounded */
				cursor: pointer;
				font-size: 1.1em;
				font-weight: 600;
				transition: background-color 0.3s ease, transform 0.2s ease;
				width: 100%%; /* Full width button */
				margin-top: 10px;
			}
			.login-form button:hover {
				background-color: #0056b3;
				transform: translateY(-2px);
			}
			.error-message {
				color: #e74c3c;
				margin-bottom: 15px;
				font-weight: bold;
				font-size: 0.9em;
			}

			/* Dashboard Styles */
			#dashboard-content {
				display: none; /* Hidden by default */
			}
			.dashboard-section {
				margin-top: 40px;
				padding-top: 30px;
				border-top: 1px solid #eee;
			}
			.dashboard-section h2 {
				color: #34495e;
				margin-bottom: 25px;
				font-size: 1.8em;
				font-weight: 600;
				border-bottom: 3px solid #007bff; /* Thicker underline */
				display: inline-block;
				padding-bottom: 8px;
			}
			table {
				width: 100%%;
				border-collapse: separate; /* Use separate for rounded corners */
				border-spacing: 0;
				margin-top: 20px;
				box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
				border-radius: 10px;
				overflow: hidden; /* Ensures rounded corners apply to table */
			}
			th, td {
				border: none; /* Remove individual cell borders */
				padding: 15px 20px; /* More padding */
				text-align: left;
			}
			th {
				background-color: #e9ecef; /* Lighter header background */
				color: #495057;
				font-weight: 600;
				text-transform: uppercase;
				font-size: 0.9em;
				border-bottom: 1px solid #dee2e6;
			}
			td {
				border-bottom: 1px solid #f0f2f5; /* Lighter row separator */
			}
			tr:last-child td {
				border-bottom: none; /* No border for the last row */
			}
			tr:nth-child(even) {
				background-color: #f8f9fa; /* Very light alternate row */
			}
			tr:hover {
				background-color: #e2e6ea; /* Subtle hover effect */
			}
			.action-button {
				background-color: #dc3545; /* Red for disconnect */
				color: white;
				border: none;
				padding: 8px 15px;
				border-radius: 6px;
				cursor: pointer;
				font-size: 0.9em;
				font-weight: 500;
				transition: background-color 0.3s ease, transform 0.2s ease;
			}
			.action-button:hover {
				background-color: #c82333;
				transform: translateY(-1px);
			}
			/* Responsive adjustments */
			@media (max-width: 768px) {
				.container {
					margin: 10px auto;
					padding: 20px;
				}
				.login-form {
					padding: 30px;
				}
				.dashboard-section h2 {
					font-size: 1.5em;
				}
				th, td {
					padding: 10px 12px;
					font-size: 0.85em;
				}
				.action-button {
					padding: 6px 10px;
					font-size: 0.8em;
				}
			}
		</style>
	</head>
	<body>
		<div class="container">
			<div id="login-section">
				<div class="login-form">
					<h1>Admin Login</h1>
					<div id="login-error" class="error-message"></div>
					<div class="input-group">
						<label for="username">Username</label>
						<input type="text" id="username" placeholder="Enter your username">
					</div>
					<div class="input-group">
						<label for="password">Password</label>
						<input type="password" id="password" placeholder="Enter your password">
					</div>
					<div class="input-group">
						<label for="totp">TOTP (if enabled)</label>
						<input type="text" id="totp" placeholder="Enter TOTP code">
					</div>
					<button onclick="login()">Login</button>
				</div>
			</div>

			<div id="dashboard-content" style="display:none;">
				<h1>Admin Dashboard</h1>
				<div class="dashboard-section">
					<h2>Connected Clients</h2>
					<table id="clients-table">
						<thead>
							<tr>
								<th>ID</th>
								<th>Remote Address</th>
								<th>Connected At</th>
								<th>Actions</th>
							</tr>
						</thead>
						<tbody>
							<!-- Client data will be loaded here -->
						</tbody>
					</table>
				</div>

				<div class="dashboard-section">
					<h2>Active TCP Connections</h2>
					<table id="connections-table">
						<thead>
							<tr>
								<th>ID</th>
								<th>Tunnel ID</th>
								<th>Client Address</th>
								<th>Server Address</th>
								<th>Connected At</th>
								<th>Actions</th>
							</tr>
						</thead>
						<tbody>
							<!-- Connection data will be loaded here -->
						</tbody>
					</table>
				</div>
			</div>

			<script>
				async function login() {
					const username = document.getElementById('username').value;
					const password = document.getElementById('password').value;
					const totp = document.getElementById('totp').value;
					const errorDiv = document.getElementById('login-error');

					errorDiv.textContent = '';

					try {
						const response = await fetch('/api/admin/login', {
							method: 'POST',
							headers: { 'Content-Type': 'application/json' },
							body: JSON.stringify({ username, password, totp })
						});

						if (response.ok) {
							document.getElementById('login-section').style.display = 'none';
							document.getElementById('dashboard-content').style.display = 'block';
							loadDashboardData();
						} else {
							const errorData = await response.json();
							errorDiv.textContent = errorData.message || 'Login failed';
						}
					} catch (error) {
						errorDiv.textContent = 'An error occurred: ' + error.message;
					}
				}

				async function loadDashboardData() {
					// Load clients
					const clientsResponse = await fetch('/api/admin/clients');
					const clients = await clientsResponse.json();
					const clientsTableBody = document.getElementById('clients-table').getElementsByTagName('tbody')[0];
					clientsTableBody.innerHTML = '';
					clients.forEach(client => {
						const row = clientsTableBody.insertRow();
						row.insertCell().textContent = client.id;
						row.insertCell().textContent = client.remote_addr;
						row.insertCell().textContent = new Date(client.connected_at).toLocaleString();
						const actionsCell = row.insertCell();
						const disconnectButton = document.createElement('button');
						disconnectButton.textContent = 'Disconnect';
						disconnectButton.className = 'action-button';
						disconnectButton.onclick = () => disconnectClient(client.id);
						actionsCell.appendChild(disconnectButton);
					});

					// Load connections
					const connectionsResponse = await fetch('/api/admin/connections');
					const connections = await connectionsResponse.json();
					const connectionsTableBody = document.getElementById('connections-table').getElementsByTagName('tbody')[0];
					connectionsTableBody.innerHTML = '';
					connections.forEach(conn => {
						const row = connectionsTableBody.insertRow();
						row.insertCell().textContent = conn.id;
						row.insertCell().textContent = conn.tunnel_id;
						row.insertCell().textContent = conn.client_addr;
						row.insertCell().textContent = conn.server_addr;
						row.insertCell().textContent = new Date(conn.connected_at).toLocaleString();
						const actionsCell = row.insertCell();
						const disconnectButton = document.createElement('button');
						disconnectButton.textContent = 'Disconnect';
						disconnectButton.className = 'action-button';
						disconnectButton.onclick = () => disconnectConnection(conn.id);
						actionsCell.appendChild(disconnectButton);
					});
				}

				async function disconnectClient(clientID) {
					if (confirm('Are you sure you want to disconnect client ' + clientID + '?')) {
						await fetch('/api/admin/disconnect', {
							method: 'POST',
							headers: { 'Content-Type': 'application/json' },
							body: JSON.stringify({ id: clientID, type: 'client' })
						});
						loadDashboardData(); // Refresh data
					}
				}

				async function disconnectConnection(connectionID) {
					if (confirm('Are you sure you want to disconnect connection ' + connectionID + '?')) {
						await fetch('/api/admin/disconnect', {
							method: 'POST',
							headers: { 'Content-Type': 'application/json' },
							body: JSON.stringify({ id: connectionID, type: 'connection' })
						});
						loadDashboardData(); // Refresh data
					}
				}

				// Initial check for authentication status
				checkAuthStatus();

				async function checkAuthStatus() {
					try {
						const response = await fetch('/api/admin/userinfo');
						if (response.ok) {
							document.getElementById('login-section').style.display = 'none';
							document.getElementById('dashboard-content').style.display = 'block';
							loadDashboardData();
						} else {
							document.getElementById('login-section').style.display = 'block';
							document.getElementById('dashboard-content').style.display = 'none';
						}
					} catch (error) {
						console.error('Error checking auth status:', error);
						document.getElementById('login-section').style.display = 'block';
						document.getElementById('dashboard-content').style.display = 'none';
					}
				}

				// Call checkAuthStatus on page load
				window.onload = checkAuthStatus;
			</script>
	</body>
	</html>
	`)
}

// handleApiClients returns a list of connected clients.
func (s *Server) handleApiClients(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	clients := make([]*ClientInfo, 0, len(s.connectedClients))
	for _, client := range s.connectedClients {
		clients = append(clients, client)
	}

	json.NewEncoder(w).Encode(clients)
}

// handleApiConnections returns a list of active TCP connections.
func (s *Server) handleApiConnections(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	connections := make([]*TCPConnectionInfo, 0, len(s.activeTCPConnections))
	for _, conn := range s.activeTCPConnections {
		connections = append(connections, conn)
	}

	json.NewEncoder(w).Encode(connections)
}

// handleApiDisconnect handles disconnecting a client or a specific TCP connection.
func (s *Server) handleApiDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID   string `json:"id"`
		Type string `json:"type"` // "client" or "connection"
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("handleApiDisconnect: Received request to disconnect ID: %s, Type: %s", req.ID, req.Type)

	s.mu.Lock()
	defer s.mu.Unlock() // Ensure lock is released when function exits

	success := false
	var clientConnToClose *websocket.Conn
	var publicConnToClose net.Conn

	switch req.Type {
	case "client":
		// Find the WebSocket connection associated with the client ID
		clientConn, ok := s.clients[req.ID]
		if ok {
			log.Printf("handleApiDisconnect: Found client connection for ID: %s", req.ID)
			clientConnToClose = clientConn
			// Mark for deletion while holding the lock
			delete(s.connectedClients, req.ID)
			delete(s.clients, req.ID)
			delete(s.connToClientID, clientConnToClose) // Use clientConnToClose here
			success = true
		} else {
			log.Printf("handleApiDisconnect: Client connection not found for ID: %s", req.ID)
		}
	case "connection":
		// Find the TCP connection associated with the connection ID
		if connInfo, ok := s.activeTCPConnections[req.ID]; ok {
			log.Printf("handleApiDisconnect: Found TCP connection for ID: %s", req.ID)
			publicConnToClose = connInfo.PublicConn
			delete(s.activeTCPConnections, req.ID)
			success = true
		} else {
			log.Printf("handleApiDisconnect: TCP connection not found for ID: %s", req.ID)
		}
	}

	// The defer s.mu.Unlock() will handle the unlock when the function exits.
	// Blocking I/O operations are performed after the lock is released.

	if clientConnToClose != nil {
		log.Printf("handleApiDisconnect: Attempting to close WebSocket connection for ID: %s", req.ID)
		if err := clientConnToClose.Close(); err != nil {
			log.Printf("handleApiDisconnect: Error closing WebSocket connection for ID %s: %v", req.ID, err)
		}
	} else if req.Type == "client" && !success {
		// If it was a client disconnect request and we didn't find the connection
		log.Printf("handleApiDisconnect: Client disconnect requested for ID %s, but connection was not found or already closed.", req.ID)
	}

	if publicConnToClose != nil {
		log.Printf("handleApiDisconnect: Attempting to close TCP connection for ID: %s", req.ID)
		if err := publicConnToClose.Close(); err != nil {
			log.Printf("handleApiDisconnect: Error closing TCP connection for ID %s: %v", req.ID, err)
		}
	}

	if success {
		log.Printf("handleApiDisconnect: Disconnect operation successful for ID: %s", req.ID)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	} else {
		log.Printf("handleApiDisconnect: Disconnect operation failed for ID: %s", req.ID)
		http.Error(w, "Failed to disconnect", http.StatusNotFound)
	}
}

// handleApiClientControl handles controlling a client's forwarding target.
func (s *Server) handleApiClientControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ClientID   string `json:"client_id"`
		RemoteHost string `json:"remote_host"`
		RemotePort int    `json:"remote_port"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Find the WebSocket connection associated with the client ID
	var clientConn *websocket.Conn
	if conn, ok := s.clients[req.ClientID]; ok {
		clientConn = conn
	}

	s.mu.Unlock() // Release lock before potential blocking I/O

	if clientConn == nil {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	// Send a message to the client to update its forwarding target
	msg := common.Message{
		Type: "update_forwarding",
		Payload: common.UpdateForwarding{
			RemoteHost: req.RemoteHost,
			RemotePort: req.RemotePort,
		},
	}
	if err := clientConn.WriteJSON(msg); err != nil {
		log.Printf("Failed to send update_forwarding to client %s: %v", req.ClientID, err)
		http.Error(w, "Failed to send command to client", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}
