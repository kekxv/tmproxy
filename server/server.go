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
	"time"

	"github.com/gemini-cli/tmproxy/common"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/pquerna/otp/totp"
)

// Server holds the state for the proxy server.

// Server holds the state for the proxy server.
// It includes the configuration, a registry of connected clients, and a map of active tunnels.
type Server struct {
	config       *common.Config
	upgrader     websocket.Upgrader
	clients      map[*websocket.Conn]bool
	activeTunnels map[string]chan net.Conn
}

// NewServer creates and initializes a new server instance.
func NewServer(config *common.Config) *Server {
	return &Server{
		config:  config,
		clients: make(map[*websocket.Conn]bool),
		// A buffered channel to hold incoming connections for a tunnel before the client connects.
		activeTunnels: make(map[string]chan net.Conn),
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
				font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol";
				line-height: 1.6;
				margin: 0;
				padding: 20px;
				background-color: #f4f4f4;
				color: #333;
			}
			.container {
				max-width: 800px;
				margin: 20px auto;
				background: #fff;
				padding: 30px;
				border-radius: 8px;
				box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
			}
			h1, h2 {
				color: #0056b3;
			}
			pre {
				background-color: #e9e9e9;
				padding: 15px;
				border-radius: 5px;
				overflow-x: auto;
				font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace;
			}
			code {
				font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace;
				background-color: #e0e0e0;
				padding: 2px 4px;
				border-radius: 3px;
			}
			a {
				color: #0056b3;
				text-decoration: none;
			}
			a:hover {
				text-decoration: underline;
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

	// Enforce connection limit.
	if len(s.clients) >= s.config.MAX_CLIENTS {
		log.Println("Max clients reached. Rejecting new connection.")
		conn.WriteJSON(common.Message{Type: "auth_response", Payload: common.AuthResponse{Success: false, Message: "Server is full"}})
		return
	}

	// Authenticate the client within a timeout.
	if !s.authenticateClient(conn) {
		return // Authentication failed, connection closed.
	}

	s.clients[conn] = true
	defer delete(s.clients, conn)

	log.Printf("Client authenticated: %s", conn.RemoteAddr())

	// Process messages from the client on the control channel.
	for {
		var msg common.Message
		if err := conn.ReadJSON(&msg); err != nil {
			log.Printf("Client disconnected: %s", conn.RemoteAddr())
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
			delete(s.activeTunnels, failedConn.TunnelID)
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
	if err := conn.ReadJSON(&msg); err != nil {
		log.Printf("Authentication failed (timeout or error): %v", err)
		return false
	}

	if msg.Type != "auth_request" {
		log.Println("Authentication failed: unexpected message type")
		return false
	}

	var authReq common.AuthRequest
	payloadBytes, _ := json.Marshal(msg.Payload)
	json.Unmarshal(payloadBytes, &authReq)

	valid := totp.Validate(authReq.Token, s.config.TOTP_SECRET_KEY)
	if !valid {
		log.Printf("Invalid TOTP token from %s", conn.RemoteAddr())
		conn.WriteJSON(common.Message{Type: "auth_response", Payload: common.AuthResponse{Success: false, Message: "Invalid token"}})
		return false
	}

	// Send success response.
	conn.WriteJSON(common.Message{Type: "auth_response", Payload: common.AuthResponse{Success: true}})
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
		delete(s.activeTunnels, tunnelID)
		// Start proxying data.
		common.Proxy(publicConn, dataConn)
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
		delete(s.activeTunnels, tunnelID)
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
