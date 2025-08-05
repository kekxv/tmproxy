package client

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/gemini-cli/tmproxy/common"
	"github.com/gorilla/websocket"
)

// Run starts the client mode of the application.
// It parses command-line arguments, connects to the server, and handles the proxying.
func Run(args []string) {
	// Define and parse command-line flags.
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	serverAddr := fs.String("server", "", "Server WebSocket URL (e.g., ws://localhost:8001/proxy_ws)")
	localAddr := fs.String("local", "localhost:3000", "Local service address to expose")
	remotePort := fs.Int("remote", 8080, "Requested public port on the server")
	fs.Parse(args)

	if *serverAddr == "" {
		log.Fatal("Server URL is required. Use the --server flag.")
	}

	// Prompt for the TOTP token.
	fmt.Print("Enter 6-digit TOTP token: ")
	reader := bufio.NewReader(os.Stdin)
	token, _ := reader.ReadString('\n')
	token = strings.TrimSpace(token)

	// Establish the main control connection.
	controlConn, _, err := websocket.DefaultDialer.Dial(*serverAddr, nil)
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer controlConn.Close()

	log.Println("Connected to server. Authenticating...")

	// Authenticate with the server.
	if err := authenticate(controlConn, token); err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	log.Println("Authentication successful. Sending proxy request...")

	// Request the proxy to be set up.
	if err := requestProxy(controlConn, *remotePort); err != nil {
		log.Fatalf("Failed to request proxy: %v", err)
	}

	log.Printf("Proxy requested for local service %s. Waiting for connections...", *localAddr)

	// Listen for new connection commands from the server.
	listenForNewConnections(controlConn, *serverAddr, *localAddr)
}

// authenticate sends the TOTP token to the server and waits for a successful response.
func authenticate(conn *websocket.Conn, token string) error {
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
func listenForNewConnections(controlConn *websocket.Conn, serverAddr, localAddr string) {
	for {
		var msg common.Message
		if err := controlConn.ReadJSON(&msg); err != nil {
			log.Printf("Error reading from control connection: %v. Exiting.", err)
			return
		}

		if msg.Type == "new_conn" {
			var newConnPayload common.NewConnection
			payloadBytes, _ := json.Marshal(msg.Payload)
			json.Unmarshal(payloadBytes, &newConnPayload)

			log.Printf("Received new connection request for tunnel: %s", newConnPayload.TunnelID)
			go handleNewTunnel(controlConn, serverAddr, localAddr, newConnPayload.TunnelID)
		}
	}
}

// handleNewTunnel connects to the local service and establishes a new data WebSocket connection.
func handleNewTunnel(controlConn *websocket.Conn, serverAddr, localAddr, tunnelID string) {
	// Connect to the local service.
	localConn, err := net.Dial("tcp", localAddr)
	if err != nil {
		log.Printf("Failed to connect to local service at %s: %v", localAddr, err)
		// Notify the server that the local connection failed.
		msg := common.Message{Type: "local_connect_failed", Payload: common.LocalConnectFailed{TunnelID: tunnelID}}
		if err := controlConn.WriteJSON(msg); err != nil {
			log.Printf("Failed to send local connect failed message to server: %v", err)
		}
		return
	}
	defer localConn.Close()

	log.Printf("[%s] Connected to local service. Establishing data tunnel...", tunnelID)

	// Construct the data tunnel URL with the tunnel ID.
	u, _ := url.Parse(serverAddr)
	dataURL := fmt.Sprintf("%s?tunnel_id=%s", u.String(), tunnelID)

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
