package cmd

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/gemini-cli/tmproxy/common"
	"github.com/pquerna/otp/totp"
)

// RunConfig generates a configuration file for server or client mode.
// It supports both interactive mode (prompting for values) and parameter mode (via command-line flags).
func RunConfig(args []string) {
	fs := flag.NewFlagSet("config", flag.ExitOnError)
	configType := fs.String("type", "", "Config type: server or client")
	outputFile := fs.String("output", "config.json", "Output config file path")

	// Server config parameters
	listenAddr := fs.String("listen", "", "Server listen address (e.g., 0.0.0.0:8001)")
	maxClients := fs.Int("max-clients", 0, "Maximum concurrent clients")
	adminUser := fs.String("admin-user", "", "Admin username")
	adminPass := fs.String("admin-pass", "", "Admin password")
	allowedPorts := fs.String("allowed-ports", "", "Allowed ports range (e.g., 8000-9000,9099)")
	wsPath := fs.String("ws-path", "", "WebSocket path (default: /proxy_ws)")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file path")
	tlsKey := fs.String("tls-key", "", "TLS key file path")

	// Client config parameters
	serverAddr := fs.String("server", "", "Server WebSocket URL (e.g., ws://localhost:8001/proxy_ws)")
	totpSecret := fs.String("totp-secret", "", "TOTP secret key")
	proxyUser := fs.String("proxy-user", "", "Proxy username")
	proxyPasswd := fs.String("proxy-passwd", "", "Proxy password")

	fs.Parse(args)

	// If type is not specified, prompt for it
	if *configType == "" {
		*configType = promptConfigType()
	}

	switch strings.ToLower(*configType) {
	case "server":
		generateServerConfig(*outputFile, *listenAddr, *maxClients, *adminUser, *adminPass, *allowedPorts, *wsPath, *tlsCert, *tlsKey)
	case "client":
		generateClientConfig(*outputFile, *serverAddr, *totpSecret, *proxyUser, *proxyPasswd)
	default:
		fmt.Printf("Unknown config type: %s\n", *configType)
		fmt.Println("Valid types: server, client")
		os.Exit(1)
	}
}

// promptConfigType interactively prompts for the config type.
func promptConfigType() string {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("Config type (server/client): ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading input: %v\n", err)
			os.Exit(1)
		}
		input = strings.TrimSpace(strings.ToLower(input))

		if input == "server" || input == "client" {
			return input
		}
		fmt.Println("Invalid type. Please enter 'server' or 'client'.")
	}
}

// promptString prompts for a string value with a default.
func promptString(prompt, defaultValue string) string {
	reader := bufio.NewReader(os.Stdin)

	if defaultValue != "" {
		fmt.Printf("%s [%s]: ", prompt, defaultValue)
	} else {
		fmt.Printf("%s: ", prompt)
	}

	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		os.Exit(1)
	}
	input = strings.TrimSpace(input)

	if input == "" {
		return defaultValue
	}
	return input
}

// promptInt prompts for an integer value with a default.
func promptInt(prompt string, defaultValue int) int {
	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("%s [%d]: ", prompt, defaultValue)
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		os.Exit(1)
	}
	input = strings.TrimSpace(input)

	if input == "" {
		return defaultValue
	}

	var result int
	if _, err := fmt.Sscanf(input, "%d", &result); err != nil {
		return defaultValue
	}
	return result
}

// generateServerConfig generates a server configuration file.
func generateServerConfig(outputPath, listenAddr string, maxClients int, adminUser, adminPass, allowedPorts, wsPath, tlsCert, tlsKey string) {
	reader := bufio.NewReader(os.Stdin)

	// Interactive mode: prompt for missing values
	if listenAddr == "" {
		listenAddr = promptString("Listen address", "0.0.0.0:8001")
	}
	if maxClients == 0 {
		maxClients = promptInt("Max clients", 100)
	}
	if adminUser == "" {
		adminUser = promptString("Admin username", "admin")
	}
	if adminPass == "" {
		fmt.Print("Admin password: ")
		pwdBytes, err := reader.ReadBytes('\n')
		if err != nil {
			fmt.Printf("Error reading password: %v\n", err)
			os.Exit(1)
		}
		adminPass = strings.TrimSpace(string(pwdBytes))
		if adminPass == "" {
			adminPass = "changeme"
			fmt.Println("Warning: Using default password 'changeme'. Please change it immediately!")
		}
	}
	if wsPath == "" {
		wsPath = promptString("WebSocket path", "/proxy_ws")
	}
	if allowedPorts == "" {
		allowedPorts = promptString("Allowed ports (e.g., 8000-9000,9099)", "")
	}
	if tlsCert == "" {
		tlsCert = promptString("TLS certificate file (optional)", "")
	}
	if tlsKey == "" {
		tlsKey = promptString("TLS key file (optional)", "")
	}

	// Generate password hash
	passwordHash, err := common.HashPassword(adminPass)
	if err != nil {
		fmt.Printf("Error hashing password: %v\n", err)
		os.Exit(1)
	}

	// Generate TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "tmproxyServer",
		AccountName: "proxy-user",
	})
	if err != nil {
		fmt.Printf("Error generating TOTP key: %v\n", err)
		os.Exit(1)
	}

	config := &common.Config{
		LISTEN_ADDR:           listenAddr,
		MAX_CLIENTS:           maxClients,
		WEBSOCKET_PATH:        wsPath,
		FORWARD:               []common.ForwardConfig{},
		PROXY_USERS:           []common.ProxyUser{},
		TOTP_SECRET_KEY:       key.Secret(),
		TLS_CERT_FILE:         tlsCert,
		TLS_KEY_FILE:          tlsKey,
		ADMIN_USERNAME:        adminUser,
		ADMIN_PASSWORD_HASH:   passwordHash,
		ADMIN_TOTP_SECRET_KEY: "",
		ENABLE_ADMIN_TOTP:     false,
		ALLOWED_PORTS:         allowedPorts,
	}

	// Write config file
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling config: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		fmt.Printf("Error writing config file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nServer config written to: %s\n", outputPath)
	fmt.Printf("TOTP Secret Key: %s\n", key.Secret())
	fmt.Printf("TOTP URI: %s\n", key.URL())
	fmt.Println("Scan the URI with your authenticator app (e.g., Google Authenticator)")
}

// generateClientConfig generates a client configuration file.
func generateClientConfig(outputPath, serverAddr, totpSecret, proxyUser, proxyPasswd string) {
	reader := bufio.NewReader(os.Stdin)

	// Interactive mode: prompt for missing values
	if serverAddr == "" {
		serverAddr = promptString("Server WebSocket URL (e.g., ws://localhost:8001/proxy_ws)", "")
		if serverAddr == "" {
			fmt.Println("Server URL is required!")
			os.Exit(1)
		}
	}
	if totpSecret == "" {
		totpSecret = promptString("TOTP secret key (optional)", "")
	}
	if proxyUser == "" {
		proxyUser = promptString("Proxy username (optional)", "")
	}
	if proxyPasswd == "" && proxyUser != "" {
		fmt.Print("Proxy password: ")
		pwdBytes, err := reader.ReadBytes('\n')
		if err != nil {
			fmt.Printf("Error reading password: %v\n", err)
			os.Exit(1)
		}
		proxyPasswd = strings.TrimSpace(string(pwdBytes))
	}

	config := &common.ClientConfig{
		ServerAddr:    serverAddr,
		ProxyUser:     proxyUser,
		ProxyPasswd:   proxyPasswd,
		TOTPSecretKey: totpSecret,
	}

	// Write config file
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling config: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		fmt.Printf("Error writing config file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nClient config written to: %s\n", outputPath)
}