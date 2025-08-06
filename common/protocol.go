package common

// Message is a generic struct for all WebSocket communication.
// The `Type` field determines how the `Payload` is interpreted.
type Message struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

// AuthRequest is the payload for an authentication request from the client.
// It contains the TOTP code required for verification.
type AuthRequest struct {
	Token string `json:"token"`
}

// AuthResponse is the payload for an authentication response from the server.
// It indicates whether the authentication was successful.
type AuthResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// ProxyRequest is the payload for a client's request to start proxying.
// It specifies the desired public port on the server.
type ProxyRequest struct {
	RemotePort int `json:"remote_port"`
}

// ProxyResponse is the payload for the server's response to a proxy request.
// It confirms the port that was opened and provides a URL for access.
type ProxyResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	PublicURL string `json:"public_url"`
}

// LocalConnectFailed is a message from the client to the server
// indicating that the client failed to connect to its local service.
type LocalConnectFailed struct {
	TunnelID string `json:"tunnel_id"`
}

// NewConnection is a message from the server to the client.
// It signals that a new external connection has been made to the public port
// and a new data tunnel should be established.
type NewConnection struct {
	TunnelID string `json:"tunnel_id"`
}

// UpdateForwarding is a message from the server to the client
// to update the client's forwarding target.
type UpdateForwarding struct {
	RemoteHost string `json:"remote_host"`
	RemotePort int    `json:"remote_port"`
}
