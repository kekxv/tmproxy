package server

import (
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gemini-cli/tmproxy/common"
	"github.com/google/uuid"
)

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateProxy(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="tmproxy"`)
		http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
		return
	}

	if r.Method == http.MethodConnect {
		s.handleHTTPS(w, r)
	} else {
		s.handleHTTP(w, r)
	}
}

func (s *Server) authenticateProxy(r *http.Request) bool {
	proxyAuth := r.Header.Get("Proxy-Authorization")
	if proxyAuth == "" {
		return false
	}

	if !strings.HasPrefix(proxyAuth, "Basic ") {
		return false
	}

	payload, err := base64.StdEncoding.DecodeString(proxyAuth[6:])
	if err != nil {
		return false
	}

	pair := strings.SplitN(string(payload), ":", 2)
	if len(pair) != 2 {
		return false
	}

	username := pair[0]
	password := pair[1]

	authenticated := false
	s.mu.Lock()
	if storedPassword, ok := s.httpProxyUsers[username]; ok && storedPassword == password {
		authenticated = true
	}
	s.mu.Unlock()

	return authenticated
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Find the client associated with the proxy user
	proxyAuth := r.Header.Get("Proxy-Authorization")
	payload, _ := base64.StdEncoding.DecodeString(proxyAuth[6:])
	pair := strings.SplitN(string(payload), ":", 2)
	username := pair[0]

	s.mu.Lock()
	clientID, ok := s.proxyUsers[username]
	if !ok {
		s.mu.Unlock()
		http.Error(w, "Proxy user not connected", http.StatusServiceUnavailable)
		return
	}

	client, ok := s.clients[clientID]
	if !ok {
		s.mu.Unlock()
		http.Error(w, "Client not found for proxy user", http.StatusServiceUnavailable)
		return
	}
	s.mu.Unlock()

	log.Printf("Forwarding request for %s to client %s (user: %s)", r.RequestURI, clientID, username)

	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	// Create the HttpRequest message
	httpReq := common.HttpRequest{
		RequestID: uuid.New().String(),
		Method:    r.Method,
		URL:       r.RequestURI,
		Headers:   r.Header,
		Body:      body,
	}

	// Create a channel to receive the response
	respChan := make(chan common.HttpResponse, 1)
	s.mu.Lock()
	s.pendingRequests[httpReq.RequestID] = respChan
	s.mu.Unlock()

	// Send the request to the client
	client.sendChan <- common.Message{Type: "http_request", Payload: httpReq}

	// Wait for the response
	select {
	case resp := <-respChan:
		// Write the response back to the original requester
		copyHeader(w.Header(), resp.Headers)
		w.WriteHeader(resp.StatusCode)
		w.Write(resp.Body)
	case <-time.After(30 * time.Second):
		http.Error(w, "Request timed out", http.StatusGatewayTimeout)
	}
}

func (s *Server) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	// Find the client associated with the proxy user
	proxyAuth := r.Header.Get("Proxy-Authorization")
	payload, _ := base64.StdEncoding.DecodeString(proxyAuth[6:])
	pair := strings.SplitN(string(payload), ":", 2)
	username := pair[0]

	s.mu.Lock()
	clientID, ok := s.proxyUsers[username]
	if !ok {
		s.mu.Unlock()
		http.Error(w, "Proxy user not connected", http.StatusServiceUnavailable)
		return
	}

	client, ok := s.clients[clientID]
	if !ok {
		s.mu.Unlock()
		http.Error(w, "Client not found for proxy user", http.StatusServiceUnavailable)
		return
	}
	s.mu.Unlock()

	// Create a new tunnel ID
	tunnelID := uuid.New().String()

	// Create the ConnectRequest message
	connectReq := common.ConnectRequest{
		TunnelID: tunnelID,
		Host:     r.Host,
	}

	// Create a channel to receive the response
	respChan := make(chan common.ConnectResponse, 1)
	s.mu.Lock()
	s.pendingConnects[tunnelID] = respChan
	s.mu.Unlock()

	// Send the request to the client
	client.sendChan <- common.Message{Type: "connect_request", Payload: connectReq}

	// Wait for the response
	select {
	case resp := <-respChan:
		if !resp.Success {
			http.Error(w, "Failed to connect to target host: "+resp.Error, http.StatusServiceUnavailable)
			return
		}
	case <-time.After(30 * time.Second):
		http.Error(w, "Request timed out", http.StatusGatewayTimeout)
		return
	}

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// The data tunnel is established by the client, we just need to wait for it.
	log.Printf("Waiting for data tunnel for CONNECT tunnel %s...", tunnelID)

	// The rest of the data transfer is handled by the data tunnel connection.
	// We can close the hijacked connection here, as the data will be transferred over the WebSocket tunnel.
	// The client will connect to the target host and proxy the data.
	// The server will then proxy the data between the hijacked connection and the WebSocket data tunnel.

	// We need a way to associate the hijacked connection with the data tunnel.
	// We can use the tunnel ID for this.
	s.activeTunnels[tunnelID] = make(chan net.Conn, 1)
	s.activeTunnels[tunnelID] <- clientConn

	log.Printf("CONNECT tunnel %s established and waiting for data connection.", tunnelID)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
