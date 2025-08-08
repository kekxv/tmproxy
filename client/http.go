package client

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"

	"github.com/gemini-cli/tmproxy/common"
	"github.com/gorilla/websocket"
)

func handleHttpRequest(conn WebSocketConn, req *common.HttpRequest) {
	log.Printf("Received HTTP request from server: %s %s", req.Method, req.URL)
	client := &http.Client{}

	httpReq, err := http.NewRequest(req.Method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		log.Printf("Failed to create HTTP request: %v", err)
		return
	}

	httpReq.Header = req.Headers

	resp, err := client.Do(httpReq)
	if err != nil {
		log.Printf("Failed to perform HTTP request: %v", err)
		// Create a basic error response
		response := common.HttpResponse{
			RequestID:  req.RequestID,
			StatusCode: http.StatusServiceUnavailable,
			Body:       []byte(err.Error()),
		}
		conn.WriteJSON(common.Message{Type: "http_response", Payload: response})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read HTTP response body: %v", err)
		return
	}

	response := common.HttpResponse{
		RequestID:  req.RequestID,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
	}

	if err := conn.WriteJSON(common.Message{Type: "http_response", Payload: response}); err != nil {
		log.Printf("Failed to send HTTP response to server: %v", err)
	}
}

func handleConnectRequest(controlConn WebSocketConn, serverAddr, clientID string, req *common.ConnectRequest) {
	log.Printf("Received CONNECT request from server for host: %s", req.Host)

	// Dial the target host
	destConn, err := net.Dial("tcp", req.Host)
	if err != nil {
		log.Printf("Failed to connect to target host %s: %v", req.Host, err)
		// Send failure response back to server
		resp := common.ConnectResponse{
			TunnelID: req.TunnelID,
			Success:  false,
			Error:    err.Error(),
		}
		controlConn.WriteJSON(common.Message{Type: "connect_response", Payload: resp})
		return
	}

	// Send success response back to server immediately
	resp := common.ConnectResponse{
		TunnelID: req.TunnelID,
		Success:  true,
	}
	if err := controlConn.WriteJSON(common.Message{Type: "connect_response", Payload: resp}); err != nil {
		log.Printf("Failed to send success response for CONNECT tunnel %s: %v", req.TunnelID, err)
		destConn.Close()
		return
	}

	// Construct the data tunnel URL
	u, _ := url.Parse(serverAddr)
	dataURL := fmt.Sprintf("%s?tunnel_id=%s&client_id=%s", u.String(), req.TunnelID, clientID)

	// Establish the data WebSocket connection
	dataConn, _, err := websocket.DefaultDialer.Dial(dataURL, nil)
	if err != nil {
		log.Printf("[%s] Failed to establish data tunnel for CONNECT: %v", req.TunnelID, err)
		destConn.Close()
		return
	}

	log.Printf("[%s] Data tunnel for CONNECT established. Proxying data...", req.TunnelID)

	// Start proxying data
	common.Proxy(destConn, dataConn)

	log.Printf("[%s] CONNECT tunnel closed.", req.TunnelID)
}