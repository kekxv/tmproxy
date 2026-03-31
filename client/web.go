package client

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"

	"github.com/gemini-cli/tmproxy/common"
)

//go:embed frontend/*
var frontendAssets embed.FS

type WebServer struct {
	client      *Client
	password    string
	token       string
	ctx         context.Context
	cancel      context.CancelFunc
}

func RunWebMode(c *Client, addr, password string) {
	token := ""
	if password == "" {
		// Generate random token if no password provided
		b := make([]byte, 8)
		rand.Read(b)
		token = hex.EncodeToString(b)
		log.Printf("**************************************************")
		log.Printf("*                                                *")
		log.Printf("*  Web Mode Access Token: %s               *", token)
		log.Printf("*                                                *")
		log.Printf("**************************************************")
	}

	ws := &WebServer{
		client:   c,
		password: password,
		token:    token,
	}

	mux := http.NewServeMux()

	// API Routes
	mux.HandleFunc("/api/login", ws.handleLogin)
	mux.HandleFunc("/api/status", ws.authMiddleware(ws.handleStatus))
	mux.HandleFunc("/api/start", ws.authMiddleware(ws.handleStart))
	mux.HandleFunc("/api/stop", ws.authMiddleware(ws.handleStop))

	// Static Files
	fe, _ := fs.Sub(frontendAssets, "frontend")
	mux.Handle("/", http.FileServer(http.FS(fe)))

	log.Printf("Web server listening on http://%s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Web server failed: %v", err)
	}
}

func (ws *WebServer) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		valid := false
		if ws.password != "" && auth == ws.password {
			valid = true
		} else if ws.token != "" && auth == ws.token {
			valid = true
		}

		if !valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func (ws *WebServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	valid := false
	if ws.password != "" && req.Password == ws.password {
		valid = true
	} else if ws.token != "" && req.Password == ws.token {
		valid = true
	}

	if !valid {
		http.Error(w, "Invalid password or token", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": req.Password})
}

func (ws *WebServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	ws.client.State.mu.RLock()
	defer ws.client.State.mu.RUnlock()

	status := map[string]interface{}{
		"is_running": ws.client.IsRunning(),
		"config":     ws.client.Config,
		"state":      ws.client.State,
	}
	json.NewEncoder(w).Encode(status)
}

func (ws *WebServer) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Config common.ClientConfig `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Update client config
	ws.client.mu.Lock()
	if ws.client.isRunning {
		ws.client.mu.Unlock()
		http.Error(w, "Client is already running", http.StatusConflict)
		return
	}
	ws.client.Config = &req.Config
	ws.client.mu.Unlock()

	// Persist config
	if ws.client.configPath != "" {
		common.SaveClientConfig(ws.client.configPath, ws.client.Config)
	}

	// Start client in a new goroutine
	go func() {
		ctx := context.Background()
		// In web mode, we assume TOTP is either in secret or not needed for initial prompt
		// If manual token is needed, web mode should have a way to provide it, but for now
		// we rely on TOTPSecretKey.
		ws.client.Start(ctx, "")
	}()

	w.WriteHeader(http.StatusOK)
}

func (ws *WebServer) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ws.client.Stop()
	w.WriteHeader(http.StatusOK)
}
