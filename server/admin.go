package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gemini-cli/tmproxy/common"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

func (s *Server) handleAdminLoginPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Admin Login</title>
		<style>
			body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; background-color: #f4f4f4; margin: 0; }
			.login-container { background-color: #fff; padding: 2em; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 300px; text-align: center; }
			h1 { color: #333; margin-bottom: 1em; }
			input[type="text"], input[type="password"] { width: calc(100% - 20px); padding: 10px; margin-bottom: 1em; border: 1px solid #ddd; border-radius: 4px; }
			button { width: 100%; padding: 10px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 1em; }
			button:hover { background-color: #0056b3; }
			.error-message { color: red; margin-top: 1em; }
		</style>
	</head>
	<body>
		<div class="login-container">
			<h1>Admin Login</h1>
			<input type="text" id="username" placeholder="Username">
			<input type="password" id="password" placeholder="Password">
			<input type="text" id="totp" placeholder="TOTP (if enabled)">
			<button onclick="login()">Login</button>
			<p id="error-message" class="error-message"></p>
		</div>

		<script>
			async function login() {
				const username = document.getElementById("username").value;
				const password = document.getElementById("password").value;
				const totp = document.getElementById("totp").value;
				const errorMessage = document.getElementById("error-message");

				errorMessage.textContent = ""; // Clear previous errors

				const res = await fetch("/api/admin/login", {
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ username, password, totp })
				});

				if (res.ok) {
					window.location.href = "/admin"; // Redirect to dashboard on success
				} else {
					const errorData = await res.json();
					errorMessage.textContent = errorData.message || "Login failed";
				}
			}
		</script>
	</body>
	</html>
	`)
}

func (s *Server) handleApiClients(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()

	clients := make([]*ClientInfo, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}

	s.mu.Unlock()

	json.NewEncoder(w).Encode(clients)
}

func (s *Server) handleApiConnections(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()

	connections := make([]*TCPConnectionInfo, 0, len(s.activeTCPConnections))
	for _, conn := range s.activeTCPConnections {
		connections = append(connections, conn)
	}

	s.mu.Unlock()

	json.NewEncoder(w).Encode(connections)
}

func (s *Server) handleAddForward(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ClientID   string `json:"client_id"`
		RemotePort int    `json:"remote_port"`
		LocalAddr  string `json:"local_addr"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Invalid request body"})
		return
	}

	s.mu.Lock()
	client, ok := s.clients[req.ClientID]
	if !ok {
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "Client not found"})
		return
	}

	// This logic is similar to handling 'proxy_request' from a client
	found := false
	for i, forward := range client.Forwards {
		if forward.REMOTE_PORT == req.RemotePort {
			// Update existing forward
			client.Forwards[i].LOCAL_ADDR = req.LocalAddr
			found = true
			log.Printf("Admin: Local address for remote port %d changed to %s. Restarting listener.", req.RemotePort, req.LocalAddr)
			if listener, listenerOk := client.Listeners[req.RemotePort]; listenerOk {
				listener.Close() // Close the old listener
				delete(client.Listeners, req.RemotePort)
				log.Printf("Admin: Closed existing listener for remote port %d.", req.RemotePort)
			}
			break
		}
	}
	if !found {
		// Add new forward
		client.Forwards = append(client.Forwards, common.ForwardConfig{REMOTE_PORT: req.RemotePort, LOCAL_ADDR: req.LocalAddr})
	}
	s.mu.Unlock()

	go s.startProxyListener(client, req.RemotePort, req.LocalAddr)

	// Notify the client about the change.
	// This is important so the client knows which local address to use for the new forward.
	// We'll send a message with all current forwards.
	client.sendChan <- common.Message{Type: "forwards_updated", Payload: client.Forwards}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

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

	if creds.Username != s.config.ADMIN_USERNAME || creds.Password != s.config.ADMIN_PASSWORD_HASH {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"message": "Invalid credentials"})
		return
	}

	if s.config.ENABLE_ADMIN_TOTP {
		if !totp.Validate(creds.TOTP, s.config.ADMIN_TOTP_SECRET_KEY) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"message": "Invalid TOTP token"})
			return
		}
	}

	sessionToken := uuid.New().String()
	s.mu.Lock()
	s.adminSessions[sessionToken] = true
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) handleGetTOTP(w http.ResponseWriter, r *http.Request) {
	if s.config.TOTP_SECRET_KEY == "" {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"message": "Client TOTP secret key is not set."})
		return
	}

	totpCode, err := totp.GenerateCode(s.config.TOTP_SECRET_KEY, time.Now())
	if err != nil {
		log.Printf("Error generating client TOTP code: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"message": "Failed to generate client TOTP code."})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"totp": totpCode})
}

func (s *Server) requireAdminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("admin_session")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}

		s.mu.Lock()
		if !s.adminSessions[cookie.Value] {
			s.mu.Unlock()
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}
		s.mu.Unlock()

		next.ServeHTTP(w, r)
	}
}
