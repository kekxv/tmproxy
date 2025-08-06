package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

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

func (s *Server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `
	<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Admin Dashboard</title>
		<style>
			body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background-color: #f0f2f5; color: #333; }
			.container { max-width: 1200px; margin: 2em auto; padding: 20px; background-color: #fff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
			h1, h2 { color: #0056b3; border-bottom: 2px solid #eee; padding-bottom: 10px; margin-top: 1.5em; }
			table { border-collapse: collapse; width: 100%; margin-top: 1em; box-shadow: 0 2px 8px rgba(0,0,0,0.05); border-radius: 8px; overflow: hidden; }
			th, td { border: 1px solid #e0e0e0; padding: 12px 15px; text-align: left; }
			th { background-color: #e9f5ff; font-weight: bold; color: #0056b3; }
			tr:nth-child(even) { background-color: #f9f9f9; }
			tr:hover { background-color: #f1f1f1; }
			button { background-color: #007bff; color: white; border: none; padding: 8px 12px; border-radius: 5px; cursor: pointer; font-size: 0.9em; transition: background-color 0.2s ease; margin-right: 5px; }
			button:hover { background-color: #0056b3; }
			button.disconnect { background-color: #dc3545; }
			button.disconnect:hover { background-color: #c82333; }
		</style>
	</head>
	<body>
		<div class="container">
		<h1>Admin Dashboard</h1>
		<h2>Connected Clients</h2>
		<table id="clients-table">
			<thead>
				<tr>
					<th>ID</th>
					<th>Remote Address</th>
					<th>Connected At</th>
					<th>Forwards</th>
					<th>Actions</th>
				</tr>
			</thead>
			<tbody></tbody>
		</table>

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
			<tbody></tbody>
		</table>
		</div>

		<script>
			async function fetchData() {
				const clientsRes = await fetch("/api/admin/clients");
				const clients = await clientsRes.json();
				const clientsTbody = document.getElementById("clients-table").querySelector("tbody");
				clientsTbody.innerHTML = "";
				for (const client of clients) {
					const forwards = Object.entries(client.forwards).map(([remote, local]) => remote + " -> " + local).join(", ");
					const row = clientsTbody.insertRow();
					row.innerHTML = '<td>' + client.id + '</td><td>' + client.remote_addr + '</td><td>' + new Date(client.connected_at).toLocaleString() + '</td><td>' + forwards + '</td><td><button onclick="addForward(\'' + client.id + '\')">Add Forward</button> <button onclick="disconnect(\'' + client.id + '\', \'client\')">Disconnect</button></td>';
				}

				const connectionsRes = await fetch("/api/admin/connections");
				const connections = await connectionsRes.json();
				const connectionsTbody = document.getElementById("connections-table").querySelector("tbody");
				connectionsTbody.innerHTML = "";
				for (const conn of connections) {
					const row = connectionsTbody.insertRow();
					row.innerHTML = '<td>' + conn.id + '</td><td>' + conn.tunnel_id + '</td><td>' + conn.client_addr + '</td><td>' + conn.server_addr + '</td><td>' + new Date(conn.connected_at).toLocaleString() + '</td><td><button onclick="disconnect(\'' + conn.id + '\', \'connection\')">Disconnect</button></td>';
				}
			}

			async function addForward(clientId) {
				const remotePort = prompt("Enter remote port:");
				const localAddr = prompt("Enter local address (e.g., localhost:3000):");
				if (remotePort && localAddr) {
					const res = await fetch("/api/admin/forwards", {
						method: "POST",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify({ client_id: clientId, remote_port: parseInt(remotePort), local_addr: localAddr })
					});
					if (res.ok) {
						fetchData();
					} else {
						const errorData = await res.json();
						alert(errorData.message || "Failed to add forward");
					}
				}
			}

			async function disconnect(id, type) {
				if (confirm('Are you sure you want to disconnect this ' + type + '?')) {
					const res = await fetch("/api/admin/disconnect", {
						method: "POST",
						headers: { "Content-Type": "application/json" },
						body: JSON.stringify({ id, type })
					});
					if (res.ok) {
						fetchData();
					} else {
						const errorData = await res.json();
						alert(errorData.message || 'Failed to disconnect ' + type);
					}
				}
			}

			fetchData();
			setInterval(fetchData, 5000);
		</script>
	</body>
	</html>
	`)
}

func (s *Server) handleApiClients(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	clients := make([]*ClientInfo, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}

	json.NewEncoder(w).Encode(clients)
}

func (s *Server) handleApiConnections(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	connections := make([]*TCPConnectionInfo, 0, len(s.activeTCPConnections))
	for _, conn := range s.activeTCPConnections {
		connections = append(connections, conn)
	}

	json.NewEncoder(w).Encode(connections)
}

func (s *Server) handleAddForward(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ClientID   string `json:"client_id"`
		RemotePort int    `json:"remote_port"`
		LocalAddr  string `json:"local_addr"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	client, ok := s.clients[req.ClientID]
	if !ok {
		s.mu.Unlock()
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	msg := common.Message{Type: "add_proxy", Payload: common.AddProxy{RemotePort: req.RemotePort, LocalAddr: req.LocalAddr}}
	if err := client.Conn.WriteJSON(msg); err != nil {
		s.mu.Unlock()
		log.Printf("Failed to send add_proxy message to client %s: %v", req.ClientID, err)
		http.Error(w, "Failed to send message to client", http.StatusInternalServerError)
		return
	}

	client.Forwards[req.RemotePort] = req.LocalAddr
	s.mu.Unlock()

	go s.startProxyListener(client, req.RemotePort)

	w.WriteHeader(http.StatusOK)
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

	s.mu.Lock()
	defer s.mu.Unlock()

	switch req.Type {
	case "client":
		if client, ok := s.clients[req.ID]; ok {
			client.Conn.Close()
			delete(s.clients, req.ID)
			delete(s.connToClientID, client.Conn)
			for _, listener := range client.Listeners {
				listener.Close()
			}
		}
	case "connection":
		// Iterate through activeTCPConnections to find the matching connection by ID
		// and remove it. Also clean up the corresponding activeTunnel.
		for tunnelID, connInfo := range s.activeTCPConnections {
			if connInfo.ID == req.ID {
				connInfo.PublicConn.Close()
				delete(s.activeTCPConnections, tunnelID)
				// Also clean up the corresponding activeTunnel if it exists
				if tunnelChan, ok := s.activeTunnels[tunnelID]; ok {
					select {
					case publicConn := <-tunnelChan:
						publicConn.Close()
					default:
					}
					delete(s.activeTunnels, tunnelID)
				}
				break
			}
		}
	}

	w.WriteHeader(http.StatusOK)
}
