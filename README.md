# tmproxy: Lightweight Reverse Proxy Tool

![Go-Proxy Logo](https://raw.githubusercontent.com/your-username/tmproxy/main/docs/logo.png) <!-- Placeholder for a logo if you add one -->

## 🚀 Project Overview

tmproxy is a lightweight, secure, and easy-to-distribute reverse proxy (or intranet penetration) tool designed to temporarily or permanently expose internal services to the public network without complex configurations. Its core strength lies in its **single-file distribution**: both client and server functionalities are integrated into a single executable, requiring no additional dependencies for users.

## ✨ Core Features

*   **Single-File Solution**: Client and server logic compiled into one Go binary.
*   **Dynamic TOTP Authentication**: Secure authentication using Time-based One-Time Passwords to mitigate key leakage risks.
*   **Automatic Configuration**: Server automatically generates `config.json` with a random TOTP key on first run.
*   **Web-based Client Guidance**: Server provides a simple HTTP/S page with instructions and dynamic download commands for the client.
*   **Cross-Platform Support**: Easily cross-compile for Linux, Windows, macOS, and other major operating systems.
*   **Secure & Robust**: Includes connection limits, authentication timeouts, and defense mechanisms against malicious input.
*   **WSS/HTTPS Support**: Supports secure WebSocket (WSS) and HTTPS connections when TLS certificates are provided.

## 🔀 HTTP/HTTPS Proxy Mode

tmproxy can also function as a secure, authenticated HTTP/HTTPS proxy. This allows you to route traffic from any application that supports HTTP proxies through a specific `tmproxy` client, effectively giving you a secure entry point into that client's network.

### How It Works

1.  **Configuration**: You define a list of `PROXY_USERS` with usernames and passwords in the server's `config.json`.
2.  **Authentication**: When a proxy request is made (e.g., via `curl`), the server authenticates the user against the `PROXY_USERS` list.
3.  **Client Association**: A `tmproxy` client must connect to the server using the *same username* to associate itself with that proxy user.
4.  **Request Forwarding**: The server forwards the HTTP/HTTPS request to the associated client via the secure WebSocket tunnel.
5.  **Execution & Response**: The client executes the request in its local network and sends the response back to the server, which then returns it to the original requester.

### Configuration

To enable the proxy, add a `PROXY_USERS` array to your `config.json`:

```json
{
  ...
  "PROXY_USERS": [
    {
      "username": "user1",
      "password": "a_very_strong_password"
    },
    {
      "username": "user2",
      "password": "another_secret_password"
    }
  ],
  ...
}
```

**Important**: When `PROXY_USERS` is configured, the server will operate in a dual mode:
*   Requests with a `Proxy-Authorization` header will be treated as proxy requests.
*   All other requests will be served the standard web interface.

### Running the Client for Proxy Mode

The client must connect with a username that matches one in the `PROXY_USERS` list. Use the `--proxy_user` and `--proxy_passwd` flags:

```bash
./tmproxy client --server ws://your-server-ip:8001/proxy_ws --proxy_user user1 --proxy_passwd a_very_strong_password
```

This command connects the client and tells the server, "I am the endpoint for all proxy requests authenticated as `user1`."

### Using the Proxy

Once the client is connected, you can use the server as a standard HTTP/HTTPS proxy:

```bash
# Example for HTTP
curl -v -x http://user1:a_very_strong_password@your-server-ip:8001 http://httpbin.org/get

# Example for HTTPS (CONNECT tunnel)
curl -v -x http://user1:a_very_strong_password@your-server-ip:8001 https://httpbin.org/ip
```

### ⚠️ Security Considerations

*   **Enable TLS**: HTTP Basic Authentication is **not encrypted**. For production use, it is **highly recommended** to run the server with TLS enabled (`TLS_CERT_FILE` and `TLS_KEY_FILE`) to protect your proxy credentials.
*   **Strong Passwords**: Use strong, unique passwords for your proxy users.
*   **Log Verbosity**: Be aware that request URLs are logged. In a production environment, consider adjusting log levels or formats to avoid logging sensitive data.

## 📦 Getting Started

### Prerequisites

*   [Go](https://golang.org/doc/install) (version 1.20 or higher) for building.

### Building the Project

1.  Clone the repository:
    ```bash
    git clone https://github.com/your-username/tmproxy.git
    cd tmproxy
    ```
2.  Download dependencies:
    ```bash
    go mod tidy
    ```
3.  Build the executable:
    ```bash
    go build -o tmproxy main.go
    ```
    This will create a `tmproxy` (or `tmproxy.exe` on Windows) executable in the current directory.

### Running the Server

To start the tmproxy in server mode:

```bash
./tmproxy server
```

**First Run**: On the first run, `config.json` will be automatically generated in the same directory. It will contain a `TOTP_SECRET_KEY` and a QR code URI. **Scan this QR code with your authenticator app (e.g., Google Authenticator) to get your 6-digit TOTP codes.**

**Configuration (`config.json`)**:

```json
{
  "LISTEN_ADDR": "0.0.0.0:8001",
  "MAX_CLIENTS": 100,
  "WEBSOCKET_PATH": "/proxy_ws",
  "FORWARD": [
    {
      "REMOTE_PORT": 8080,
      "LOCAL_ADDR": "127.0.0.1:3000"
    }
  ],
  "TOTP_SECRET_KEY": "RANDOM_BASE32_ENCODED_STRING",
  "TLS_CERT_FILE": "",
  "TLS_KEY_FILE": "",
  "ADMIN_USERNAME": "admin",
  "ADMIN_PASSWORD_HASH": "changeme",
  "ADMIN_TOTP_SECRET_KEY": "",
  "ENABLE_ADMIN_TOTP": false
}
```

*   `LISTEN_ADDR`: The address and port the server will listen on.
*   `MAX_CLIENTS`: Maximum concurrent client connections.
*   `WEBSOCKET_PATH`: The WebSocket endpoint path.
*   `FORWARD`: An array of forwarding configurations. Each entry specifies a `REMOTE_PORT` (publicly accessible port on the server) and a `LOCAL_ADDR` (the address of the service on the client machine).
*   `TOTP_SECRET_KEY`: The secret key for TOTP authentication. **DO NOT SHARE THIS!**
*   `TLS_CERT_FILE`: Path to your TLS certificate file (e.g., `server.crt`). Leave empty for HTTP/WS.
*   `TLS_KEY_FILE`: Path to your TLS private key file (e.g., `server.key`). Leave empty for HTTP/WS.
*   `ADMIN_USERNAME`: Username for the admin panel.
*   `ADMIN_PASSWORD_HASH`: BCrypt hash of the admin panel password. Change the default!
*   `ADMIN_TOTP_SECRET_KEY`: TOTP secret key for the admin panel (optional).
*   `ENABLE_ADMIN_TOTP`: Boolean to enable or disable TOTP for the admin panel.

**For HTTPS/WSS**: Place your `server.crt` and `server.key` files in the same directory as `config.json` and update `TLS_CERT_FILE` and `TLS_KEY_FILE` in the config.

### Running the Client

After starting the server, open its homepage in a web browser (e.g., `http://localhost:8001`). The page will provide dynamic `curl` commands to download the client for your specific OS and architecture.

**Example Client Command (from server homepage)**:

```bash
./tmproxy client --server ws://your-server-ip:8001/proxy_ws --local localhost:3000 --remote 8080
```

When prompted, enter the 6-digit TOTP code from your authenticator app.

### Distributing Clients

For robust client distribution, place your cross-compiled binaries (e.g., `tmproxy-linux-amd64`, `tmproxy-windows-amd64.exe`) into a `clients/` directory relative to your server executable. The server will then serve these specific binaries when requested by clients with `os` and `arch` query parameters.

## ⚙️ Development

### Project Structure

```
.github/
└── workflows/
    └── release.yml # GitHub Actions for automated builds and releases
clients/            # Directory for pre-built client binaries
common/             # Shared code (config, protocol, proxy logic)
    ├── config.go
    ├── protocol.go
    ├── proxy.go
    └── ..._test.go
client/             # Client-side logic
    └── client.go
server/             # Server-side logic
    ├── server.go
    └── ..._test.go
main.go             # Main entry point
go.mod              # Go module file
go.sum              # Go module checksums
README.md           # This file
config.json         # Server configuration (auto-generated)
```

### Running Tests

```bash
cd tmproxy
go test ./...
```

## 🚀 Automated Releases (GitHub Actions)

The `.github/workflows/release.yml` workflow automates the build and release process. When you push a new Git tag (e.g., `v1.0.0`), it will:

1.  Build cross-platform binaries (Linux, Windows, macOS) for `amd64` and `arm64` architectures.
2.  Create a new GitHub Release.
3.  Upload the compiled binaries as assets to the release.

To trigger a release:

```bash
git tag v1.0.0
git push origin v1.0.0
```

## 🤝 Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. <!-- Create a LICENSE file if you haven't already -->
