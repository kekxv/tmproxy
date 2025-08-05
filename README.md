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
  "DEFAULT_REMOTE_PORT": 8080,
  "DEFAULT_LOCAL_PORT": 3000,
  "TOTP_SECRET_KEY": "RANDOM_BASE32_ENCODED_STRING",
  "TLS_CERT_FILE": "",
  "TLS_KEY_FILE": ""
}
```

*   `LISTEN_ADDR`: The address and port the server will listen on.
*   `MAX_CLIENTS`: Maximum concurrent client connections.
*   `WEBSOCKET_PATH`: The WebSocket endpoint path.
*   `DEFAULT_REMOTE_PORT`: Default public port requested by clients.
*   `DEFAULT_LOCAL_PORT`: Default local service port for clients.
*   `TOTP_SECRET_KEY`: The secret key for TOTP authentication. **DO NOT SHARE THIS!**
*   `TLS_CERT_FILE`: Path to your TLS certificate file (e.g., `server.crt`). Leave empty for HTTP/WS.
*   `TLS_KEY_FILE`: Path to your TLS private key file (e.g., `server.key`). Leave empty for HTTP/WS.

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
