# tmproxy: 轻量级反向代理工具

![Go-Proxy Logo](https://raw.githubusercontent.com/your-username/tmproxy/main/docs/logo.png) <!-- 如果您添加了Logo，请替换此占位符 -->

## 🚀 项目概述

tmproxy 是一个轻量级、安全且易于分发的反向代理（或内网穿透）工具，旨在帮助用户临时或长期地将内网服务暴露到公网，而无需复杂的配置。其核心优势在于**单文件分发**：客户端和服务器端功能都集成在同一个可执行文件中，用户下载后无需安装任何额外依赖即可运行。

## ✨ 核心特性

*   **单文件解决方案**: 客户端和服务器端逻辑编译到单个 Go 二进制文件中。
*   **动态 TOTP 认证**: 使用基于时间的一次性密码（TOTP）进行安全认证，降低密钥泄露风险。
*   **自动配置生成**: 服务器首次启动时，自动生成包含随机 TOTP 密钥的 `config.json` 配置文件。
*   **Web 引导页面**: 服务器提供一个简单的 HTTP/S 页面，包含客户端使用说明和动态下载命令。
*   **跨平台支持**: 得益于 Go 语言，可轻松交叉编译以支持 Linux, Windows, macOS 等主流操作系统。
*   **安全加固**: 内置连接数限制、认证超时以及对恶意输入的防御机制。
*   **WSS/HTTPS 支持**: 当提供 TLS 证书时，支持安全的 WebSocket (WSS) 和 HTTPS 连接。

## 📦 快速开始

### 前提条件

*   [Go](https://golang.org/doc/install) (1.20 或更高版本) 用于构建。

### 构建项目

1.  克隆仓库:
    ```bash
    git clone https://github.com/your-username/tmproxy.git
    cd tmproxy
    ```
2.  下载依赖:
    ```bash
    go mod tidy
    ```
3.  构建可执行文件:
    ```bash
    go build -o tmproxy main.go
    ```
    这将在当前目录中创建一个 `tmproxy` (Windows 上为 `tmproxy.exe`) 可执行文件。

### 运行服务器

以服务器模式启动 tmproxy:

```bash
./tmproxy server
```

**首次运行**: 首次运行时，`config.json` 将在同一目录中自动生成。它将包含一个 `TOTP_SECRET_KEY` 和一个二维码 URI。**请使用您的身份验证器应用（例如 Google Authenticator）扫描此二维码，以获取您的 6 位 TOTP 码。**

**配置 (`config.json`)**:

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

*   `LISTEN_ADDR`: 服务器将监听的地址和端口。
*   `MAX_CLIENTS`: 最大并发客户端连接数。
*   `WEBSOCKET_PATH`: WebSocket 端点路径。
*   `DEFAULT_REMOTE_PORT`: 客户端请求的默认公共端口。
*   `DEFAULT_LOCAL_PORT`: 客户端的默认本地服务端口。
*   `TOTP_SECRET_KEY`: 用于 TOTP 认证的密钥。**请勿共享此密钥！**
*   `TLS_CERT_FILE`: TLS 证书文件的路径（例如 `server.crt`）。留空表示使用 HTTP/WS。
*   `TLS_KEY_FILE`: TLS 私钥文件的路径（例如 `server.key`）。留空表示使用 HTTP/WS。

**对于 HTTPS/WSS**: 将您的 `server.crt` 和 `server.key` 文件放在与 `config.json` 相同的目录中，并更新 `config.json` 中的 `TLS_CERT_FILE` 和 `TLS_KEY_FILE`。

### 运行客户端

启动服务器后，在 Web 浏览器中打开其主页（例如 `http://localhost:8001`）。页面将提供动态的 `curl` 命令，用于下载适用于您特定操作系统和架构的客户端。

**客户端命令示例（来自服务器主页）**:

```bash
./tmproxy client --server ws://your-server-ip:8001/proxy_ws --local localhost:3000 --remote 8080
```

当提示时，输入您的身份验证器应用中的 6 位 TOTP 码。

### 分发客户端

为了实现可靠的客户端分发，请将您的交叉编译的二进制文件（例如 `tmproxy-linux-amd64`, `tmproxy-windows-amd64.exe`）放置在服务器可执行文件相对的 `clients/` 目录中。然后，服务器将在客户端通过 `os` 和 `arch` 查询参数请求时，提供这些特定的二进制文件。

## ⚙️ 开发

### 项目结构

```
.github/
└── workflows/
    └── release.yml # 用于自动化构建和发布的 GitHub Actions
clients/            # 预构建客户端二进制文件的目录
common/             # 共享代码（配置、协议、代理逻辑）
    ├── config.go
    ├── protocol.go
    ├── proxy.go
    └── ..._test.go
client/             # 客户端逻辑
    └── client.go
server/             # 服务器逻辑
    ├── server.go
    └── ..._test.go
main.go             # 主入口点
go.mod              # Go 模块文件
go.sum              # Go 模块校验和
README.md           # 本文件
config.json         # 服务器配置（自动生成）
```

### 运行测试

```bash
cd tmproxy
go test ./...
```

## 🚀 自动化发布 (GitHub Actions)

`.github/workflows/release.yml` 工作流自动化了构建和发布过程。当您推送新的 Git 标签（例如 `v1.0.0`）时，它将:

1.  为 `amd64` 和 `arm64` 架构构建跨平台二进制文件（Linux, Windows, macOS）。
2.  创建一个新的 GitHub Release。
3.  将编译后的二进制文件作为资产上传到 Release。

触发发布:

```bash
git tag v1.0.0
git push origin v1.0.0
```

## 🤝 贡献

欢迎贡献！请随时提交问题或拉取请求。

## 📄 许可证

本项目采用 MIT 许可证 - 详情请参阅 [LICENSE](LICENSE) 文件。 <!-- 如果您还没有创建 LICENSE 文件，请创建一个 -->
