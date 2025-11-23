# NoshiTalk

Self-hosted encrypted chat over Tor with Ed25519 cryptographic identity.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go 1.19+](https://img.shields.io/badge/Go-1.19+-00ADD8)](https://go.dev/)

## Overview

NoshiTalk is a self-hosted instant messaging platform designed for decentralized operation over Tor. Each instance operates independently with no central authority.

**Key characteristics:**
- Ed25519 cryptographic identity (no registration)
- E2E encryption (ECDH X25519 + AES-256-GCM)
- Ephemeral messages (RAM only, no persistence)
- Tor-only routing (.onion hidden services)
- Zero-knowledge server architecture

---

## Project Structure

```
noshitalk/
├── cmd/                    # Application entry points
│   ├── server/            # TCP server for Tor hidden service
│   ├── cli-client/        # Command-line interface client
│   ├── gui-client/        # Desktop GUI client (Fyne)
│   └── web-client/        # Web interface with WebSocket
├── pkg/                    # Shared libraries
│   ├── crypto/            # Encryption, padding, ECDH, HMAC auth
│   ├── protocol/          # Message types and JSON serialization
│   ├── identity/          # Persistent identity management
│   └── tor/               # Tor SOCKS5 proxy utilities
├── Makefile               # Build automation
├── go.mod                 # Go module definition
└── README.md              # This file
```

---

## Quick Start

### Prerequisites

- Go 1.19+
- Tor daemon (for client connections)

### Build

```bash
# Clone repository
git clone https://github.com/gabrix73/Noshitalk.git
cd Noshitalk

# Build all components
make build-all

# Or build individual components
make server        # bin/noshitalk-server
make cli-client    # bin/noshitalk-cli
make gui-client    # bin/noshitalk-gui
make web-client    # bin/noshitalk-web
```

### Run Tests

```bash
make test          # Run all tests
make test-verbose  # Verbose output
make coverage      # Generate HTML coverage report
```

### Available Make Targets

```bash
make help          # Show all available targets
```

| Target | Description |
|--------|-------------|
| `build-all` | Build all components |
| `test` | Run tests with coverage |
| `test-race` | Run tests with race detector |
| `coverage` | Generate HTML coverage report |
| `bench` | Run benchmarks |
| `fmt` | Format code |
| `vet` | Run go vet |
| `clean` | Remove build artifacts |
| `release` | Build for all platforms |

---

## Components

### Server (`cmd/server`)

TCP server designed for Tor hidden service deployment. Handles:
- Client connections via encrypted channel
- Message routing (public and private)
- File transfers
- Ghost mode (invisible users)
- Key rotation

```bash
./bin/noshitalk-server
# Listens on 127.0.0.1:8083
```

### CLI Client (`cmd/cli-client`)

Lightweight terminal-based client:

```bash
./bin/noshitalk-cli
# Enter .onion address when prompted
```

Commands:
- `/help` - Show commands
- `/users` - List online users
- `/pm user message` - Private message
- `/ghost` / `/reveal` - Toggle visibility
- `/quit` - Exit

### GUI Client (`cmd/gui-client`)

Desktop application using Fyne framework:

```bash
./bin/noshitalk-gui
```

Features:
- Visual user list
- Click-to-PM
- Auto-reconnect
- PANIC button (wipe keys)

### Web Client (`cmd/web-client`)

Browser-based interface:

```bash
./bin/noshitalk-web
# Access at http://localhost:8080
```

Features:
- WebSocket communication
- Browser-based key generation
- Export/import .noshikey files

---

## VPS Installation (Debian/Ubuntu)

### Requirements

- Debian 11+ or Ubuntu 20.04+
- 512MB RAM minimum (1GB recommended)
- Tor daemon
- Go 1.19+

### Setup

#### 1. Install dependencies

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y tor golang-go git build-essential
```

#### 2. Clone and build

```bash
cd ~
git clone https://github.com/gabrix73/Noshitalk.git
cd Noshitalk
make server web-client
```

#### 3. Configure Tor

Edit `/etc/tor/torrc`:
```
HiddenServiceDir /var/lib/tor/noshitalk/
HiddenServicePort 8080 127.0.0.1:8080
```

Restart Tor:
```bash
sudo systemctl restart tor
sudo cat /var/lib/tor/noshitalk/hostname  # Get .onion address
```

#### 4. Create systemd service

```bash
sudo nano /etc/systemd/system/noshitalk.service
```

```ini
[Unit]
Description=NoshiTalk Server
After=network.target tor.service
Requires=tor.service

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/home/YOUR_USERNAME/Noshitalk
ExecStart=/home/YOUR_USERNAME/Noshitalk/bin/noshitalk-web
Restart=always
RestartSec=10

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable noshitalk
sudo systemctl start noshitalk
```

---

## Architecture

### Shared Packages

#### `pkg/crypto`
- `PadMessage()` / `UnpadMessage()` - Traffic analysis resistance
- `EncryptMessage()` / `DecryptMessage()` - AES-256-GCM
- `PerformClientAuth()` / `PerformServerAuth()` - HMAC mutual auth
- `GenerateX25519KeyPair()` / `PerformECDH()` - Key exchange
- `RandomDelay()` - Timing attack mitigation

#### `pkg/protocol`
- `Message` - Chat message structure
- `UserListMessage` - Online users
- `FileOfferMessage` / `FileChunkMessage` - File transfers
- `KeyRotationMessage` - Forward secrecy

#### `pkg/identity`
- `New()` - Generate new identity
- `Load()` / `Save()` - Persistent storage
- `LoadOrCreate()` - Auto-initialize

#### `pkg/tor`
- `ValidateOnionAddress()` - v3 .onion validation
- `Connect()` - SOCKS5 proxy connection
- `Dialer` - Reusable connection helper

### Cryptographic Flow

```
Client                              Server
  |                                   |
  |------ Connect via Tor:9050 ----->|
  |------ Public Key (32B) --------->|
  |<----- Public Key (32B) ----------|
  |       [ECDH Shared Secret]       |
  |<----- Challenge (32B) -----------|
  |------ HMAC Response (32B) ------>|
  |------ Challenge (32B) ---------->|
  |<----- HMAC Response (32B) -------|
  |       [AES-256-GCM Session]      |
  |<===== Encrypted Messages =======>|
```

### Zero-Knowledge Design

Server cannot:
- Decrypt message content (E2E encrypted)
- Log IP addresses (Tor anonymization)
- Access private keys (client-side generation)
- Store messages (RAM only)

---

## Technical Specifications

| Component | Algorithm | Key Size |
|-----------|-----------|----------|
| Identity | Ed25519 | 256-bit |
| Key Exchange | ECDH X25519 | 256-bit |
| Encryption | AES-GCM | 256-bit |
| Authentication | HMAC-SHA256 | 256-bit |
| Transport | Tor v3 | - |
| Padding | 256-byte blocks | - |

---

## Security

### Threat Model

**Protected against:**
- Network surveillance (Tor)
- Server compromise (E2E encryption)
- Metadata harvesting (zero-knowledge)
- Traffic analysis (message padding)
- Timing attacks (random delays)

**Not protected against:**
- Client device compromise
- Physical device seizure
- Social engineering

### Memory Protection

- **Desktop/CLI:** memguard encrypts keys in RAM
- **Web:** Keys cleared on disconnect/panic
- **All:** Random padding prevents size analysis

---

## Development

### Running Tests

```bash
make test          # Quick test
make test-verbose  # Detailed output
make test-race     # Race condition detection
make coverage      # HTML report in coverage/
make bench         # Performance benchmarks
```

### Code Quality

```bash
make fmt           # Format code
make vet           # Static analysis
make lint          # golangci-lint (if installed)
```

### Building Releases

```bash
make release       # Builds for Linux, macOS, Windows (amd64/arm64)
```

---

## Contributing

1. Fork repository
2. Create feature branch
3. Run `make test` and `make fmt`
4. Commit changes
5. Open pull request

### Security Issues

Report to: security@virebent.art

Do not open public issues for vulnerabilities.

---

## License

MIT License. See [LICENSE](LICENSE) file.

---

## Links

- Documentation: [virebent.art/noshitalk.html](https://virebent.art/noshitalk.html)
- Repository: [github.com/gabrix73/Noshitalk](https://github.com/gabrix73/Noshitalk)
- Issues: [github.com/gabrix73/Noshitalk/issues](https://github.com/gabrix73/Noshitalk/issues)
