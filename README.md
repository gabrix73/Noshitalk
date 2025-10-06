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

Verify:
```bash
tor --version  # Expected: 0.4.x+
go version     # Expected: 1.19+
```

#### 2. Clone repository

```bash
cd ~
git clone https://github.com/gabrix73/Noshitalk.git
cd Noshitalk
```

#### 3. Build with hardened flags

```bash
go build \
  -ldflags="-s -w" \
  -trimpath \
  -buildmode=pie \
  -o noshitalk-server \
  noshitalk-web-client.go
```

**Build flags:**
- `-ldflags="-s -w"`: Strip symbols and DWARF tables
- `-trimpath`: Remove filesystem paths
- `-buildmode=pie`: Position-independent executable (ASLR)

#### 4. Configure Tor

Edit configuration:
```bash
sudo nano /etc/tor/torrc
```

Add:
```
HiddenServiceDir /var/lib/tor/noshitalk/
HiddenServicePort 8080 127.0.0.1:8080
```

Restart Tor:
```bash
sudo systemctl restart tor
sudo systemctl enable tor
```

Retrieve .onion address:
```bash
sudo cat /var/lib/tor/noshitalk/hostname
```

#### 5. Create systemd service

```bash
sudo nano /etc/systemd/system/noshitalk.service
```

Configuration:
```ini
[Unit]
Description=NoshiTalk Server
After=network.target tor.service
Requires=tor.service

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/home/YOUR_USERNAME/Noshitalk
ExecStart=/home/YOUR_USERNAME/Noshitalk/noshitalk-server
Restart=always
RestartSec=10

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/home/YOUR_USERNAME/Noshitalk

[Install]
WantedBy=multi-user.target
```

Replace `YOUR_USERNAME` with actual username.

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable noshitalk
sudo systemctl start noshitalk
```

Check status:
```bash
sudo systemctl status noshitalk
```

#### 6. Configure firewall

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw enable
```

Note: No incoming ports required (Tor handles routing).

#### 7. Verify

Access via Tor Browser:
```
http://YOUR_ONION_ADDRESS.onion
```

---

## Architecture

### Decentralization

Each server operates independently. No federation protocol implemented (servers do not communicate). Users connect directly to specific .onion addresses.

**Network characteristics:**
- No single point of failure
- Geographic/jurisdictional distribution
- Each instance sets own policies

### Cryptographic Implementation

**Identity:** Ed25519 public key hash serves as user identifier

**Key Exchange:** ECDH X25519 generates shared secret

**Encryption:** AES-256-GCM with derived keys

**Authentication:** Challenge-response using Ed25519 signatures

**Transport:** Tor v3 hidden services

### Zero-Knowledge Design

Server cannot:
- Decrypt message content (E2E encrypted)
- Log IP addresses (Tor anonymization)
- Access private keys (client-side generation)
- Store messages (RAM only, no database)

### Client Implementation

**Web:** JavaScript WebCrypto API, keys in browser memory

**Desktop:** Go native with memguard (encrypted RAM)

**CLI:** Go terminal interface

All clients generate keys locally and support .noshikey file export.

---

## Configuration

### Performance Tuning

For high-traffic servers, increase file descriptor limits:

```bash
sudo nano /etc/security/limits.conf
```

Add:
```
YOUR_USERNAME soft nofile 65535
YOUR_USERNAME hard nofile 65535
```

### Monitoring

View logs:
```bash
sudo journalctl -u noshitalk -f
```

Check Tor:
```bash
sudo systemctl status tor
```

### Updates

```bash
cd ~/Noshitalk
git pull
go build -ldflags="-s -w" -trimpath -buildmode=pie -o noshitalk-server noshitalk-web-client.go
sudo systemctl restart noshitalk
```

---

## Troubleshooting

### Server fails to start

Check logs:
```bash
sudo journalctl -u noshitalk -n 50
```

Common causes:
- Tor not running: `sudo systemctl start tor`
- Port conflict: Change port or kill conflicting process
- Permission errors: Verify systemd service user

### Tor connection issues

Verify Tor status:
```bash
sudo systemctl status tor
```

Check Tor logs:
```bash
sudo journalctl -u tor -f
```

Verify hidden service:
```bash
sudo ls -la /var/lib/tor/noshitalk/
```

### Client connection failures

1. Verify .onion address: `sudo cat /var/lib/tor/noshitalk/hostname`
2. Check server listening: `sudo netstat -tlnp | grep 8080`
3. Test locally: `curl -x socks5h://localhost:9050 http://YOUR_ONION.onion`

---

## Technical Specifications

| Component | Algorithm | Key Size |
|-----------|-----------|----------|
| Identity | Ed25519 | 256-bit |
| Key Exchange | ECDH X25519 | 256-bit |
| Encryption | AES-GCM | 256-bit |
| Authentication | HMAC-SHA256 | 256-bit |
| Transport | Tor v3 | - |

**Language:** Go

**License:** MIT

---

## Security

### Threat Model

**Protected against:**
- Network surveillance (Tor)
- Server compromise (E2E encryption)
- Metadata harvesting (zero-knowledge design)

**Not protected against:**
- Client device compromise
- Physical device seizure
- Social engineering
- Global passive adversary

### Memory Protection

**Desktop client:** memguard encrypts key material in RAM

**Web client:** Keys cleared on disconnect/panic

### Build Security

Recommended compilation:
```bash
go build -ldflags="-s -w" -trimpath -buildmode=pie
```

This enables:
- ASLR (Address Space Layout Randomization)
- Symbol stripping (reduced attack surface)
- Path obfuscation (information disclosure prevention)

---

## Contributing

1. Fork repository
2. Create feature branch
3. Commit changes
4. Open pull request

### Development

```bash
git clone https://github.com/gabrix73/Noshitalk.git
cd Noshitalk
go mod download
go test ./...
```

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
