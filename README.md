# Noshitalk
NoshiTalk is a zero-knowledge, end-to-end encrypted messaging system designed for maximum privacy and security. Built with Go, it operates seamlessly over Tor hidden services and implements military-grade cryptography with perfect forward secrecy.

🌟 Features
🔒 Uncompromising Security

End-to-End Encryption: ECDH key exchange + AES-256-GCM
Perfect Forward Secrecy: New keys for every session
TLS 1.3: Modern secure transport layer
Memory Protection: Secure key handling with memguard
Zero-Knowledge Architecture: Server learns nothing about messages

🧅 Complete Anonymity

Native Tor Support: Built-in .onion routing
No Logs Policy: Zero data retention
Anonymous Identities: Random user IDs per session
No Registration: Connect and chat instantly
Auto-Wipe: Session data destroyed on disconnect

💪 Reliability & Performance

Persistent Connections: No timeouts, infinite session support
Auto-Reconnection: Intelligent connection recovery
Heartbeat Protocol: Keep-alive mechanism
Low Latency: Optimized for Tor networks
Cross-Platform: Linux, macOS, Windows support

🚀 Quick Start
Prerequisites

Go 1.21 or higher
Tor (for .onion connections)
Git

Installation
bash# Clone the repository
git clone https://github.com/gabrix73/noshitalk.git
cd noshitalk

# Install dependencies
go mod init noshitalk
go get github.com/awnumar/memguard
go get fyne.io/fyne/v2
go get golang.org/x/net/proxy

# Build server
go build -trimpath -ldflags="-s -w" -o noshitalk-server server.go

# Build client (requires CGO for GUI)
CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o noshitalk-client client.go
📖 Usage
Starting the Server
bash# Standard mode
./noshitalk-server

# The server will:
# - Generate self-signed certificates (first run)
# - Listen on port 8083
# - Accept connections via Tor or direct
Running the Client
bash# Launch GUI client
./noshitalk-client

# Connect to:
# - Local server: localhost:8083
# - Tor hidden service: xyz123.onion:8083
Tor Hidden Service Setup

Install Tor:

bash# Debian/Ubuntu
sudo apt install tor

# macOS
brew install tor

# Start Tor
tor

Configure Hidden Service (/etc/tor/torrc):

bashHiddenServiceDir /var/lib/tor/noshitalk/
HiddenServicePort 8083 127.0.0.1:8083

Get your .onion address:

bashsudo cat /var/lib/tor/noshitalk/hostname
🔧 Configuration
Server Options
ParameterDefaultDescriptionPort8083Listening portTLSAuto-generatedECC certificatesTimeoutNonePersistent connectionsLoggingDisabledZero-knowledge policy
Client Features

Auto-Reconnect: Checkbox to enable/disable
Debug Log: Real-time connection monitoring
Secure Input: Encrypted before leaving client
Message History: Session-only, wiped on disconnect

🏗️ Architecture
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│   Client A   │◄────────┤   Server     ├────────►│   Client B   │
├──────────────┤  ECDH + │              │  ECDH + ├──────────────┤
│  AES-256-GCM │  TLS 1.3│  Zero-Trust  │  TLS 1.3│  AES-256-GCM │
│   memguard   │◄────────┤  No Storage  ├────────►│   memguard   │
└──────────────┘   Tor   └──────────────┘   Tor   └──────────────┘
Cryptographic Flow

TLS Handshake: Establish secure channel
ECDH Exchange: Generate shared secret (X25519)
Key Derivation: Create AES-256-GCM key
Message Encryption: AES-256-GCM with random nonce
Forward Secrecy: Keys destroyed on disconnect

🔮 Roadmap
v0.2 - Quantum Resistance (In Development)

 McEliece post-quantum cryptography
 Hybrid classical-quantum encryption
 Independent from NIST curves

v0.3 - Secure File Transfer

 End-to-end encrypted file sharing
 Chunked transfer protocol
 Integrity verification (BLAKE3)

v0.4 - Multimedia Support

 Encrypted audio/video streaming
 WebRTC integration
 Opus/AV1 codecs

v0.5 - Advanced Steganography

 Hide messages in images
 Drag & drop interface
 Multiple encoding algorithms

🛡️ Security Considerations
What NoshiTalk Protects Against
✅ Message Interception: End-to-end encryption
✅ Traffic Analysis: Tor routing
✅ Identity Correlation: Anonymous, ephemeral IDs
✅ Memory Forensics: Secure key wiping
✅ Replay Attacks: Nonce-based encryption
✅ Future Decryption: Perfect forward secrecy
Operational Security (OPSEC)

Always verify .onion addresses out-of-band
Use Tor Browser for additional anonymity
Run on trusted, encrypted systems
Consider using Tails OS for maximum security
Never share session identifiers

🤝 Contributing
Contributions are welcome! Please ensure:

Code follows Go best practices
Security is never compromised for features
All cryptographic changes are peer-reviewed
Tests pass and coverage remains high

📄 License
MIT License - See LICENSE file for details
⚠️ Disclaimer
NoshiTalk is provided as-is for educational and legitimate privacy purposes. Users are responsible for complying with local laws and regulations. The developers assume no liability for misuse.
🙏 Acknowledgments

memguard - Secure memory handling
Fyne - Native Go GUI framework
Tor Project - Anonymous communication
Cryptography community for peer review

📞 Contact

Security Issues: Open a private security advisory
Feature Requests: Use GitHub Issues
General Discussion: GitHub Discussions


Remember: True security comes from good OPSEC, not just good crypto.
🔐 Stay Secure, Stay Anonymous, Use NoshiTalk
