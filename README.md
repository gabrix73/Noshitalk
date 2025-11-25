# NoshiTalk v2.0.0 - Zero-Knowledge Encrypted Chat

Sistema di chat sicuro con crittografia end-to-end e architettura zero-knowledge.

## Caratteristiche

- **End-to-End Encryption**: X25519 ECDH + AES-GCM-256
- **Perfect Forward Secrecy**: Chiavi effimere per ogni sessione
- **Zero-Knowledge Server**: Il server è un relay cieco - non può leggere i messaggi
- **Memory Protection**: memguard per protezione della memoria
- **Zero Logging**: Nessun dato viene salvato su disco
- **Tor Ready**: Configurabile come hidden service

## Architettura

```
Browser (Web Crypto API)
    ↓ SSE (Server-Sent Events) + HTTP POST
Go Server (blind relay)
    ↓ SSE + POST
Browser (Web Crypto API)
```

La crittografia avviene interamente nel browser:
1. Il browser genera keypair X25519 effimero
2. Scambia chiavi pubbliche con altri utenti via server
3. Deriva shared secret con ECDH
4. Cripta/decripta messaggi con AES-GCM-256

Il server vede solo blob crittografati.

## Build

```bash
# Richiede Go 1.21+
go mod tidy
CGO_ENABLED=0 go build -ldflags="-s -w" -o noshitalk main.go
```

## Esecuzione

```bash
# Default porta 8080
./noshitalk

# Porta custom
NOSHITALK_PORT=3000 ./noshitalk
```

## Deployment con Tor Hidden Service

1. Installa Tor:
```bash
apt install tor
```

2. Configura `/etc/tor/torrc`:
```
HiddenServiceDir /var/lib/tor/noshitalk/
HiddenServicePort 80 127.0.0.1:8080
```

3. Riavvia Tor:
```bash
systemctl restart tor
```

4. Ottieni indirizzo .onion:
```bash
cat /var/lib/tor/noshitalk/hostname
```

## Deployment con Apache (opzionale)

```apache
<VirtualHost *:443>
    ServerName chat.example.com
    
    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem
    
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/
    
    # SSE requires no buffering
    SetEnv proxy-sendchunked 1
    SetEnv proxy-nokeepalive 1
</VirtualHost>
```

## Systemd Service

Crea `/etc/systemd/system/noshitalk.service`:

```ini
[Unit]
Description=NoshiTalk Secure Chat
After=network.target

[Service]
Type=simple
User=noshitalk
ExecStart=/opt/noshitalk/noshitalk
Restart=on-failure
RestartSec=5
Environment=NOSHITALK_PORT=8080

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable noshitalk
systemctl start noshitalk
```

## API Endpoints

| Endpoint | Method | Descrizione |
|----------|--------|-------------|
| `/` | GET | Interfaccia web |
| `/join` | POST | Entra in chat |
| `/leave` | POST | Esci dalla chat |
| `/events` | GET | SSE stream messaggi |
| `/send` | POST | Invia messaggio |
| `/key-exchange` | GET/POST | Scambio chiavi pubbliche |
| `/health` | GET | Health check |

## Sicurezza

- **Browser**: Web Crypto API per X25519/AES-GCM (nativo, no librerie esterne)
- **Server**: memguard per protezione memoria, cleanup sicuro
- **Rete**: Supporto TLS, Tor hidden service
- **Policy**: Zero logging, auto-purge alla disconnessione

## File

```
noshitalk-web/
├── main.go              # Server Go con SSE
├── static/
│   └── index.html       # Frontend con Web Crypto API
├── go.mod
├── go.sum
└── README.md
```

## Note

- Il browser DEVE supportare Web Crypto API con X25519 (Chrome 113+, Firefox 72+)
- Per browser più vecchi, considera fallback a curve25519-js (non incluso)
- La chat pubblica attualmente usa encryption semplificata per demo
- Per produzione seria, implementa proper group encryption (Signal Protocol)

## Licenza

MIT
