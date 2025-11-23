# NoshiTalk Production Deployment Guide for Debian

## Overview
This guide covers deployment of NoshiTalk server on Debian with:
- Non-privileged user: `noshitalk`
- Home directory: `/var/lib/noshitalk`
- Tor Hidden Service integration
- systemd service management

---

## 1. System Preparation

### 1.1 Update System
```bash
sudo apt update && sudo apt upgrade -y
```

### 1.2 Install Dependencies
```bash
# Build tools and Go
sudo apt install -y build-essential git curl wget

# Install Go 1.21+ (check latest version)
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/golang.sh
source /etc/profile.d/golang.sh

# Verify Go installation
go version
```

### 1.3 Install Tor
```bash
# Add Tor repository
sudo apt install -y apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/tor.list
wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --dearmor | sudo tee /usr/share/keyrings/tor-archive-keyring.gpg >/dev/null

# Install Tor
sudo apt update
sudo apt install -y tor deb.torproject.org-keyring
```

---

## 2. Create NoshiTalk User

```bash
# Create system user with home in /var/lib/noshitalk
sudo useradd --system \
    --home-dir /var/lib/noshitalk \
    --create-home \
    --shell /usr/sbin/nologin \
    --comment "NoshiTalk Chat Server" \
    noshitalk

# Set ownership
sudo chown -R noshitalk:noshitalk /var/lib/noshitalk
sudo chmod 750 /var/lib/noshitalk

# Create required directories
sudo -u noshitalk mkdir -p /var/lib/noshitalk/{bin,keys,logs}
sudo chmod 700 /var/lib/noshitalk/keys
```

---

## 3. Build NoshiTalk

### 3.1 Clone and Build
```bash
# Clone repository (as root or admin user)
cd /opt
sudo git clone https://github.com/gabrix73/Noshitalk.git noshitalk
sudo chown -R noshitalk:noshitalk /opt/noshitalk

# Build as noshitalk user
sudo -u noshitalk bash -c 'cd /opt/noshitalk && make build-all'

# Copy binaries
sudo cp /opt/noshitalk/bin/noshitalk-server /var/lib/noshitalk/bin/
sudo cp /opt/noshitalk/bin/noshitalk-web /var/lib/noshitalk/bin/
sudo chown noshitalk:noshitalk /var/lib/noshitalk/bin/*
sudo chmod 750 /var/lib/noshitalk/bin/*
```

### 3.2 Alternative: Build from Source Directly
```bash
# If you have the source files, copy them to /opt/noshitalk/
# Then build:
cd /opt/noshitalk
sudo -u noshitalk go mod download
sudo -u noshitalk make server web-client
```

---

## 4. Configure Tor Hidden Service

### 4.1 Edit Tor Configuration
```bash
sudo nano /etc/tor/torrc
```

Add at the end:
```
# NoshiTalk Hidden Service
HiddenServiceDir /var/lib/tor/noshitalk/
HiddenServicePort 8083 127.0.0.1:8083
```

### 4.2 Apply Tor Configuration
```bash
# Restart Tor to create hidden service
sudo systemctl restart tor

# Wait for hidden service to be created
sleep 5

# Get your .onion address
sudo cat /var/lib/tor/noshitalk/hostname
```

**IMPORTANT**: Save the `.onion` address - this is your server's anonymous address.

### 4.3 Secure Tor Hidden Service
```bash
# Backup hidden service keys (store securely!)
sudo cp -r /var/lib/tor/noshitalk /root/noshitalk-tor-backup/
sudo chmod 700 /root/noshitalk-tor-backup
```

---

## 5. Create systemd Services

### 5.1 NoshiTalk Server Service
```bash
sudo nano /etc/systemd/system/noshitalk-server.service
```

Content:
```ini
[Unit]
Description=NoshiTalk Encrypted Chat Server
After=network.target tor.service
Wants=tor.service

[Service]
Type=simple
User=noshitalk
Group=noshitalk
WorkingDirectory=/var/lib/noshitalk
ExecStart=/var/lib/noshitalk/bin/noshitalk-server
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/noshitalk
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=noshitalk-server

[Install]
WantedBy=multi-user.target
```

### 5.2 NoshiTalk Web Service (Optional)
```bash
sudo nano /etc/systemd/system/noshitalk-web.service
```

Content:
```ini
[Unit]
Description=NoshiTalk Web Client Server
After=network.target

[Service]
Type=simple
User=noshitalk
Group=noshitalk
WorkingDirectory=/var/lib/noshitalk
ExecStart=/var/lib/noshitalk/bin/noshitalk-web
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/noshitalk
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

StandardOutput=journal
StandardError=journal
SyslogIdentifier=noshitalk-web

[Install]
WantedBy=multi-user.target
```

### 5.3 Enable and Start Services
```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable services
sudo systemctl enable noshitalk-server
sudo systemctl enable noshitalk-web  # optional

# Start services
sudo systemctl start noshitalk-server
sudo systemctl start noshitalk-web   # optional

# Check status
sudo systemctl status noshitalk-server
sudo systemctl status noshitalk-web
```

---

## 6. Firewall Configuration

### 6.1 UFW (Recommended)
```bash
# Install UFW
sudo apt install -y ufw

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (adjust port if needed)
sudo ufw allow 22/tcp

# NoshiTalk only listens on localhost (127.0.0.1:8083)
# No need to open external ports - Tor handles routing

# Enable firewall
sudo ufw enable
sudo ufw status verbose
```

### 6.2 iptables Alternative
```bash
# Block all incoming except SSH
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -j DROP

# Save rules
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

---

## 7. Monitoring and Maintenance

### 7.1 View Logs
```bash
# Server logs
sudo journalctl -u noshitalk-server -f

# Web client logs
sudo journalctl -u noshitalk-web -f

# Tor logs
sudo journalctl -u tor -f

# Combined view
sudo journalctl -u noshitalk-server -u tor -f
```

### 7.2 Health Check Script
```bash
sudo nano /var/lib/noshitalk/bin/healthcheck.sh
```

Content:
```bash
#!/bin/bash
# NoshiTalk Health Check

SERVER_PORT=8083
ONION_FILE="/var/lib/tor/noshitalk/hostname"

echo "=== NoshiTalk Health Check ==="
echo "Date: $(date)"
echo ""

# Check services
echo "Services:"
systemctl is-active --quiet noshitalk-server && echo "  [OK] noshitalk-server" || echo "  [FAIL] noshitalk-server"
systemctl is-active --quiet tor && echo "  [OK] tor" || echo "  [FAIL] tor"
echo ""

# Check ports
echo "Ports:"
netstat -tlnp 2>/dev/null | grep -q ":$SERVER_PORT" && echo "  [OK] Port $SERVER_PORT listening" || echo "  [FAIL] Port $SERVER_PORT not listening"
echo ""

# Check Tor hidden service
echo "Tor Hidden Service:"
if [ -f "$ONION_FILE" ]; then
    echo "  [OK] .onion address: $(cat $ONION_FILE)"
else
    echo "  [FAIL] Hidden service not configured"
fi
echo ""

# Memory usage
echo "Memory:"
ps aux | grep noshitalk-server | grep -v grep | awk '{print "  Server: " $6/1024 " MB"}'
echo ""

echo "=== End Health Check ==="
```

```bash
sudo chmod +x /var/lib/noshitalk/bin/healthcheck.sh
sudo chown noshitalk:noshitalk /var/lib/noshitalk/bin/healthcheck.sh
```

### 7.3 Cron Jobs
```bash
# Edit crontab
sudo crontab -u noshitalk -e
```

Add:
```cron
# Health check every hour
0 * * * * /var/lib/noshitalk/bin/healthcheck.sh >> /var/lib/noshitalk/logs/healthcheck.log 2>&1

# Log rotation
0 0 * * * find /var/lib/noshitalk/logs -type f -mtime +7 -delete
```

---

## 8. Security Hardening

### 8.1 System Hardening
```bash
# Disable unnecessary services
sudo systemctl disable bluetooth
sudo systemctl disable cups

# SSH hardening
sudo nano /etc/ssh/sshd_config
```

Recommended SSH settings:
```
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
AllowUsers your_admin_user
```

### 8.2 Automatic Updates
```bash
# Install unattended-upgrades
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

### 8.3 Fail2ban
```bash
sudo apt install -y fail2ban

# Create jail for SSH
sudo nano /etc/fail2ban/jail.local
```

Content:
```ini
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
```

```bash
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

---

## 9. Backup Strategy

### 9.1 Automated Backup Script
```bash
sudo nano /var/lib/noshitalk/bin/backup.sh
```

Content:
```bash
#!/bin/bash
# NoshiTalk Backup Script

BACKUP_DIR="/var/backups/noshitalk"
DATE=$(date +%Y%m%d_%H%M%S)
TOR_DIR="/var/lib/tor/noshitalk"

mkdir -p $BACKUP_DIR

# Backup Tor hidden service keys (CRITICAL)
sudo tar -czf $BACKUP_DIR/tor-keys-$DATE.tar.gz $TOR_DIR

# Backup NoshiTalk configuration (if any)
tar -czf $BACKUP_DIR/noshitalk-config-$DATE.tar.gz /var/lib/noshitalk/keys/

# Set permissions
chmod 600 $BACKUP_DIR/*.tar.gz

# Keep only last 7 backups
find $BACKUP_DIR -type f -mtime +7 -delete

echo "Backup completed: $DATE"
```

```bash
sudo chmod +x /var/lib/noshitalk/bin/backup.sh
```

### 9.2 Add to Cron
```bash
# Daily backup at 3 AM
0 3 * * * /var/lib/noshitalk/bin/backup.sh >> /var/lib/noshitalk/logs/backup.log 2>&1
```

---

## 10. Testing

### 10.1 Test Server
```bash
# Check if server is running
sudo systemctl status noshitalk-server

# Check listening port
sudo ss -tlnp | grep 8083

# Test local connection (from server)
nc -zv 127.0.0.1 8083
```

### 10.2 Test via Tor (from another machine)
```bash
# Get your .onion address
ONION=$(sudo cat /var/lib/tor/noshitalk/hostname)
echo "Your server: $ONION"

# Test with CLI client (from client machine)
./noshitalk-cli
# Enter: <your-onion-address>:8083
```

---

## 11. Troubleshooting

### Common Issues

**Server won't start:**
```bash
# Check logs
sudo journalctl -u noshitalk-server -n 50

# Check permissions
ls -la /var/lib/noshitalk/bin/
sudo -u noshitalk /var/lib/noshitalk/bin/noshitalk-server
```

**Tor hidden service not working:**
```bash
# Check Tor status
sudo systemctl status tor
sudo journalctl -u tor -n 50

# Verify hidden service directory
sudo ls -la /var/lib/tor/noshitalk/
```

**Can't connect from client:**
```bash
# Verify Tor is running on client
systemctl status tor

# Test SOCKS proxy
curl --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip
```

---

## 12. Directory Structure Summary

```
/var/lib/noshitalk/
├── bin/
│   ├── noshitalk-server      # Main server binary
│   ├── noshitalk-web         # Web client binary (optional)
│   ├── healthcheck.sh        # Health check script
│   └── backup.sh             # Backup script
├── keys/                      # Identity keys (if any)
└── logs/
    ├── healthcheck.log
    └── backup.log

/var/lib/tor/noshitalk/
├── hostname                   # Your .onion address
├── hs_ed25519_public_key     # Hidden service public key
└── hs_ed25519_secret_key     # Hidden service private key (BACKUP!)

/etc/systemd/system/
├── noshitalk-server.service
└── noshitalk-web.service

/etc/tor/torrc                 # Tor configuration
```

---

## Quick Reference Commands

```bash
# Start/Stop/Restart
sudo systemctl start noshitalk-server
sudo systemctl stop noshitalk-server
sudo systemctl restart noshitalk-server

# View logs
sudo journalctl -u noshitalk-server -f

# Get .onion address
sudo cat /var/lib/tor/noshitalk/hostname

# Health check
sudo /var/lib/noshitalk/bin/healthcheck.sh

# Rebuild
cd /opt/noshitalk && sudo -u noshitalk make clean build-all
sudo cp /opt/noshitalk/bin/noshitalk-server /var/lib/noshitalk/bin/
sudo systemctl restart noshitalk-server
```
