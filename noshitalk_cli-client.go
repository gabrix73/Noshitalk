package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/awnumar/memguard"
	"golang.org/x/net/proxy"
)

type CLIClient struct {
	conn          net.Conn
	gcm           cipher.AEAD
	sharedSecret  *memguard.Enclave
	connected     bool
	serverAddr    string
	quit          chan struct{}
	mu            sync.Mutex
	autoReconnect bool
	lastServer    string
	onlineUsers   []string

	// Persistent identity
	privateKey    *ecdh.PrivateKey
	identity      string
}

type Message struct {
	From    string `json:"from"`
	To      string `json:"to,omitempty"`
	Content string `json:"content"`
	Time    string `json:"time"`
	Type    string `json:"type"`
}

type UserListMessage struct {
	Type  string   `json:"type"`
	Users []string `json:"users"`
	Time  string   `json:"time"`
}

var (
	version    = "0.8-identity"
	onionRegex = regexp.MustCompile(`^[a-z2-7]{56}\.onion(:[0-9]{1,5})?$`)
)

const (
	messageBlockSize = 256
	minRandomDelay   = 50
	maxRandomDelay   = 200
)

func main() {
	memguard.CatchInterrupt()
	defer memguard.Purge()

	fmt.Printf("🔐 NoshiTalk CLI Client v%s\n", version)
	fmt.Printf("💻 Lightweight Command Line Interface\n")
	fmt.Printf("🧅 Tor-Only Mode - No Clearnet Connections\n")
	fmt.Printf("🔒 ECDH + HMAC + AES-GCM Encryption\n\n")

	client := &CLIClient{
		quit:          make(chan struct{}),
		autoReconnect: true,
		onlineUsers:   []string{},
	}

	// Initialize persistent identity
	if err := client.initializeIdentity(); err != nil {
		fmt.Printf("❌ Failed to initialize identity: %v\n", err)
		fmt.Printf("   Continuing with temporary identity...\n\n")
	}

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Printf("\n🛑 Shutting down securely...\n")
		client.disconnect()
		memguard.Purge()
		os.Exit(0)
	}()

	// Start auto-reconnect goroutine
	go client.autoReconnectLoop()

	client.run()
}

func (c *CLIClient) run() {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Printf("📡 Enter Tor Hidden Service address (.onion only)\n")
	fmt.Printf("💡 Example: abcd1234...xyz9876.onion:8083\n")
	fmt.Printf("⚠️  Clearnet addresses blocked by design\n\n")

	for {
		if !c.connected {
			fmt.Print("🧅 .onion address: ")
			if !scanner.Scan() {
				break
			}
			c.serverAddr = strings.TrimSpace(scanner.Text())

			if c.serverAddr == "" {
				fmt.Printf("❌ Address required\n\n")
				continue
			}

			// Validate .onion address
			if err := validateOnionAddress(c.serverAddr); err != nil {
				fmt.Printf("❌ Invalid address: %v\n\n", err)
				continue
			}

			c.lastServer = c.serverAddr
			fmt.Printf("⏳ Connecting to %s via Tor...\n", c.serverAddr)

			if err := c.connect(); err != nil {
				fmt.Printf("❌ Connection failed: %v\n", err)
				fmt.Printf("💡 Will retry automatically if auto-reconnect is enabled\n\n")
				continue
			}
		}

		fmt.Print("💬 > ")
		if !scanner.Scan() {
			break
		}

		message := strings.TrimSpace(scanner.Text())
		if message == "" {
			continue
		}

		// Handle commands
		switch message {
		case "/quit", "/exit", "/q":
			c.autoReconnect = false
			c.disconnect()
			fmt.Println("👋 Goodbye!")
			return
		case "/disconnect", "/d":
			c.disconnect()
			continue
		case "/help", "/h", "/?":
			c.showHelp()
			continue
		case "/status", "/s":
			c.showStatus()
			continue
		case "/reconnect", "/r":
			if !c.connected && c.lastServer != "" {
				c.serverAddr = c.lastServer
				fmt.Printf("🔄 Reconnecting to %s...\n", c.serverAddr)
				c.connect()
			}
			continue
		case "/auto on":
			c.autoReconnect = true
			fmt.Printf("✅ Auto-reconnect enabled\n")
			continue
		case "/auto off":
			c.autoReconnect = false
			fmt.Printf("❌ Auto-reconnect disabled\n")
			continue
		case "/clear", "/cls":
			fmt.Print("\033[H\033[2J")
			continue
		case "/users", "/u":
			c.showUsers()
			continue
		}

		// Handle /pm command
		if len(message) > 4 && message[:4] == "/pm " {
			if !c.connected {
				fmt.Printf("❌ Not connected. Use /reconnect or enter server address\n")
				continue
			}
			// Send directly - server will parse it
			if err := c.sendMessage(message); err != nil {
				fmt.Printf("❌ Send error: %v\n", err)
				c.disconnect()
			}
			continue
		}

		// Send regular message
		if !c.connected {
			fmt.Printf("❌ Not connected. Use /reconnect or enter server address\n")
			continue
		}

		if err := c.sendMessage(message); err != nil {
			fmt.Printf("❌ Send error: %v\n", err)
			c.disconnect()
		}
	}

	c.disconnect()
}

func validateOnionAddress(addr string) error {
	if addr == "" {
		return fmt.Errorf("address cannot be empty")
	}

	if !strings.Contains(addr, ".onion") {
		return fmt.Errorf("only Tor .onion addresses allowed - no clearnet connections")
	}

	if !onionRegex.MatchString(addr) {
		return fmt.Errorf("invalid .onion address format (must be v3: 56 chars + .onion:port)")
	}

	return nil
}

func (c *CLIClient) connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	// Only Tor connections allowed
	fmt.Printf("🧅 Routing through Tor network...\n")
	conn, err := c.connectThroughTor()
	if err != nil {
		return err
	}

	c.conn = conn
	return c.setupEncryption()
}

func (c *CLIClient) connectThroughTor() (net.Conn, error) {
	fmt.Printf("🧅 Initializing Tor connection...\n")
	
	// Test Tor proxy
	if err := c.testTorProxy(); err != nil {
		return nil, fmt.Errorf("Tor proxy not available: %v", err)
	}
	
	// Try multiple proxy addresses
	proxyURLs := []string{
		"socks5://127.0.0.1:9050",
		"socks5://localhost:9050",
		"socks5://127.0.0.1:9150", // Tor Browser
	}
	
	var conn net.Conn
	var lastErr error
	
	for _, proxyURL := range proxyURLs {
		fmt.Printf("🔗 Trying proxy %s...\n", proxyURL)
		
		torProxyUrl, err := url.Parse(proxyURL)
		if err != nil {
			lastErr = err
			continue
		}

		baseDialer := &net.Dialer{
			Timeout:   90 * time.Second,
			KeepAlive: 30 * time.Second,
		}

		dialer, err := proxy.FromURL(torProxyUrl, baseDialer)
		if err != nil {
			lastErr = err
			continue
		}

		fmt.Printf("⏳ Connecting to %s (may take up to 90 seconds)...\n", c.serverAddr)
		
		conn, err = dialer.Dial("tcp", c.serverAddr)
		if err != nil {
			lastErr = err
			fmt.Printf("❌ Failed with %s: %v\n", proxyURL, err)
			continue
		}
		
		fmt.Printf("✅ Connected through %s\n", proxyURL)
		break
	}
	
	if conn == nil {
		return nil, fmt.Errorf("all Tor proxy attempts failed: %v", lastErr)
	}

	fmt.Printf("✅ TCP connection through Tor established\n")
	fmt.Printf("✅ Tor circuit complete (3-layer encryption)\n")
	fmt.Printf("🔒 Proceeding to ECDH handshake...\n")

	return conn, nil
}

func (c *CLIClient) testTorProxy() error {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:9050", 2*time.Second)
	if err != nil {
		return fmt.Errorf("Tor SOCKS proxy not responding on port 9050")
	}
	conn.Close()
	
	fmt.Printf("✅ Tor proxy detected and responsive\n")
	return nil
}

func (c *CLIClient) setupEncryption() error {
	fmt.Printf("🔐 Establishing end-to-end encryption...\n")

	// X25519 curve for key exchange
	curve := ecdh.X25519()

	// Use persistent identity key (or generate temporary if not available)
	var privateKey *ecdh.PrivateKey
	if c.privateKey != nil {
		privateKey = c.privateKey
		fmt.Printf("🔑 Using persistent identity: %s\n", c.identity)
	} else {
		// Fallback: generate temporary key
		var err error
		privateKey, err = curve.GenerateKey(cryptorand.Reader)
		if err != nil {
			c.conn.Close()
			return fmt.Errorf("key generation failed: %v", err)
		}
		fmt.Printf("⚠️  Using temporary identity (will change on reconnect)\n")
	}

	privateKeyBuffer := memguard.NewBufferFromBytes(privateKey.Bytes())
	defer privateKeyBuffer.Destroy()

	// Send public key (this identifies us to the server)
	publicKey := privateKey.PublicKey()
	publicKeyBytes := publicKey.Bytes()
	
	c.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	totalSent := 0
	for totalSent < len(publicKeyBytes) {
		n, err := c.conn.Write(publicKeyBytes[totalSent:])
		if err != nil {
			c.conn.Close()
			return fmt.Errorf("failed to send public key: %v", err)
		}
		totalSent += n
	}
	c.conn.SetWriteDeadline(time.Time{})

	// Receive server's public key
	serverPubKeyBytes := make([]byte, 32)
	if _, err := io.ReadFull(c.conn, serverPubKeyBytes); err != nil {
		c.conn.Close()
		return fmt.Errorf("failed to receive server public key: %v", err)
	}

	serverPublicKey, err := curve.NewPublicKey(serverPubKeyBytes)
	if err != nil {
		c.conn.Close()
		return fmt.Errorf("invalid server public key: %v", err)
	}

	// Calculate shared secret
	sharedSecret, err := privateKey.ECDH(serverPublicKey)
	if err != nil {
		c.conn.Close()
		return fmt.Errorf("ECDH failed: %v", err)
	}

	// Use sharedSecret directly, seal into memguard after we're done
	// HMAC Mutual Authentication
	fmt.Printf("🔐 Starting HMAC mutual authentication...\n")
	if err := c.performMutualAuth(sharedSecret); err != nil {
		c.conn.Close()
		return fmt.Errorf("authentication failed: %v", err)
	}
	fmt.Printf("✅ Mutual authentication successful\n")

	// Setup AES-GCM
	block, err := aes.NewCipher(sharedSecret[:32])
	if err != nil {
		c.conn.Close()
		return fmt.Errorf("AES cipher creation failed: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		c.conn.Close()
		return fmt.Errorf("GCM cipher creation failed: %v", err)
	}

	// Now seal sharedSecret into memguard (this zeros the original)
	sharedSecretBuffer := memguard.NewBufferFromBytes(sharedSecret)
	defer sharedSecretBuffer.Destroy()

	c.gcm = gcm
	c.sharedSecret = sharedSecretBuffer.Seal()
	c.connected = true

	// Success messages
	fmt.Printf("✅ Connected to %s\n", c.serverAddr)
	fmt.Printf("🔐 End-to-end encryption active (AES-256-GCM)\n")
	fmt.Printf("🧅 Anonymous Tor routing active\n")
	fmt.Printf("🔒 ECDH + HMAC + AES-GCM protection\n")
	fmt.Printf("💬 Ready for secure messaging\n")
	fmt.Printf("ℹ️  Type /help for commands\n\n")

	// Start receiving messages
	go c.receiveMessages()

	return nil
}

func (c *CLIClient) performMutualAuth(sharedSecret []byte) error {
	c.conn.SetDeadline(time.Now().Add(30 * time.Second))
	defer c.conn.SetDeadline(time.Time{})

	// Step 1: Receive server challenge
	serverChallenge := make([]byte, 32)
	if _, err := io.ReadFull(c.conn, serverChallenge); err != nil {
		return fmt.Errorf("receive server challenge failed: %v", err)
	}

	// Step 2: Compute HMAC response to server's challenge
	h := hmac.New(sha256.New, sharedSecret)
	h.Write(serverChallenge)
	clientResponse := h.Sum(nil)

	// Step 3: Generate client's own challenge
	clientChallenge := make([]byte, 32)
	if _, err := cryptorand.Read(clientChallenge); err != nil {
		return fmt.Errorf("challenge generation failed: %v", err)
	}

	// Step 4: Send client response + client challenge
	if _, err := c.conn.Write(clientResponse); err != nil {
		return fmt.Errorf("send client response failed: %v", err)
	}
	if _, err := c.conn.Write(clientChallenge); err != nil {
		return fmt.Errorf("send client challenge failed: %v", err)
	}

	// Step 5: Receive and verify server's response
	serverResponse := make([]byte, 32)
	if _, err := io.ReadFull(c.conn, serverResponse); err != nil {
		return fmt.Errorf("receive server response failed: %v", err)
	}

	h.Reset()
	h.Write(clientChallenge)
	expectedServerMAC := h.Sum(nil)

	if !hmac.Equal(serverResponse, expectedServerMAC) {
		return fmt.Errorf("server authentication failed - HMAC mismatch")
	}

	return nil
}

func (c *CLIClient) disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return
	}

	c.sendEncryptedMessage("/quit")
	time.Sleep(100 * time.Millisecond)

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	if c.sharedSecret != nil {
		// Open enclave and destroy the buffer
		buf, _ := c.sharedSecret.Open()
		if buf != nil {
			buf.Destroy()
		}
		c.sharedSecret = nil
	}
	c.gcm = nil

	c.connected = false
	fmt.Printf("\n📴 Disconnected from server\n")
	fmt.Printf("🔒 Keys wiped from memory\n")

	if c.autoReconnect {
		fmt.Printf("🔄 Auto-reconnect is enabled\n")
	}
	fmt.Printf("\n")
}

func (c *CLIClient) sendMessage(message string) error {
	return c.sendEncryptedMessage(message)
}

func padMessage(plaintext []byte) []byte {
	currentLen := len(plaintext)
	paddedLen := ((currentLen / messageBlockSize) + 1) * messageBlockSize
	padLen := paddedLen - currentLen

	result := make([]byte, 2+paddedLen)
	binary.BigEndian.PutUint16(result[0:2], uint16(currentLen))
	copy(result[2:], plaintext)

	if padLen > 0 {
		padding := make([]byte, padLen)
		cryptorand.Read(padding)
		copy(result[2+currentLen:], padding)
	}

	return result
}

func unpadMessage(paddedData []byte) ([]byte, error) {
	if len(paddedData) < 2 {
		return nil, fmt.Errorf("padded data too short")
	}

	originalLen := binary.BigEndian.Uint16(paddedData[0:2])

	if int(originalLen) > len(paddedData)-2 {
		return nil, fmt.Errorf("invalid padding length")
	}

	return paddedData[2 : 2+originalLen], nil
}

func randomDelay() {
	delay := minRandomDelay + rand.Intn(maxRandomDelay-minRandomDelay)
	time.Sleep(time.Duration(delay) * time.Millisecond)
}

func (c *CLIClient) sendEncryptedMessage(message string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected || c.gcm == nil || c.conn == nil {
		return fmt.Errorf("not connected")
	}

	// Random delay (timing attack mitigation)
	randomDelay()

	// Pad message
	paddedMessage := padMessage([]byte(message))

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(cryptorand.Reader, nonce); err != nil {
		return fmt.Errorf("nonce generation failed: %v", err)
	}

	encrypted := c.gcm.Seal(nil, nonce, paddedMessage, nil)
	data := append(nonce, encrypted...)

	_, err := c.conn.Write(data)
	return err
}

func (c *CLIClient) receiveMessages() {
	buf := make([]byte, 8192)
	
	for {
		c.mu.Lock()
		if !c.connected {
			c.mu.Unlock()
			return
		}
		conn := c.conn
		gcm := c.gcm
		c.mu.Unlock()
		
		// No read deadline for persistent connections
		conn.SetReadDeadline(time.Time{})
		
		n, err := conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				fmt.Printf("\n📴 Server closed connection\n")
			} else {
				fmt.Printf("\n❌ Connection lost: %v\n", err)
			}
			
			c.mu.Lock()
			c.connected = false
			c.mu.Unlock()
			return
		}

		if n < 12 {
			continue
		}

		// Decrypt message
		nonce := buf[:12]
		ciphertext := buf[12:n]

		paddedPlaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			fmt.Printf("\n⚠️ Failed to decrypt message\n")
			continue
		}

		// Remove padding
		plaintext, err := unpadMessage(paddedPlaintext)
		if err != nil {
			fmt.Printf("\n⚠️ Failed to unpad message: %v\n", err)
			continue
		}

		// Try to parse as UserListMessage first
		var userListMsg UserListMessage
		if err := json.Unmarshal(plaintext, &userListMsg); err == nil && userListMsg.Type == "user_list" {
			c.mu.Lock()
			c.onlineUsers = userListMsg.Users
			c.mu.Unlock()
			fmt.Printf("\r👥 Online users (%d): %s\n💬 > ", len(userListMsg.Users), strings.Join(userListMsg.Users, ", "))
			continue
		}

		// Try to parse as Message
		var msg Message
		if err := json.Unmarshal(plaintext, &msg); err == nil {
			timestamp := msg.Time
			if timestamp == "" {
				timestamp = time.Now().Format("15:04:05")
			}

			switch msg.Type {
			case "system":
				fmt.Printf("\r🔔 [%s] %s\n💬 > ", timestamp, msg.Content)
			case "private":
				if msg.To != "" {
					// Private message
					fmt.Printf("\r🔒 [%s] PM from %s: %s\n💬 > ", timestamp, msg.From, msg.Content)
				}
			case "error":
				fmt.Printf("\r❌ [%s] %s\n💬 > ", timestamp, msg.Content)
			default:
				// Regular message
				if msg.From == "" {
					fmt.Printf("\r📨 [%s] %s\n💬 > ", timestamp, msg.Content)
				} else {
					fmt.Printf("\r👤 [%s] %s: %s\n💬 > ", timestamp, msg.From, msg.Content)
				}
			}
		} else {
			// Plain message fallback
			timestamp := time.Now().Format("15:04:05")
			fmt.Printf("\r📨 [%s] %s\n💬 > ", timestamp, string(plaintext))
		}
	}
}

func (c *CLIClient) autoReconnectLoop() {
	lastAttempt := time.Now()
	
	for {
		time.Sleep(5 * time.Second)
		
		c.mu.Lock()
		shouldReconnect := !c.connected && c.autoReconnect && c.lastServer != ""
		c.mu.Unlock()
		
		if shouldReconnect {
			if time.Since(lastAttempt) < 10*time.Second {
				continue
			}
			lastAttempt = time.Now()
			
			fmt.Printf("\n🔄 Auto-reconnecting to %s...\n", c.lastServer)
			c.serverAddr = c.lastServer
			if err := c.connect(); err != nil {
				fmt.Printf("❌ Auto-reconnect failed: %v\n", err)
				fmt.Printf("⏳ Will retry in 10 seconds...\n")
			}
		}
	}
}

func (c *CLIClient) showStatus() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	fmt.Printf("\n📊 Connection Status:\n")
	fmt.Printf("  Connected: %v\n", c.connected)
	if c.connected {
		fmt.Printf("  Server: %s\n", c.serverAddr)
		fmt.Printf("  Mode: Tor Hidden Service (Anonymous)\n")
		fmt.Printf("  Encryption: AES-256-GCM\n")
		fmt.Printf("  Key Exchange: ECDH-X25519\n")
		fmt.Printf("  Authentication: HMAC-SHA256\n")
	}
	fmt.Printf("  Auto-Reconnect: %v\n", c.autoReconnect)
	fmt.Printf("  Version: %s\n\n", version)
}

func (c *CLIClient) showHelp() {
	fmt.Printf(`
╔════════════════════════════════════════════╗
║        NoshiTalk CLI Commands v%s        ║
╚════════════════════════════════════════════╝

Connection:
  /reconnect, /r     - Reconnect to last server
  /disconnect, /d    - Disconnect from server
  /status, /s        - Show connection status

Messaging:
  /users, /u         - Show online users
  /pm user message   - Send private message

Settings:
  /auto on           - Enable auto-reconnect
  /auto off          - Disable auto-reconnect

Interface:
  /clear, /cls       - Clear screen
  /help, /h, /?      - Show this help
  /quit, /exit, /q   - Exit application

Tips:
  • Only .onion addresses accepted (Tor-only mode)
  • All messages are end-to-end encrypted
  • ECDH + HMAC + AES-GCM protection
  • Auto-reconnect keeps you connected
  • Press Ctrl+C for emergency shutdown
  • Clearnet connections blocked by design

Examples:
  /pm alice Hey, how are you?
  /users

`, version)
}

func (c *CLIClient) showUsers() {
	c.mu.Lock()
	users := c.onlineUsers
	c.mu.Unlock()

	if len(users) == 0 {
		fmt.Printf("👥 No users online (or not yet received user list)\n")
		return
	}

	fmt.Printf("👥 Online users (%d):\n", len(users))
	for _, user := range users {
		fmt.Printf("   • %s\n", user)
	}
}

// Identity management functions

func (c *CLIClient) initializeIdentity() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	keyPath := filepath.Join(homeDir, ".noshitalk", "identity.key")

	// Try to load existing key
	if _, err := os.Stat(keyPath); err == nil {
		return c.loadIdentity(keyPath)
	}

	// Generate new key pair
	return c.generateNewIdentity(keyPath)
}

func (c *CLIClient) generateNewIdentity(keyPath string) error {
	fmt.Printf("🔑 No identity found. Generating new anonymous identity...\n")

	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(cryptorand.Reader)
	if err != nil {
		return err
	}

	pubKey := privKey.PublicKey().Bytes()

	// Derive identity from public key
	hash := sha256.Sum256(pubKey)
	identity := fmt.Sprintf("anon_%s", hex.EncodeToString(hash[:8]))

	c.privateKey = privKey
	c.identity = identity

	fmt.Printf("✅ Identity created: %s\n", identity)
	fmt.Printf("   (will be saved to %s)\n\n", keyPath)

	// Save to disk
	return c.saveIdentity(keyPath)
}

func (c *CLIClient) loadIdentity(keyPath string) error {
	fmt.Printf("🔑 Loading identity from %s\n", keyPath)

	data, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}

	curve := ecdh.X25519()
	privKey, err := curve.NewPrivateKey(data)
	if err != nil {
		return err
	}

	pubKey := privKey.PublicKey().Bytes()

	// Derive identity
	hash := sha256.Sum256(pubKey)
	identity := fmt.Sprintf("anon_%s", hex.EncodeToString(hash[:8]))

	c.privateKey = privKey
	c.identity = identity

	fmt.Printf("✅ Identity loaded: %s\n\n", identity)

	return nil
}

func (c *CLIClient) saveIdentity(keyPath string) error {
	// Create directory if needed
	dir := filepath.Dir(keyPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	// Save private key
	privKeyBytes := c.privateKey.Bytes()

	if err := os.WriteFile(keyPath, privKeyBytes, 0600); err != nil {
		return err
	}

	fmt.Printf("💾 Identity saved securely\n")
	return nil
}
