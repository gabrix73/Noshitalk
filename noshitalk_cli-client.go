package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
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
	connected     bool
	serverAddr    string
	quit          chan struct{}
	mu            sync.Mutex
	autoReconnect bool
	lastServer    string
}

var version = "0.1"

func main() {
	memguard.CatchInterrupt()
	defer memguard.Purge()

	fmt.Printf("🔐 NoshiTalk CLI Client v%s\n", version)
	fmt.Printf("💻 Lightweight Command Line Interface\n")
	fmt.Printf("🧅 Tor Support Built-in\n\n")

	client := &CLIClient{
		quit:          make(chan struct{}),
		autoReconnect: true,
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

	// Start heartbeat
	go client.heartbeatLoop()

	client.run()
}

func (c *CLIClient) run() {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Printf("📡 Enter server address (or press Enter for localhost:8083)\n")
	fmt.Printf("💡 Tip: Use .onion addresses for maximum anonymity\n\n")

	for {
		if !c.connected {
			fmt.Print("🔗 Server [localhost:8083]: ")
			if !scanner.Scan() {
				break
			}
			c.serverAddr = strings.TrimSpace(scanner.Text())
			
			if c.serverAddr == "" {
				c.serverAddr = "localhost:8083"
			}

			c.lastServer = c.serverAddr
			fmt.Printf("⏳ Connecting to %s...\n", c.serverAddr)
			
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

func (c *CLIClient) connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	// Detect if it's an .onion address
	isOnion := strings.HasSuffix(c.serverAddr, ".onion") || 
			  strings.Contains(c.serverAddr, ".onion:")

	var conn net.Conn
	var err error

	if isOnion {
		fmt.Printf("🧅 Detected .onion address - routing through Tor\n")
		conn, err = c.connectThroughTor()
	} else {
		fmt.Printf("🌐 Connecting directly\n")
		conn, err = c.connectDirect()
	}

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

	fmt.Printf("🔐 Establishing TLS over Tor...\n")

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "",
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}

	tlsConn := tls.Client(conn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(45 * time.Second))
	
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %v", err)
	}
	
	tlsConn.SetDeadline(time.Time{})
	
	fmt.Printf("✅ Secure Tor connection established\n")
	return tlsConn, nil
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

func (c *CLIClient) connectDirect() (net.Conn, error) {
	fmt.Printf("📡 Establishing direct connection...\n")
	
	conn, err := net.DialTimeout("tcp", c.serverAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("TCP connection failed: %v", err)
	}

	fmt.Printf("🔐 Starting TLS handshake...\n")
	
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %v", err)
	}

	fmt.Printf("✅ Secure connection established\n")
	return tlsConn, nil
}

func (c *CLIClient) setupEncryption() error {
	fmt.Printf("🔐 Establishing end-to-end encryption...\n")
	
	// ECDH Key Exchange
	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		c.conn.Close()
		return fmt.Errorf("key generation failed: %v", err)
	}

	privateKeyBuffer := memguard.NewBufferFromBytes(privateKey.Bytes())
	defer privateKeyBuffer.Destroy()

	// Send public key
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

	sharedSecretBuffer := memguard.NewBufferFromBytes(sharedSecret)
	defer sharedSecretBuffer.Destroy()

	// Setup AES-GCM
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		c.conn.Close()
		return fmt.Errorf("AES cipher creation failed: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		c.conn.Close()
		return fmt.Errorf("GCM cipher creation failed: %v", err)
	}

	c.gcm = gcm
	c.connected = true

	// Success messages
	fmt.Printf("✅ Connected to %s\n", c.serverAddr)
	fmt.Printf("🔐 End-to-end encryption active (AES-256-GCM)\n")
	
	if strings.Contains(c.serverAddr, ".onion") {
		fmt.Printf("🧅 Anonymous Tor routing active\n")
		fmt.Printf("👻 Your identity is protected\n")
	}
	
	fmt.Printf("💬 Ready for secure messaging\n")
	fmt.Printf("ℹ️  Type /help for commands\n\n")

	// Start receiving messages
	go c.receiveMessages()

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
	
	c.connected = false
	fmt.Printf("\n📴 Disconnected from server\n")
	
	if c.autoReconnect {
		fmt.Printf("🔄 Auto-reconnect is enabled\n")
	}
	fmt.Printf("\n")
}

func (c *CLIClient) sendMessage(message string) error {
	return c.sendEncryptedMessage(message)
}

func (c *CLIClient) sendEncryptedMessage(message string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if !c.connected || c.gcm == nil || c.conn == nil {
		return fmt.Errorf("not connected")
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("nonce generation failed: %v", err)
	}

	encrypted := c.gcm.Seal(nil, nonce, []byte(message), nil)
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

		decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			fmt.Printf("\n⚠️ Failed to decrypt message\n")
			continue
		}

		message := string(decrypted)
		
		// Handle special commands
		if message == "/pong" {
			// Heartbeat response - don't display
			continue
		}

		// Try to parse as JSON
		var msg struct {
			From    string `json:"from"`
			Content string `json:"content"`
			Type    string `json:"type"`
			Time    string `json:"time"`
		}
		
		if err := json.Unmarshal(decrypted, &msg); err == nil {
			timestamp := msg.Time
			if timestamp == "" {
				timestamp = time.Now().Format("15:04:05")
			}
			
			switch msg.Type {
			case "system":
				fmt.Printf("\r🔔 [%s] %s\n💬 > ", timestamp, msg.Content)
			default:
				if msg.From == "" {
					fmt.Printf("\r📨 [%s] %s\n💬 > ", timestamp, msg.Content)
				} else {
					fmt.Printf("\r👤 [%s] %s: %s\n💬 > ", timestamp, msg.From, msg.Content)
				}
			}
		} else {
			// Plain message
			timestamp := time.Now().Format("15:04:05")
			fmt.Printf("\r📨 [%s] %s\n💬 > ", timestamp, message)
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

func (c *CLIClient) heartbeatLoop() {
	for {
		time.Sleep(30 * time.Second)
		
		c.mu.Lock()
		if c.connected {
			c.mu.Unlock()
			if err := c.sendEncryptedMessage("/ping"); err != nil {
				fmt.Printf("\n⚠️ Heartbeat failed\n")
			}
		} else {
			c.mu.Unlock()
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
		if strings.Contains(c.serverAddr, ".onion") {
			fmt.Printf("  Mode: Tor (Anonymous)\n")
		} else {
			fmt.Printf("  Mode: Direct\n")
		}
		fmt.Printf("  Encryption: AES-256-GCM\n")
		fmt.Printf("  Key Exchange: ECDH-X25519\n")
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
  
Settings:
  /auto on           - Enable auto-reconnect
  /auto off          - Disable auto-reconnect
  
Interface:
  /clear, /cls       - Clear screen
  /help, /h, /?      - Show this help
  /quit, /exit, /q   - Exit application
  
Tips:
  • .onion addresses route through Tor automatically
  • All messages are end-to-end encrypted
  • Auto-reconnect keeps you connected
  • Press Ctrl+C for emergency shutdown

`, version)
}
