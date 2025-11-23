package main

import (
	"bufio"
	"crypto/cipher"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/awnumar/memguard"

	"noshitalk/pkg/crypto"
	"noshitalk/pkg/identity"
	"noshitalk/pkg/protocol"
	"noshitalk/pkg/tor"
)

// CLIClient represents the command-line chat client.
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
	identity      *identity.Identity
}

var version = "2.0-refactored"

func main() {
	memguard.CatchInterrupt()
	defer memguard.Purge()

	fmt.Printf("NoshiTalk CLI Client v%s\n", version)
	fmt.Printf("Lightweight Command Line Interface\n")
	fmt.Printf("Tor-Only Mode - No Clearnet Connections\n")
	fmt.Printf("ECDH + HMAC + AES-GCM Encryption\n\n")

	client := &CLIClient{
		quit:          make(chan struct{}),
		autoReconnect: true,
		onlineUsers:   []string{},
	}

	// Initialize persistent identity
	keyPath, err := identity.GetDefaultKeyPath("cli-identity.noshikey")
	if err != nil {
		fmt.Printf("Failed to get key path: %v\n", err)
	} else {
		client.identity, err = identity.LoadOrCreate(keyPath, "cli")
		if err != nil {
			fmt.Printf("Failed to initialize identity: %v\n", err)
			fmt.Printf("Continuing with temporary identity...\n\n")
		} else {
			fmt.Printf("Identity: %s\n", client.identity.Username)
			fmt.Printf("Fingerprint: %s\n\n", client.identity.Fingerprint)
		}
	}

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Printf("\nShutting down securely...\n")
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

	fmt.Printf("Enter Tor Hidden Service address (.onion only)\n")
	fmt.Printf("Example: abcd1234...xyz9876.onion:8083\n")
	fmt.Printf("Clearnet addresses blocked by design\n\n")

	for {
		if !c.connected {
			fmt.Print(".onion address: ")
			if !scanner.Scan() {
				break
			}
			c.serverAddr = strings.TrimSpace(scanner.Text())

			if c.serverAddr == "" {
				fmt.Printf("Address required\n\n")
				continue
			}

			if err := tor.ValidateOnionAddress(c.serverAddr); err != nil {
				fmt.Printf("Invalid address: %v\n\n", err)
				continue
			}

			c.lastServer = c.serverAddr
			fmt.Printf("Connecting to %s via Tor...\n", c.serverAddr)

			if err := c.connect(); err != nil {
				fmt.Printf("Connection failed: %v\n", err)
				fmt.Printf("Will retry automatically if auto-reconnect is enabled\n\n")
				continue
			}
		}

		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}

		message := strings.TrimSpace(scanner.Text())
		if message == "" {
			continue
		}

		if c.handleCommand(message) {
			continue
		}

		// Send regular message
		if !c.connected {
			fmt.Printf("Not connected. Use /reconnect or enter server address\n")
			continue
		}

		if err := c.sendMessage(message); err != nil {
			fmt.Printf("Send error: %v\n", err)
			c.disconnect()
		}
	}

	c.disconnect()
}

func (c *CLIClient) handleCommand(message string) bool {
	switch message {
	case "/quit", "/exit", "/q":
		c.autoReconnect = false
		c.disconnect()
		fmt.Println("Goodbye!")
		os.Exit(0)
		return true
	case "/disconnect", "/d":
		c.disconnect()
		return true
	case "/help", "/h", "/?":
		c.showHelp()
		return true
	case "/status", "/s":
		c.showStatus()
		return true
	case "/reconnect", "/r":
		if !c.connected && c.lastServer != "" {
			c.serverAddr = c.lastServer
			fmt.Printf("Reconnecting to %s...\n", c.serverAddr)
			c.connect()
		}
		return true
	case "/auto on":
		c.autoReconnect = true
		fmt.Printf("Auto-reconnect enabled\n")
		return true
	case "/auto off":
		c.autoReconnect = false
		fmt.Printf("Auto-reconnect disabled\n")
		return true
	case "/clear", "/cls":
		fmt.Print("\033[H\033[2J")
		return true
	case "/users", "/u":
		c.showUsers()
		return true
	}

	// Handle /pm command
	if len(message) > 4 && message[:4] == "/pm " {
		if !c.connected {
			fmt.Printf("Not connected. Use /reconnect or enter server address\n")
			return true
		}
		if err := c.sendMessage(message); err != nil {
			fmt.Printf("Send error: %v\n", err)
			c.disconnect()
		}
		return true
	}

	return false
}

func (c *CLIClient) connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	fmt.Printf("Routing through Tor network...\n")

	// Test Tor proxy
	torDialer := tor.NewDialer()
	if !torDialer.IsAvailable() {
		return fmt.Errorf("Tor proxy not available on port 9050")
	}
	fmt.Printf("Tor proxy detected and responsive\n")

	// Connect through Tor
	conn, err := torDialer.DialWithCallback(c.serverAddr, func(msg string) {
		fmt.Printf("%s\n", msg)
	})
	if err != nil {
		return err
	}

	c.conn = conn
	return c.setupEncryption()
}

func (c *CLIClient) setupEncryption() error {
	fmt.Printf("Establishing end-to-end encryption...\n")

	// Use persistent identity or generate temporary
	var privateKey = c.identity.PrivateKey
	if c.identity != nil && c.identity.PrivateKey != nil {
		fmt.Printf("Using persistent identity: %s\n", c.identity.Username)
	} else {
		var err error
		privateKey, err = crypto.GenerateX25519KeyPair()
		if err != nil {
			c.conn.Close()
			return fmt.Errorf("key generation failed: %w", err)
		}
		fmt.Printf("Using temporary identity\n")
	}

	// Send public key
	publicKeyBytes := privateKey.PublicKey().Bytes()
	c.conn.SetWriteDeadline(time.Now().Add(crypto.HandshakeTimeout))
	if _, err := c.conn.Write(publicKeyBytes); err != nil {
		c.conn.Close()
		return fmt.Errorf("failed to send public key: %w", err)
	}
	c.conn.SetWriteDeadline(time.Time{})

	// Receive server public key
	serverPubKeyBytes := make([]byte, 32)
	if _, err := io.ReadFull(c.conn, serverPubKeyBytes); err != nil {
		c.conn.Close()
		return fmt.Errorf("failed to receive server public key: %w", err)
	}

	// Calculate shared secret
	sharedSecret, err := crypto.PerformECDH(privateKey, serverPubKeyBytes)
	if err != nil {
		c.conn.Close()
		return fmt.Errorf("ECDH failed: %w", err)
	}

	// Mutual authentication
	fmt.Printf("Starting HMAC mutual authentication...\n")
	if err := crypto.PerformClientAuth(c.conn, sharedSecret); err != nil {
		c.conn.Close()
		return fmt.Errorf("authentication failed: %w", err)
	}
	fmt.Printf("Mutual authentication successful\n")

	// Setup AES-GCM
	gcm, err := crypto.SetupAESGCM(sharedSecret)
	if err != nil {
		c.conn.Close()
		return err
	}

	c.gcm = gcm
	c.sharedSecret = crypto.SecureBuffer(sharedSecret)
	c.connected = true

	fmt.Printf("Connected to %s\n", c.serverAddr)
	fmt.Printf("End-to-end encryption active (AES-256-GCM)\n")
	fmt.Printf("Type /help for commands\n\n")

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

	c.sendEncrypted("/quit")
	time.Sleep(100 * time.Millisecond)

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	if c.sharedSecret != nil {
		buf, _ := c.sharedSecret.Open()
		if buf != nil {
			buf.Destroy()
		}
		c.sharedSecret = nil
	}
	c.gcm = nil
	c.connected = false

	fmt.Printf("\nDisconnected from server\n")
	fmt.Printf("Keys wiped from memory\n")

	if c.autoReconnect {
		fmt.Printf("Auto-reconnect is enabled\n")
	}
	fmt.Printf("\n")
}

func (c *CLIClient) sendMessage(message string) error {
	return c.sendEncrypted(message)
}

func (c *CLIClient) sendEncrypted(message string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected || c.gcm == nil || c.conn == nil {
		return fmt.Errorf("not connected")
	}

	data, err := crypto.EncryptMessage(c.gcm, message)
	if err != nil {
		return err
	}

	_, err = c.conn.Write(data)
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

		conn.SetReadDeadline(time.Time{})

		n, err := conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				fmt.Printf("\nServer closed connection\n")
			} else {
				fmt.Printf("\nConnection lost: %v\n", err)
			}

			c.mu.Lock()
			c.connected = false
			c.mu.Unlock()
			return
		}

		if n < 12 {
			continue
		}

		message, err := crypto.DecryptMessage(gcm, buf[:n])
		if err != nil {
			fmt.Printf("\nFailed to decrypt message\n")
			continue
		}

		// Try to parse as UserListMessage
		if userList, err := protocol.ParseAsUserList([]byte(message)); err == nil && userList.Type == protocol.TypeUserList {
			c.mu.Lock()
			c.onlineUsers = userList.Users
			c.mu.Unlock()
			fmt.Printf("\rOnline users (%d): %s\n> ", len(userList.Users), strings.Join(userList.Users, ", "))
			continue
		}

		// Try to parse as Message
		if msg, err := protocol.ParseAsMessage([]byte(message)); err == nil {
			timestamp := msg.Time
			if timestamp == "" {
				timestamp = time.Now().Format("15:04:05")
			}

			switch msg.Type {
			case protocol.TypeSystem:
				fmt.Printf("\r[%s] %s\n> ", timestamp, msg.Content)
			case protocol.TypePrivate:
				fmt.Printf("\r[%s] PM from %s: %s\n> ", timestamp, msg.From, msg.Content)
			case protocol.TypeError:
				fmt.Printf("\r[%s] Error: %s\n> ", timestamp, msg.Content)
			default:
				if msg.From != "" {
					fmt.Printf("\r[%s] %s: %s\n> ", timestamp, msg.From, msg.Content)
				} else {
					fmt.Printf("\r[%s] %s\n> ", timestamp, msg.Content)
				}
			}
		} else {
			timestamp := time.Now().Format("15:04:05")
			fmt.Printf("\r[%s] %s\n> ", timestamp, message)
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

			fmt.Printf("\nAuto-reconnecting to %s...\n", c.lastServer)
			c.serverAddr = c.lastServer
			if err := c.connect(); err != nil {
				fmt.Printf("Auto-reconnect failed: %v\n", err)
				fmt.Printf("Will retry in 10 seconds...\n")
			}
		}
	}
}

func (c *CLIClient) showStatus() {
	c.mu.Lock()
	defer c.mu.Unlock()

	fmt.Printf("\nConnection Status:\n")
	fmt.Printf("  Connected: %v\n", c.connected)
	if c.connected {
		fmt.Printf("  Server: %s\n", c.serverAddr)
		fmt.Printf("  Mode: Tor Hidden Service (Anonymous)\n")
		fmt.Printf("  Encryption: AES-256-GCM\n")
		fmt.Printf("  Key Exchange: ECDH-X25519\n")
		fmt.Printf("  Authentication: HMAC-SHA256\n")
	}
	if c.identity != nil {
		fmt.Printf("  Identity: %s\n", c.identity.Username)
	}
	fmt.Printf("  Auto-Reconnect: %v\n", c.autoReconnect)
	fmt.Printf("  Version: %s\n\n", version)
}

func (c *CLIClient) showHelp() {
	fmt.Printf(`
NoshiTalk CLI Commands v%s

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
  - Only .onion addresses accepted (Tor-only mode)
  - All messages are end-to-end encrypted
  - ECDH + HMAC + AES-GCM protection
  - Press Ctrl+C for emergency shutdown

`, version)
}

func (c *CLIClient) showUsers() {
	c.mu.Lock()
	users := c.onlineUsers
	c.mu.Unlock()

	if len(users) == 0 {
		fmt.Printf("No users online (or not yet received user list)\n")
		return
	}

	fmt.Printf("Online users (%d):\n", len(users))
	for _, user := range users {
		fmt.Printf("   - %s\n", user)
	}
}
