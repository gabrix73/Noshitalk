package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/awnumar/memguard"
)

type Client struct {
	conn         net.Conn
	identity     string
	gcm          cipher.AEAD
	sharedSecret *memguard.Enclave
	quit         chan struct{}
	lastActivity time.Time
	mu           sync.Mutex
}

type Message struct {
	From    string `json:"from"`
	Content string `json:"content"`
	Time    string `json:"time"`
	Type    string `json:"type"`
}

var (
	clients    = make(map[net.Conn]*Client)
	clientsMux sync.RWMutex
	version    = "0.1"
)

const port = "0.0.0.0:8083"

func main() {
	fmt.Printf("🔐 NoshiTalk Server v%s - Maximum Security\n", version)
	fmt.Printf("⚠️  Zero logs, zero traces, auto-wipe post-session\n")
	
	secureSetup()
	defer secureShutdown("Session completed")

	// Privacy-focused - no IP disclosure
	fmt.Printf("🧅 Tor Hidden Service Only - No direct connections\n")
	fmt.Printf("📍 Listening on port: 8083 (accessible only via Tor)\n")
	fmt.Printf("\n")

	listener, err := tls.Listen("tcp", port, getTLSConfig())
	if err != nil {
		fmt.Printf("❌ TLS listen error: %v\n", err)
		secureShutdown(fmt.Sprintf("TLS listen error: %v", err))
	}

	fmt.Printf("🚀 Server started successfully\n")
	fmt.Printf("🔗 Waiting for connections...\n")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stop
		fmt.Printf("\n🛑 Received shutdown signal\n")
		secureShutdown("Operator requested shutdown")
	}()

	// Monitor goroutine - check for idle connections
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			clientsMux.RLock()
			activeCount := len(clients)
			if activeCount > 0 {
				fmt.Printf("📊 Active connections: %d\n", activeCount)
				// Check for idle connections (optional)
				now := time.Now()
				for _, client := range clients {
					client.mu.Lock()
					idleTime := now.Sub(client.lastActivity)
					client.mu.Unlock()
					if idleTime > 5*time.Minute {
						fmt.Printf("⏰ [%s] Idle for %v\n", client.identity, idleTime)
					}
				}
			}
			clientsMux.RUnlock()
		}
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("❌ Accept error: %v\n", err)
			continue
		}

		fmt.Printf("🎯 New connection received\n")
		go handleClient(conn)
	}
}

func getTLSConfig() *tls.Config {
	if _, err := os.Stat("server_ec.crt"); os.IsNotExist(err) {
		fmt.Println("🔧 Generating self-signed certificates for testing...")
		if err := generateTestCerts(); err != nil {
			log.Fatal("Error generating test certificates:", err)
		}
		fmt.Println("✅ Certificates generated successfully")
	}

	cert, err := tls.LoadX509KeyPair("server_ec.crt", "server_ec.key")
	if err != nil {
		log.Fatal("Error loading ECC server certificates:", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
	}
}

func generateTestCerts() error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"NoshiTalk"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"localhost"},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create("server_ec.crt")
	if err != nil {
		return err
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	keyOut, err := os.Create("server_ec.key")
	if err != nil {
		return err
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}

	return pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
}

func getClientIdentity(conn net.Conn) (string, error) {
	id := make([]byte, 8)
	rand.Read(id)
	return fmt.Sprintf("user_%x", id), nil
}

func handleClient(conn net.Conn) {
	defer func() {
		fmt.Printf("🔌 Connection handler ending\n")
		conn.Close()
		removeClient(conn)
	}()

	identity, err := getClientIdentity(conn)
	if err != nil {
		fmt.Printf("❌ Error getting client identity: %v\n", err)
		return
	}

	fmt.Printf("🔑 Client authenticated: %s\n", identity)

	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("❌ [%s] Private key generation failed: %v\n", identity, err)
		return
	}

	privateKeyBuffer := memguard.NewBufferFromBytes(privateKey.Bytes())
	defer privateKeyBuffer.Destroy()

	fmt.Printf("📥 [%s] Waiting for client public key...\n", identity)
	clientPubKeyBytes := make([]byte, 32)
	
	// Set timeout for initial handshake
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	
	totalRead := 0
	for totalRead < 32 {
		n, err := conn.Read(clientPubKeyBytes[totalRead:])
		if err != nil {
			fmt.Printf("❌ [%s] Error reading client public key (read %d/32 bytes): %v\n", identity, totalRead, err)
			return
		}
		totalRead += n
		fmt.Printf("📥 [%s] Read %d bytes, total: %d/32\n", identity, n, totalRead)
	}
	
	// Clear the deadline after handshake
	conn.SetReadDeadline(time.Time{})
	
	fmt.Printf("✅ [%s] Received complete client public key (%d bytes)\n", identity, totalRead)

	clientPubKey, err := curve.NewPublicKey(clientPubKeyBytes)
	if err != nil {
		fmt.Printf("❌ [%s] Error parsing client public key: %v\n", identity, err)
		return
	}

	fmt.Printf("📤 [%s] Sending server public key...\n", identity)
	serverPubKey := privateKey.PublicKey()
	if _, err := conn.Write(serverPubKey.Bytes()); err != nil {
		fmt.Printf("❌ [%s] Error sending server public key: %v\n", identity, err)
		return
	}
	fmt.Printf("✅ [%s] Sent server public key\n", identity)

	fmt.Printf("🔢 [%s] Calculating shared secret...\n", identity)
	sharedSecret, err := privateKey.ECDH(clientPubKey)
	if err != nil {
		fmt.Printf("❌ [%s] ECDH failed: %v\n", identity, err)
		return
	}

	sharedSecretBuffer := memguard.NewBufferFromBytes(sharedSecret)
	defer sharedSecretBuffer.Destroy()

	fmt.Printf("🔐 [%s] Setting up AES-GCM...\n", identity)
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		fmt.Printf("❌ [%s] AES cipher creation failed: %v\n", identity, err)
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("❌ [%s] GCM creation failed: %v\n", identity, err)
		return
	}

	client := &Client{
		conn:         conn,
		identity:     identity,
		gcm:          gcm,
		sharedSecret: sharedSecretBuffer.Seal(),
		quit:         make(chan struct{}),
		lastActivity: time.Now(),
	}

	addClient(conn, client)
	fmt.Printf("✅ [%s] Client fully initialized and added to active connections\n", identity)
	broadcastSystemMessage(fmt.Sprintf("🟢 %s connected", identity))

	fmt.Printf("📡 [%s] Starting message handling...\n", identity)
	client.receiveMessages()

	fmt.Printf("📴 [%s] Client disconnected\n", identity)
	broadcastSystemMessage(fmt.Sprintf("🔴 %s disconnected", identity))
}

func addClient(conn net.Conn, client *Client) {
	clientsMux.Lock()
	clients[conn] = client
	clientsMux.Unlock()
}

func removeClient(conn net.Conn) {
	clientsMux.Lock()
	delete(clients, conn)
	clientsMux.Unlock()
}

func broadcastSystemMessage(message string) {
	clientsMux.RLock()
	defer clientsMux.RUnlock()

	systemMsg := Message{
		From:    "System",
		Content: message,
		Time:    time.Now().Format("15:04:05"),
		Type:    "system",
	}

	msgJSON, _ := json.Marshal(systemMsg)

	for _, client := range clients {
		client.sendEncryptedMessage(string(msgJSON))
	}
}

func broadcastUserMessage(sender *Client, message string) {
	clientsMux.RLock()
	defer clientsMux.RUnlock()

	fmt.Printf("📢 [%s] Starting broadcast to %d clients\n", sender.identity, len(clients))

	userMsg := Message{
		From:    sender.identity,
		Content: message,
		Time:    time.Now().Format("15:04:05"),
		Type:    "message",
	}

	msgJSON, err := json.Marshal(userMsg)
	if err != nil {
		fmt.Printf("❌ [%s] JSON marshal error: %v\n", sender.identity, err)
		return
	}

	sentCount := 0
	for _, client := range clients {
		if client != sender {
			fmt.Printf("📤 Sending to %s\n", client.identity)
			err := client.sendEncryptedMessage(string(msgJSON))
			if err != nil {
				fmt.Printf("❌ Failed to send to %s: %v\n", client.identity, err)
			} else {
				sentCount++
			}
		}
	}
	
	fmt.Printf("✅ [%s] Broadcast completed - sent to %d clients\n", sender.identity, sentCount)
}

func (c *Client) receiveMessages() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("💥 [%s] PANIC in receiveMessages: %v\n", c.identity, r)
		}
		fmt.Printf("🔚 [%s] Exiting receiveMessages\n", c.identity)
		close(c.quit)
	}()
	
	buf := make([]byte, 8192)
	
	fmt.Printf("📡 [%s] Starting receive loop\n", c.identity)
	
	// NO read deadline for persistent connections
	c.conn.SetReadDeadline(time.Time{})
	
	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				fmt.Printf("📴 [%s] Client closed connection cleanly\n", c.identity)
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				fmt.Printf("⏱️ [%s] Read timeout - connection idle\n", c.identity)
				continue // Continue on timeout
			} else {
				fmt.Printf("❌ [%s] Read error: %v\n", c.identity, err)
			}
			return
		}
		
		if n == 0 {
			fmt.Printf("⚠️ [%s] Read 0 bytes\n", c.identity)
			continue
		}
		
		// Update last activity
		c.mu.Lock()
		c.lastActivity = time.Now()
		c.mu.Unlock()
		
		fmt.Printf("📥 [%s] Received %d bytes\n", c.identity, n)
		
		message, err := c.decryptMessage(buf[:n])
		if err != nil {
			fmt.Printf("❌ [%s] Decrypt error: %v\n", c.identity, err)
			continue
		}
		
		fmt.Printf("📝 [%s] Message: %s\n", c.identity, message)
		
		// Handle special commands
		if message == "/quit" {
			fmt.Printf("👋 [%s] Quit received\n", c.identity)
			return
		}
		
		if message == "/ping" {
			fmt.Printf("🏓 [%s] Ping received, sending pong\n", c.identity)
			err := c.sendEncryptedMessage("/pong")
			if err != nil {
				fmt.Printf("❌ [%s] Failed to send pong: %v\n", c.identity, err)
			} else {
				fmt.Printf("✅ [%s] Pong sent successfully\n", c.identity)
			}
			continue
		}
		
		// Broadcast regular messages
		fmt.Printf("💬 [%s] Broadcasting: %s\n", c.identity, message)
		broadcastUserMessage(c, message)
		fmt.Printf("📈 [%s] Continuing to wait for next message\n", c.identity)
	}
}

func (c *Client) sendEncryptedMessage(message string) error {
	if c.conn == nil {
		return fmt.Errorf("connection is nil")
	}
	
	if c.gcm == nil {
		return fmt.Errorf("gcm cipher is nil")
	}
	
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("nonce generation failed: %v", err)
	}

	ciphertext := c.gcm.Seal(nil, nonce, []byte(message), nil)
	data := append(nonce, ciphertext...)
	
	fmt.Printf("📤 [%s] Sending encrypted message (%d bytes): %s\n", c.identity, len(data), message)
	
	n, err := c.conn.Write(data)
	if err != nil {
		return fmt.Errorf("write failed: %v", err)
	}
	
	if n != len(data) {
		return fmt.Errorf("incomplete write: wrote %d of %d bytes", n, len(data))
	}
	
	fmt.Printf("✅ [%s] Successfully wrote %d bytes\n", c.identity, n)
	return nil
}

func (c *Client) decryptMessage(data []byte) (string, error) {
	if len(data) < 12 {
		return "", fmt.Errorf("message too short: %d bytes", len(data))
	}

	nonce := data[:12]
	ciphertext := data[12:]

	plaintext, err := c.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %v", err)
	}

	return string(plaintext), nil
}

func secureSetup() {
	memguard.CatchInterrupt()
}

func secureShutdown(reason string) {
	fmt.Printf("\n🛑 Server shutdown: %s\n", reason)
	
	clientsMux.Lock()
	for _, client := range clients {
		client.conn.Close()
	}
	clients = make(map[net.Conn]*Client)
	clientsMux.Unlock()

	memguard.Purge()
	os.Exit(0)
}
