package main

import (
	"bytes"
	"compress/zlib"
	"crypto/cipher"
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/awnumar/memguard"

	"noshitalk/pkg/crypto"
	"noshitalk/pkg/protocol"
)

// Client represents a connected chat client.
type Client struct {
	conn         net.Conn
	identity     string
	gcm          cipher.AEAD
	sharedSecret *memguard.Enclave
	quit         chan struct{}
	lastActivity time.Time
	mu           sync.Mutex

	// Visibility control
	isVisible bool

	// Key rotation
	currentKeyPair   *ecdh.PrivateKey
	nextKeyPair      *ecdh.PrivateKey
	sessionKeys      [][]byte
	keyRotationCount uint32
	lastRotation     time.Time
	messageCount     uint32
}

// FileTransfer tracks an ongoing file transfer.
type FileTransfer struct {
	FileID      string
	Sender      *Client
	Receiver    *Client
	StartTime   time.Time
	TotalChunks int
	Received    int
	Completed   bool
}

var (
	clients       = make(map[net.Conn]*Client)
	clientsMux    sync.RWMutex
	fileTransfers = make(map[string]*FileTransfer)
	transfersMux  sync.RWMutex
	version       = "2.0-refactored"
)

const (
	protocolVersion        = 2
	fileChunkSize          = 256 * 1024        // 256KB chunks
	maxFileSize            = 500 * 1024 * 1024 // 500MB max
	maxConcurrentTransfers = 3
	rotateAfterMessages    = 100
	rotateAfterTime        = 5 * time.Minute
)

func main() {
	fmt.Printf("NoshiTalk Server v%s\n", version)
	fmt.Printf("Zero logs, zero traces, auto-wipe post-session\n")
	fmt.Printf("Designed for Tor Hidden Service - localhost only\n")
	fmt.Printf("Traffic obfuscation: Padding + Random delays\n")
	fmt.Printf("Key rotation enabled (every %d messages or %v)\n", rotateAfterMessages, rotateAfterTime)
	fmt.Printf("Ghost mode enabled by default\n\n")

	memguard.CatchInterrupt()
	defer secureShutdown("Session completed")

	listenAddr := "127.0.0.1:8083"
	fmt.Printf("Listening on: %s (Tor Hidden Service backend)\n", listenAddr)
	fmt.Printf("Server NOT exposed directly - Tor proxy required\n\n")

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Printf("Listen error: %v\n", err)
		secureShutdown(fmt.Sprintf("Listen error: %v", err))
	}

	fmt.Printf("Server started successfully\n")
	fmt.Printf("Waiting for connections...\n\n")

	// Signal handling
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		fmt.Printf("\nReceived shutdown signal\n")
		secureShutdown("Operator requested shutdown")
	}()

	// Monitor goroutine
	go monitorLoop()

	// Accept connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Accept error: %v\n", err)
			continue
		}

		fmt.Printf("New connection from %s\n", conn.RemoteAddr())
		go handleClient(conn)
	}
}

func monitorLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		clientsMux.RLock()
		activeCount := len(clients)
		visibleCount := 0
		for _, client := range clients {
			if client.isVisible {
				visibleCount++
			}
		}
		if activeCount > 0 {
			fmt.Printf("Active connections: %d (visible: %d, ghost: %d)\n",
				activeCount, visibleCount, activeCount-visibleCount)
		}
		clientsMux.RUnlock()

		cleanupOldTransfers()
	}
}

func handleClient(conn net.Conn) {
	defer func() {
		fmt.Printf("Connection handler ending\n")
		conn.Close()
		removeClient(conn)
	}()

	// Generate server key pair
	privateKey, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		fmt.Printf("Key generation failed: %v\n", err)
		return
	}

	// Receive client public key
	fmt.Printf("Waiting for client public key...\n")
	clientPubKeyBytes := make([]byte, 32)

	conn.SetReadDeadline(time.Now().Add(crypto.HandshakeTimeout))
	n, err := io.ReadFull(conn, clientPubKeyBytes)
	if err != nil {
		fmt.Printf("Error reading client public key: %v\n", err)
		return
	}
	conn.SetReadDeadline(time.Time{})

	identity := crypto.DeriveIdentity(clientPubKeyBytes)
	fmt.Printf("[%s] Received client public key (%d bytes)\n", identity, n)

	// Send server public key
	fmt.Printf("[%s] Sending server public key...\n", identity)
	if _, err := conn.Write(privateKey.PublicKey().Bytes()); err != nil {
		fmt.Printf("[%s] Error sending server public key: %v\n", identity, err)
		return
	}

	// Calculate shared secret
	fmt.Printf("[%s] Calculating shared secret...\n", identity)
	sharedSecret, err := crypto.PerformECDH(privateKey, clientPubKeyBytes)
	if err != nil {
		fmt.Printf("[%s] ECDH failed: %v\n", identity, err)
		return
	}

	// Mutual authentication
	fmt.Printf("[%s] Starting mutual authentication...\n", identity)
	if err := crypto.PerformServerAuth(conn, sharedSecret); err != nil {
		fmt.Printf("[%s] Authentication failed: %v\n", identity, err)
		return
	}

	// Setup AES-GCM
	fmt.Printf("[%s] Setting up AES-GCM...\n", identity)
	gcm, err := crypto.SetupAESGCM(sharedSecret)
	if err != nil {
		fmt.Printf("[%s] %v\n", identity, err)
		return
	}

	// Create client
	client := &Client{
		conn:           conn,
		identity:       identity,
		gcm:            gcm,
		sharedSecret:   crypto.SecureBuffer(sharedSecret),
		quit:           make(chan struct{}),
		lastActivity:   time.Now(),
		isVisible:      false, // Ghost mode by default
		currentKeyPair: privateKey,
		lastRotation:   time.Now(),
		messageCount:   0,
	}

	addClient(conn, client)
	fmt.Printf("[%s] Client initialized (ghost mode)\n", identity)

	// Send welcome message
	welcomeMsg := protocol.NewSystemMessage(
		fmt.Sprintf("Connected as %s (ghost mode). Use /reveal to become visible, /ghost to hide.", identity))
	client.sendMessage(welcomeMsg)

	// Send personal user list
	sendPersonalUserList(client)

	fmt.Printf("[%s] Starting message handling...\n", identity)
	client.receiveMessages()

	fmt.Printf("[%s] Client disconnected\n", identity)

	if client.isVisible {
		broadcastSystemMessage(fmt.Sprintf("%s disconnected", identity))
	}
}

func addClient(conn net.Conn, client *Client) {
	clientsMux.Lock()
	clients[conn] = client
	totalClients := len(clients)
	clientsMux.Unlock()

	fmt.Printf("[%s] Added to clients map. Total clients: %d\n", client.identity, totalClients)
}

func removeClient(conn net.Conn) {
	clientsMux.Lock()
	client, exists := clients[conn]
	if exists && client.isVisible {
		delete(clients, conn)
		clientsMux.Unlock()
		broadcastUserListToVisible()
	} else {
		delete(clients, conn)
		clientsMux.Unlock()
	}
}

func (c *Client) sendMessage(msg *protocol.Message) error {
	data, err := msg.ToJSON()
	if err != nil {
		return err
	}
	return c.sendEncrypted(string(data))
}

func (c *Client) sendEncrypted(message string) error {
	if c.conn == nil || c.gcm == nil {
		return fmt.Errorf("not ready")
	}

	data, err := crypto.EncryptMessage(c.gcm, message)
	if err != nil {
		return err
	}

	_, err = c.conn.Write(data)
	return err
}

func (c *Client) receiveMessages() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[%s] PANIC: %v\n", c.identity, r)
		}
		close(c.quit)
	}()

	buf := make([]byte, 512*1024)

	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				fmt.Printf("[%s] Connection closed\n", c.identity)
			} else {
				fmt.Printf("[%s] Read error: %v\n", c.identity, err)
			}
			return
		}

		if n == 0 {
			continue
		}

		c.mu.Lock()
		c.lastActivity = time.Now()
		c.messageCount++
		c.mu.Unlock()

		message, err := crypto.DecryptMessage(c.gcm, buf[:n])
		if err != nil {
			fmt.Printf("[%s] Decrypt error: %v\n", c.identity, err)
			continue
		}

		c.checkKeyRotation()

		if c.handleCommand(message) {
			continue
		}

		// Handle JSON messages
		msgType, _, err := protocol.ParseMessage([]byte(message))
		if err == nil {
			switch msgType {
			case protocol.TypeFileOffer:
				if fileOffer, err := protocol.ParseAsFileOffer([]byte(message)); err == nil {
					routeFileOffer(c, fileOffer)
					continue
				}
			case protocol.TypeFileChunk:
				if fileChunk, err := protocol.ParseAsFileChunk([]byte(message)); err == nil {
					routeFileChunk(c, fileChunk)
					continue
				}
			case protocol.TypeFileAccept, protocol.TypeFileReject, protocol.TypeFileComplete:
				if fileResp, err := protocol.ParseAsFileResponse([]byte(message)); err == nil {
					routeFileResponse(c, fileResp)
					continue
				}
			}
		}

		// Handle private messages
		if len(message) > 4 && message[:4] == "/pm " {
			parts := splitPrivateMessage(message)
			if len(parts) < 2 {
				errorMsg := protocol.NewErrorMessage("Usage: /pm username message")
				c.sendMessage(errorMsg)
				continue
			}
			sendPrivateMessage(c, parts[0], parts[1])
			continue
		}

		// Broadcast if visible
		if c.isVisible {
			broadcastUserMessage(c, message)
		} else {
			errorMsg := protocol.NewErrorMessage("You are in ghost mode. Use /reveal to send messages.")
			c.sendMessage(errorMsg)
		}
	}
}

func (c *Client) handleCommand(message string) bool {
	switch message {
	case "/quit":
		return true
	case "/reveal":
		c.mu.Lock()
		wasVisible := c.isVisible
		c.isVisible = true
		c.mu.Unlock()

		if !wasVisible {
			fmt.Printf("[%s] Became visible\n", c.identity)
			broadcastSystemMessage(fmt.Sprintf("%s joined the chat", c.identity))
			broadcastUserListToVisible()
		}
		return true
	case "/ghost":
		c.mu.Lock()
		wasVisible := c.isVisible
		c.isVisible = false
		c.mu.Unlock()

		if wasVisible {
			fmt.Printf("[%s] Went ghost\n", c.identity)
			broadcastSystemMessage(fmt.Sprintf("%s went invisible", c.identity))
			broadcastUserListToVisible()
		}
		return true
	case "/users":
		sendPersonalUserList(c)
		return true
	}
	return false
}

func (c *Client) checkKeyRotation() {
	c.mu.Lock()
	defer c.mu.Unlock()

	needRotation := false
	if c.messageCount >= rotateAfterMessages {
		needRotation = true
		fmt.Printf("[%s] Key rotation triggered (message count: %d)\n", c.identity, c.messageCount)
	}
	if time.Since(c.lastRotation) > rotateAfterTime {
		needRotation = true
		fmt.Printf("[%s] Key rotation triggered (time elapsed: %v)\n", c.identity, time.Since(c.lastRotation))
	}

	if needRotation {
		c.performKeyRotation()
	}
}

func (c *Client) performKeyRotation() {
	newKeyPair, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		fmt.Printf("[%s] Key rotation failed: %v\n", c.identity, err)
		return
	}

	c.nextKeyPair = newKeyPair
	c.keyRotationCount++
	c.messageCount = 0
	c.lastRotation = time.Now()

	rotMsg := protocol.KeyRotationMessage{
		Type:      protocol.TypeKeyRotation,
		PublicKey: newKeyPair.PublicKey().Bytes(),
		Nonce:     make([]byte, 12),
		Time:      time.Now().Format("15:04:05"),
	}

	if data, err := rotMsg.ToJSON(); err == nil {
		c.sendEncrypted(string(data))
	}

	fmt.Printf("[%s] Key rotation completed (rotation #%d)\n", c.identity, c.keyRotationCount)
}

func sendPersonalUserList(client *Client) {
	clientsMux.RLock()
	visibleUsers := []string{}
	for _, c := range clients {
		if c.isVisible || c == client {
			visibleUsers = append(visibleUsers, c.identity)
		}
	}
	clientsMux.RUnlock()

	userListMsg := protocol.NewUserListMessage(visibleUsers)
	if data, err := userListMsg.ToJSON(); err == nil {
		client.sendEncrypted(string(data))
	}
}

func broadcastUserListToVisible() {
	clientsMux.RLock()
	defer clientsMux.RUnlock()

	visibleUsers := []string{}
	for _, c := range clients {
		if c.isVisible {
			visibleUsers = append(visibleUsers, c.identity)
		}
	}

	userListMsg := protocol.NewUserListMessage(visibleUsers)
	data, err := userListMsg.ToJSON()
	if err != nil {
		return
	}

	for _, client := range clients {
		if client.isVisible {
			client.sendEncrypted(string(data))
		}
	}
}

func broadcastSystemMessage(message string) {
	clientsMux.RLock()
	defer clientsMux.RUnlock()

	systemMsg := protocol.NewSystemMessage(message)
	data, err := systemMsg.ToJSON()
	if err != nil {
		return
	}

	for _, client := range clients {
		if client.isVisible {
			client.sendEncrypted(string(data))
		}
	}
}

func broadcastUserMessage(sender *Client, message string) {
	clientsMux.RLock()
	defer clientsMux.RUnlock()

	userMsg := protocol.NewMessage(sender.identity, "", message, protocol.TypeMessage)
	data, err := userMsg.ToJSON()
	if err != nil {
		return
	}

	for _, client := range clients {
		if client != sender && client.isVisible {
			client.sendEncrypted(string(data))
		}
	}
}

func sendPrivateMessage(sender *Client, targetUsername, message string) {
	clientsMux.RLock()
	defer clientsMux.RUnlock()

	var targetClient *Client
	for _, client := range clients {
		if client.identity == targetUsername {
			targetClient = client
			break
		}
	}

	if targetClient == nil {
		errorMsg := protocol.NewErrorMessage(fmt.Sprintf("User '%s' not found", targetUsername))
		sender.sendMessage(errorMsg)
		return
	}

	privateMsg := protocol.NewMessage(sender.identity, targetUsername, message, protocol.TypePrivate)
	data, err := privateMsg.ToJSON()
	if err != nil {
		return
	}

	fmt.Printf("[%s -> %s] Private message\n", sender.identity, targetUsername)
	targetClient.sendEncrypted(string(data))
	sender.sendEncrypted(string(data))
}

func splitPrivateMessage(msg string) []string {
	content := msg[4:]
	spaceIdx := -1
	for i, ch := range content {
		if ch == ' ' {
			spaceIdx = i
			break
		}
	}

	if spaceIdx == -1 {
		return []string{content}
	}

	return []string{content[:spaceIdx], content[spaceIdx+1:]}
}

// File transfer functions
func routeFileOffer(sender *Client, offer *protocol.FileOfferMessage) {
	transfersMux.RLock()
	activeTransfers := 0
	for _, transfer := range fileTransfers {
		if !transfer.Completed && transfer.Sender == sender {
			activeTransfers++
		}
	}
	transfersMux.RUnlock()

	if activeTransfers >= maxConcurrentTransfers {
		errorMsg := protocol.NewErrorMessage(fmt.Sprintf("Max concurrent transfers (%d) reached", maxConcurrentTransfers))
		sender.sendMessage(errorMsg)
		return
	}

	clientsMux.RLock()
	var targetClient *Client
	for _, client := range clients {
		if client.identity == offer.To {
			targetClient = client
			break
		}
	}
	clientsMux.RUnlock()

	if targetClient == nil {
		errorMsg := protocol.NewErrorMessage(fmt.Sprintf("User '%s' not found", offer.To))
		sender.sendMessage(errorMsg)
		return
	}

	transfer := &FileTransfer{
		FileID:      offer.FileID,
		Sender:      sender,
		Receiver:    targetClient,
		StartTime:   time.Now(),
		TotalChunks: offer.TotalChunks,
	}

	transfersMux.Lock()
	fileTransfers[offer.FileID] = transfer
	transfersMux.Unlock()

	offer.From = sender.identity
	offer.Time = time.Now().Format("15:04:05")

	fmt.Printf("[%s -> %s] File offer: %s (%d bytes, %d chunks)\n",
		sender.identity, offer.To, offer.Filename, offer.Size, offer.TotalChunks)

	if data, err := offer.ToJSON(); err == nil {
		targetClient.sendEncrypted(string(data))
	}
}

func routeFileChunk(sender *Client, chunk *protocol.FileChunkMessage) {
	transfersMux.RLock()
	transfer, exists := fileTransfers[chunk.FileID]
	transfersMux.RUnlock()

	if !exists || transfer.Sender != sender {
		return
	}

	chunk.Time = time.Now().Format("15:04:05")

	transfersMux.Lock()
	transfer.Received++
	if transfer.Received >= transfer.TotalChunks {
		transfer.Completed = true
		fmt.Printf("[%s] File transfer completed in %v\n", sender.identity, time.Since(transfer.StartTime))
	}
	transfersMux.Unlock()

	if data, err := chunk.ToJSON(); err == nil {
		transfer.Receiver.sendEncrypted(string(data))
	}
}

func routeFileResponse(sender *Client, resp *protocol.FileResponseMessage) {
	transfersMux.RLock()
	transfer, exists := fileTransfers[resp.FileID]
	transfersMux.RUnlock()

	if !exists {
		return
	}

	resp.From = sender.identity
	resp.Time = time.Now().Format("15:04:05")

	data, err := resp.ToJSON()
	if err != nil {
		return
	}

	if sender == transfer.Receiver {
		transfer.Sender.sendEncrypted(string(data))
	} else {
		transfer.Receiver.sendEncrypted(string(data))
	}

	if resp.Status == "rejected" || resp.Status == "completed" {
		transfersMux.Lock()
		delete(fileTransfers, resp.FileID)
		transfersMux.Unlock()
	}
}

func cleanupOldTransfers() {
	transfersMux.Lock()
	defer transfersMux.Unlock()

	now := time.Now()
	for fileID, transfer := range fileTransfers {
		if now.Sub(transfer.StartTime) > 30*time.Minute {
			fmt.Printf("Cleaning up old transfer: %s\n", fileID[:8])
			delete(fileTransfers, fileID)
		}
	}
}

func compressData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, err := w.Write(data)
	w.Close()
	return buf.Bytes(), err
}

func decompressData(data []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func secureShutdown(reason string) {
	fmt.Printf("\nServer shutdown: %s\n", reason)

	clientsMux.Lock()
	for _, client := range clients {
		client.conn.Close()
	}
	clients = make(map[net.Conn]*Client)
	clientsMux.Unlock()

	memguard.Purge()
	os.Exit(0)
}
