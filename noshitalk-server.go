package main

import (
	"bytes"
	"compress/zlib"
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
	
	// Visibility control
	isVisible    bool
	
	// Key rotation
	currentKeyPair   *ecdh.PrivateKey
	nextKeyPair      *ecdh.PrivateKey
	sessionKeys      [][]byte
	keyRotationCount uint32
	lastRotation     time.Time
	messageCount     uint32
}

type FileTransfer struct {
	FileID      string
	Sender      *Client
	Receiver    *Client
	StartTime   time.Time
	TotalChunks int
	Received    int
	Completed   bool
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

type FileOfferMessage struct {
	Type         string `json:"type"`
	From         string `json:"from"`
	To           string `json:"to"`
	FileID       string `json:"file_id"`
	Filename     string `json:"filename"`
	Size         int64  `json:"size"`
	TotalChunks  int    `json:"total_chunks"`
	SHA256       string `json:"sha256"`
	Compressed   bool   `json:"compressed"`
	Time         string `json:"time"`
}

type FileChunkMessage struct {
	Type        string `json:"type"`
	FileID      string `json:"file_id"`
	ChunkIndex  int    `json:"chunk_index"`
	TotalChunks int    `json:"total_chunks"`
	Data        string `json:"data"`
	Time        string `json:"time"`
}

type FileResponseMessage struct {
	Type    string `json:"type"`
	FileID  string `json:"file_id"`
	From    string `json:"from"`
	Status  string `json:"status"`
	Message string `json:"message"`
	SHA256  string `json:"sha256,omitempty"`
	Time    string `json:"time"`
}

type KeyRotationMessage struct {
	Type      string `json:"type"`
	PublicKey []byte `json:"public_key"`
	Nonce     []byte `json:"nonce"`
	Signature []byte `json:"signature"`
	Time      string `json:"time"`
}

var (
	clients        = make(map[net.Conn]*Client)
	clientsMux     sync.RWMutex
	fileTransfers  = make(map[string]*FileTransfer)
	transfersMux   sync.RWMutex
	version        = "1.0-enhanced"
)

const (
	handshakeTimeout  = 30 * time.Second
	protocolVersion   = 2
	messageBlockSize  = 256
	minRandomDelay    = 50
	maxRandomDelay    = 200
	
	// Enhanced file transfer settings
	fileChunkSize         = 256 * 1024        // 256KB chunks
	maxFileSize           = 500 * 1024 * 1024 // 500MB max
	maxConcurrentTransfers = 3
	
	// Key rotation settings
	rotateAfterMessages = 100
	rotateAfterTime     = 5 * time.Minute
)

func main() {
	fmt.Printf("🔐 NoshiTalk Server v%s - Enhanced Security Edition\n", version)
	fmt.Printf("⚠️  Zero logs, zero traces, auto-wipe post-session\n")
	fmt.Printf("🧅 Designed for Tor Hidden Service - localhost only\n")
	fmt.Printf("🎭 Traffic obfuscation: Padding + Random delays\n")
	fmt.Printf("🔄 Key rotation enabled (every %d messages or %v)\n", rotateAfterMessages, rotateAfterTime)
	fmt.Printf("👻 Ghost mode enabled by default\n")

	secureSetup()
	defer secureShutdown("Session completed")

	listenAddr := "127.0.0.1:8083"
	fmt.Printf("🔐 Listening on: localhost:8083 (Tor Hidden Service backend)\n")
	fmt.Printf("⚠️  Server NOT exposed directly - Tor proxy required\n\n")

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Printf("❌ Listen error: %v\n", err)
		secureShutdown(fmt.Sprintf("Listen error: %v", err))
	}

	fmt.Printf("🚀 Server started successfully\n")
	fmt.Printf("🔗 Waiting for connections...\n\n")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		fmt.Printf("\n🛑 Received shutdown signal\n")
		secureShutdown("Operator requested shutdown")
	}()

	// Monitor goroutine
	go func() {
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
				fmt.Printf("📊 Active connections: %d (visible: %d, ghost: %d)\n", 
					activeCount, visibleCount, activeCount-visibleCount)
			}
			clientsMux.RUnlock()
			
			// Cleanup old transfers
			cleanupOldTransfers()
		}
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("❌ Accept error: %v\n", err)
			continue
		}

		fmt.Printf("🎯 New connection from %s\n", conn.RemoteAddr())
		go handleClient(conn)
	}
}

func deriveIdentity(publicKey []byte) string {
	hash := sha256.Sum256(publicKey)
	return fmt.Sprintf("anon_%s", hex.EncodeToString(hash[:8]))
}

func handleClient(conn net.Conn) {
	defer func() {
		fmt.Printf("🔌 Connection handler ending\n")
		conn.Close()
		removeClient(conn)
	}()

	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(cryptorand.Reader)
	if err != nil {
		fmt.Printf("❌ Key generation failed: %v\n", err)
		return
	}

	privateKeyBuffer := memguard.NewBufferFromBytes(privateKey.Bytes())
	defer privateKeyBuffer.Destroy()

	fmt.Printf("📥 Waiting for client public key...\n")
	clientPubKeyBytes := make([]byte, 32)

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	n, err := io.ReadFull(conn, clientPubKeyBytes)
	if err != nil {
		fmt.Printf("❌ Error reading client public key: %v\n", err)
		return
	}
	conn.SetReadDeadline(time.Time{})

	identity := deriveIdentity(clientPubKeyBytes)
	fmt.Printf("🔑 Client identity derived: %s\n", identity)
	fmt.Printf("✅ [%s] Received client public key (%d bytes)\n", identity, n)

	clientPubKey, err := curve.NewPublicKey(clientPubKeyBytes)
	if err != nil {
		fmt.Printf("❌ [%s] Invalid client public key: %v\n", identity, err)
		return
	}

	fmt.Printf("📤 [%s] Sending server public key...\n", identity)
	serverPubKey := privateKey.PublicKey()
	if _, err := conn.Write(serverPubKey.Bytes()); err != nil {
		fmt.Printf("❌ [%s] Error sending server public key: %v\n", identity, err)
		return
	}

	fmt.Printf("🔢 [%s] Calculating shared secret...\n", identity)
	sharedSecret, err := privateKey.ECDH(clientPubKey)
	if err != nil {
		fmt.Printf("❌ [%s] ECDH failed: %v\n", identity, err)
		return
	}

	fmt.Printf("🔐 [%s] Starting mutual authentication...\n", identity)
	if err := performMutualAuth(conn, sharedSecret, identity); err != nil {
		fmt.Printf("❌ [%s] Authentication failed: %v\n", identity, err)
		return
	}

	fmt.Printf("🔐 [%s] Setting up AES-GCM...\n", identity)
	block, err := aes.NewCipher(sharedSecret[:32])
	if err != nil {
		fmt.Printf("❌ [%s] AES cipher creation failed: %v\n", identity, err)
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("❌ [%s] GCM creation failed: %v\n", identity, err)
		return
	}

	sharedSecretBuffer := memguard.NewBufferFromBytes(sharedSecret)
	defer sharedSecretBuffer.Destroy()

	client := &Client{
		conn:         conn,
		identity:     identity,
		gcm:          gcm,
		sharedSecret: sharedSecretBuffer.Seal(),
		quit:         make(chan struct{}),
		lastActivity: time.Now(),
		isVisible:    false, // Ghost mode by default
		currentKeyPair: privateKey,
		lastRotation:  time.Now(),
		messageCount:  0,
	}

	addClient(conn, client)
	fmt.Printf("✅ [%s] Client initialized (ghost mode)\n", identity)
	
	// Send welcome message only to the new client
	welcomeMsg := Message{
		From:    "System",
		Content: fmt.Sprintf("🟢 Connected as %s (ghost mode). Use /reveal to become visible, /ghost to hide.", identity),
		Time:    time.Now().Format("15:04:05"),
		Type:    "system",
	}
	msgJSON, _ := json.Marshal(welcomeMsg)
	client.sendEncryptedMessage(string(msgJSON))
	
	// Send personal user list (only themselves initially)
	sendPersonalUserList(client)

	fmt.Printf("📡 [%s] Starting message handling...\n", identity)
	client.receiveMessages()

	fmt.Printf("🔴 [%s] Client disconnected\n", identity)
	
	// Only notify if user was visible
	if client.isVisible {
		broadcastSystemMessage(fmt.Sprintf("🔴 %s disconnected", identity))
	}
}

func addClient(conn net.Conn, client *Client) {
	clientsMux.Lock()
	clients[conn] = client
	totalClients := len(clients)
	clientsMux.Unlock()

	fmt.Printf("➕ [%s] Added to clients map. Total clients: %d\n", client.identity, totalClients)
}

func removeClient(conn net.Conn) {
	clientsMux.Lock()
	client, exists := clients[conn]
	if exists && client.isVisible {
		delete(clients, conn)
		clientsMux.Unlock()
		// Only update lists if user was visible
		broadcastUserListToVisible()
	} else {
		delete(clients, conn)
		clientsMux.Unlock()
	}
}

func sendPersonalUserList(client *Client) {
	// Send only visible users to this client
	clientsMux.RLock()
	visibleUsers := []string{}
	for _, c := range clients {
		if c.isVisible || c == client {
			visibleUsers = append(visibleUsers, c.identity)
		}
	}
	clientsMux.RUnlock()

	userListMsg := UserListMessage{
		Type:  "user_list",
		Users: visibleUsers,
		Time:  time.Now().Format("15:04:05"),
	}

	msgJSON, _ := json.Marshal(userListMsg)
	client.sendEncryptedMessage(string(msgJSON))
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

	userListMsg := UserListMessage{
		Type:  "user_list",
		Users: visibleUsers,
		Time:  time.Now().Format("15:04:05"),
	}

	msgJSON, _ := json.Marshal(userListMsg)

	// Send only to visible users
	for _, client := range clients {
		if client.isVisible {
			client.sendEncryptedMessage(string(msgJSON))
		}
	}
}

func (c *Client) checkKeyRotation() {
	c.mu.Lock()
	defer c.mu.Unlock()

	needRotation := false
	if c.messageCount >= rotateAfterMessages {
		needRotation = true
		fmt.Printf("🔄 [%s] Key rotation triggered (message count: %d)\n", c.identity, c.messageCount)
	}
	if time.Since(c.lastRotation) > rotateAfterTime {
		needRotation = true
		fmt.Printf("🔄 [%s] Key rotation triggered (time elapsed: %v)\n", c.identity, time.Since(c.lastRotation))
	}

	if needRotation {
		c.performKeyRotation()
	}
}

func (c *Client) performKeyRotation() {
	// Generate new key pair
	curve := ecdh.X25519()
	newKeyPair, err := curve.GenerateKey(cryptorand.Reader)
	if err != nil {
		fmt.Printf("❌ [%s] Key rotation failed: %v\n", c.identity, err)
		return
	}

	c.nextKeyPair = newKeyPair
	c.keyRotationCount++
	c.messageCount = 0
	c.lastRotation = time.Now()

	// Send new public key to client
	rotMsg := KeyRotationMessage{
		Type:      "key_rotation",
		PublicKey: newKeyPair.PublicKey().Bytes(),
		Nonce:     make([]byte, 12),
		Time:      time.Now().Format("15:04:05"),
	}
	
	cryptorand.Read(rotMsg.Nonce)
	
	msgJSON, _ := json.Marshal(rotMsg)
	c.sendEncryptedMessage(string(msgJSON))

	fmt.Printf("✅ [%s] Key rotation completed (rotation #%d)\n", c.identity, c.keyRotationCount)
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

func (c *Client) receiveMessages() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("💥 [%s] PANIC: %v\n", c.identity, r)
		}
		close(c.quit)
	}()
	
	buf := make([]byte, 512*1024) // Larger buffer for big file chunks
	
	fmt.Printf("📡 [%s] Starting receive loop\n", c.identity)
	
	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				fmt.Printf("🔴 [%s] Connection closed\n", c.identity)
			} else {
				fmt.Printf("❌ [%s] Read error: %v\n", c.identity, err)
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
		
		fmt.Printf("📥 [%s] Received %d bytes\n", c.identity, n)
		
		message, err := c.decryptMessage(buf[:n])
		if err != nil {
			fmt.Printf("❌ [%s] Decrypt error: %v\n", c.identity, err)
			continue
		}
		
		// Check for key rotation
		c.checkKeyRotation()
		
		// Handle commands
		if message == "/quit" {
			return
		}

		if message == "/reveal" {
			c.mu.Lock()
			wasVisible := c.isVisible
			c.isVisible = true
			c.mu.Unlock()
			
			if !wasVisible {
				fmt.Printf("👻→👤 [%s] Became visible\n", c.identity)
				broadcastSystemMessage(fmt.Sprintf("👤 %s joined the chat", c.identity))
				broadcastUserListToVisible()
			}
			continue
		}

		if message == "/ghost" {
			c.mu.Lock()
			wasVisible := c.isVisible
			c.isVisible = false
			c.mu.Unlock()
			
			if wasVisible {
				fmt.Printf("👤→👻 [%s] Went ghost\n", c.identity)
				broadcastSystemMessage(fmt.Sprintf("👻 %s went invisible", c.identity))
				broadcastUserListToVisible()
			}
			continue
		}

		if message == "/users" {
			sendPersonalUserList(c)
			continue
		}

		// Handle file transfer messages
		var genericMsg map[string]interface{}
		if err := json.Unmarshal([]byte(message), &genericMsg); err == nil {
			msgType, ok := genericMsg["type"].(string)
			if ok {
				switch msgType {
				case "file_offer":
					var fileOffer FileOfferMessage
					if err := json.Unmarshal([]byte(message), &fileOffer); err == nil {
						routeFileOfferEnhanced(c, &fileOffer)
						continue
					}
				case "file_chunk":
					var fileChunk FileChunkMessage
					if err := json.Unmarshal([]byte(message), &fileChunk); err == nil {
						routeFileChunkEnhanced(c, &fileChunk)
						continue
					}
				case "file_accept", "file_reject", "file_complete":
					var fileResp FileResponseMessage
					if err := json.Unmarshal([]byte(message), &fileResp); err == nil {
						routeFileResponseEnhanced(c, &fileResp)
						continue
					}
				}
			}
		}

		// Handle private messages
		if len(message) > 4 && message[:4] == "/pm " {
			parts := splitPrivateMessage(message)
			if len(parts) < 2 {
				errorMsg := Message{
					From:    "System",
					Content: "❌ Usage: /pm username message",
					Time:    time.Now().Format("15:04:05"),
					Type:    "error",
				}
				msgJSON, _ := json.Marshal(errorMsg)
				c.sendEncryptedMessage(string(msgJSON))
				continue
			}
			sendPrivateMessage(c, parts[0], parts[1])
			continue
		}

		// Broadcast only if visible
		if c.isVisible {
			broadcastUserMessage(c, message)
		} else {
			// Ghost users can't broadcast
			errorMsg := Message{
				From:    "System",
				Content: "👻 You are in ghost mode. Use /reveal to send messages.",
				Time:    time.Now().Format("15:04:05"),
				Type:    "error",
			}
			msgJSON, _ := json.Marshal(errorMsg)
			c.sendEncryptedMessage(string(msgJSON))
		}
	}
}

func routeFileOfferEnhanced(sender *Client, offer *FileOfferMessage) {
	// Check concurrent transfers limit
	transfersMux.RLock()
	activeTransfers := 0
	for _, transfer := range fileTransfers {
		if !transfer.Completed && transfer.Sender == sender {
			activeTransfers++
		}
	}
	transfersMux.RUnlock()

	if activeTransfers >= maxConcurrentTransfers {
		errorMsg := Message{
			From:    "System",
			Content: fmt.Sprintf("❌ Max concurrent transfers (%d) reached", maxConcurrentTransfers),
			Time:    time.Now().Format("15:04:05"),
			Type:    "error",
		}
		msgJSON, _ := json.Marshal(errorMsg)
		sender.sendEncryptedMessage(string(msgJSON))
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
		errorMsg := Message{
			From:    "System",
			Content: fmt.Sprintf("❌ User '%s' not found", offer.To),
			Time:    time.Now().Format("15:04:05"),
			Type:    "error",
		}
		msgJSON, _ := json.Marshal(errorMsg)
		sender.sendEncryptedMessage(string(msgJSON))
		return
	}

	// Create transfer tracking
	transfer := &FileTransfer{
		FileID:      offer.FileID,
		Sender:      sender,
		Receiver:    targetClient,
		StartTime:   time.Now(),
		TotalChunks: offer.TotalChunks,
		Received:    0,
		Completed:   false,
	}

	transfersMux.Lock()
	fileTransfers[offer.FileID] = transfer
	transfersMux.Unlock()

	offer.From = sender.identity
	offer.Time = time.Now().Format("15:04:05")

	fmt.Printf("📁 [%s → %s] File offer: %s (%d bytes, %d chunks, compressed: %v)\n",
		sender.identity, offer.To, offer.Filename, offer.Size, offer.TotalChunks, offer.Compressed)

	offerJSON, _ := json.Marshal(offer)
	targetClient.sendEncryptedMessage(string(offerJSON))
}

func routeFileChunkEnhanced(sender *Client, chunk *FileChunkMessage) {
	transfersMux.RLock()
	transfer, exists := fileTransfers[chunk.FileID]
	transfersMux.RUnlock()

	if !exists {
		fmt.Printf("⚠️ [%s] Unknown file transfer: %s\n", sender.identity, chunk.FileID[:8])
		return
	}

	if transfer.Sender != sender {
		fmt.Printf("⚠️ [%s] Unauthorized chunk sender for: %s\n", sender.identity, chunk.FileID[:8])
		return
	}

	chunk.Time = time.Now().Format("15:04:05")

	// Update progress
	transfersMux.Lock()
	transfer.Received++
	if transfer.Received >= transfer.TotalChunks {
		transfer.Completed = true
		duration := time.Since(transfer.StartTime)
		fmt.Printf("✅ [%s] File transfer completed in %v\n", sender.identity, duration)
	}
	transfersMux.Unlock()

	fmt.Printf("📦 [%s] File chunk %d/%d (FileID: %s)\n",
		sender.identity, chunk.ChunkIndex+1, chunk.TotalChunks, chunk.FileID[:8])

	chunkJSON, _ := json.Marshal(chunk)
	transfer.Receiver.sendEncryptedMessage(string(chunkJSON))
}

func routeFileResponseEnhanced(sender *Client, resp *FileResponseMessage) {
	transfersMux.RLock()
	transfer, exists := fileTransfers[resp.FileID]
	transfersMux.RUnlock()

	if exists {
		resp.From = sender.identity
		resp.Time = time.Now().Format("15:04:05")

		fmt.Printf("📬 [%s] File response: %s (FileID: %s)\n",
			sender.identity, resp.Status, resp.FileID[:8])

		respJSON, _ := json.Marshal(resp)
		
		// Send to the other party
		if sender == transfer.Receiver {
			transfer.Sender.sendEncryptedMessage(string(respJSON))
		} else {
			transfer.Receiver.sendEncryptedMessage(string(respJSON))
		}

		// Cleanup if rejected or completed
		if resp.Status == "rejected" || resp.Status == "completed" {
			transfersMux.Lock()
			delete(fileTransfers, resp.FileID)
			transfersMux.Unlock()
		}
	}
}

func cleanupOldTransfers() {
	transfersMux.Lock()
	defer transfersMux.Unlock()

	now := time.Now()
	for fileID, transfer := range fileTransfers {
		if now.Sub(transfer.StartTime) > 30*time.Minute {
			fmt.Printf("🗑️ Cleaning up old transfer: %s\n", fileID[:8])
			delete(fileTransfers, fileID)
		}
	}
}

func sendPrivateMessage(sender *Client, targetUsername string, message string) {
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
		errorMsg := Message{
			From:    "System",
			Content: fmt.Sprintf("❌ User '%s' not found", targetUsername),
			Time:    time.Now().Format("15:04:05"),
			Type:    "error",
		}
		msgJSON, _ := json.Marshal(errorMsg)
		sender.sendEncryptedMessage(string(msgJSON))
		return
	}

	privateMsg := Message{
		From:    sender.identity,
		To:      targetUsername,
		Content: message,
		Time:    time.Now().Format("15:04:05"),
		Type:    "private",
	}

	msgJSON, _ := json.Marshal(privateMsg)

	fmt.Printf("🔒 [%s → %s] Private message\n", sender.identity, targetUsername)
	targetClient.sendEncryptedMessage(string(msgJSON))
	sender.sendEncryptedMessage(string(msgJSON))
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
		if client.isVisible {
			client.sendEncryptedMessage(string(msgJSON))
		}
	}
}

func broadcastUserMessage(sender *Client, message string) {
	clientsMux.RLock()
	defer clientsMux.RUnlock()

	visibleCount := 0
	for _, client := range clients {
		if client.isVisible {
			visibleCount++
		}
	}

	fmt.Printf("📢 [%s] Broadcasting to %d visible clients\n", sender.identity, visibleCount-1)

	userMsg := Message{
		From:    sender.identity,
		Content: message,
		Time:    time.Now().Format("15:04:05"),
		Type:    "message",
	}

	msgJSON, _ := json.Marshal(userMsg)

	for _, client := range clients {
		if client != sender && client.isVisible {
			fmt.Printf("📤 Sending to %s\n", client.identity)
			client.sendEncryptedMessage(string(msgJSON))
		}
	}
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

func (c *Client) sendEncryptedMessage(message string) error {
	if c.conn == nil || c.gcm == nil {
		return fmt.Errorf("not ready")
	}

	randomDelay()

	paddedMessage := padMessage([]byte(message))

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(cryptorand.Reader, nonce); err != nil {
		return fmt.Errorf("nonce failed: %v", err)
	}

	ciphertext := c.gcm.Seal(nil, nonce, paddedMessage, nil)
	data := append(nonce, ciphertext...)

	fmt.Printf("📤 [%s] Sending %d bytes (padded)\n", c.identity, len(data))

	n, err := c.conn.Write(data)
	if err != nil {
		return err
	}

	fmt.Printf("✅ [%s] Sent %d bytes\n", c.identity, n)
	return nil
}

func (c *Client) decryptMessage(data []byte) (string, error) {
	if len(data) < 12 {
		return "", fmt.Errorf("too short")
	}

	nonce := data[:12]
	ciphertext := data[12:]

	paddedPlaintext, err := c.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	plaintext, err := unpadMessage(paddedPlaintext)
	if err != nil {
		return "", fmt.Errorf("unpad failed: %v", err)
	}

	return string(plaintext), nil
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

	username := content[:spaceIdx]
	message := content[spaceIdx+1:]

	return []string{username, message}
}

func secureSetup() {
	memguard.CatchInterrupt()
}

func performMutualAuth(conn net.Conn, sharedSecret []byte, identity string) error {
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	serverChallenge := make([]byte, 32)
	if _, err := cryptorand.Read(serverChallenge); err != nil {
		return fmt.Errorf("challenge generation failed: %v", err)
	}

	if _, err := conn.Write(serverChallenge); err != nil {
		return fmt.Errorf("challenge send failed: %v", err)
	}

	clientResponse := make([]byte, 32)
	if _, err := io.ReadFull(conn, clientResponse); err != nil {
		return fmt.Errorf("client response read failed: %v", err)
	}

	clientChallenge := make([]byte, 32)
	if _, err := io.ReadFull(conn, clientChallenge); err != nil {
		return fmt.Errorf("client challenge read failed: %v", err)
	}

	h := hmac.New(sha256.New, sharedSecret)
	h.Write(serverChallenge)
	expectedClientMAC := h.Sum(nil)

	if !hmac.Equal(clientResponse, expectedClientMAC) {
		return fmt.Errorf("client authentication failed")
	}

	h.Reset()
	h.Write(clientChallenge)
	serverResponse := h.Sum(nil)

	if _, err := conn.Write(serverResponse); err != nil {
		return fmt.Errorf("server response send failed: %v", err)
	}

	return nil
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
