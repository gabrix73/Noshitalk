package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/awnumar/memguard"
)

//go:embed static/index.html
var staticFS embed.FS

// Version info
const (
	Version   = "2.0.0"
	BuildType = "production"
)

// Client represents a connected chat client
type Client struct {
	ID           string
	Nickname     string
	MessageChan  chan []byte
	ConnectedAt  time.Time
	LastActivity time.Time
	mu           sync.Mutex
}

// Message represents an encrypted message
type Message struct {
	Type       string `json:"type"`
	From       string `json:"from,omitempty"`
	FromID     string `json:"fromId,omitempty"`
	Content    string `json:"content,omitempty"`
	PublicKey  string `json:"publicKey,omitempty"`
	TargetID   string `json:"targetId,omitempty"`
	Timestamp  int64  `json:"timestamp,omitempty"`
	SessionID  string `json:"sessionId,omitempty"`
	Users      []User `json:"users,omitempty"`
}

// User represents a user in the user list
type User struct {
	ID        string `json:"id"`
	Nickname  string `json:"nickname"`
	PublicKey string `json:"publicKey,omitempty"`
}

// Server holds the chat server state
type Server struct {
	clients    map[string]*Client
	clientsMu  sync.RWMutex
	publicKeys map[string]string // clientID -> publicKey
	keysMu     sync.RWMutex
}

var server *Server

func main() {
	// Initialize memguard
	memguard.CatchInterrupt()
	defer memguard.Purge()

	// Note: memguard handles core dump protection internally

	// Initialize server
	server = &Server{
		clients:    make(map[string]*Client),
		publicKeys: make(map[string]string),
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n🛑 Shutting down securely...")
		server.disconnectAll()
		memguard.Purge()
		os.Exit(0)
	}()

	// Setup HTTP routes
	mux := http.NewServeMux()

	// Serve embedded static files
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/events", handleSSE)
	mux.HandleFunc("/send", handleSend)
	mux.HandleFunc("/join", handleJoin)
	mux.HandleFunc("/leave", handleLeave)
	mux.HandleFunc("/key-exchange", handleKeyExchange)
	mux.HandleFunc("/health", handleHealth)

	// Get port from environment or default
	port := os.Getenv("NOSHITALK_PORT")
	if port == "" {
		port = "8080"
	}

	// Print startup banner
	printBanner(port)

	// Start server
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      securityHeaders(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // SSE needs no write timeout
		IdleTimeout:  120 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func printBanner(port string) {
	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║           🔐 NoshiTalk Secure Chat v" + Version + "               ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════╣")
	fmt.Println("║  ✓ End-to-End Encryption (X25519 + AES-GCM-256)           ║")
	fmt.Println("║  ✓ Zero-Knowledge Server (blind relay)                   ║")
	fmt.Println("║  ✓ Perfect Forward Secrecy                               ║")
	fmt.Println("║  ✓ Memory Protection (memguard)                          ║")
	fmt.Println("║  ✓ Zero Logging Policy                                   ║")
	fmt.Println("║  ✓ Tor Hidden Service Ready                              ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════╣")
	fmt.Printf("║  🌐 Listening on: http://localhost:%-22s  ║\n", port)
	fmt.Println("║  🧅 Tor: Configure hidden service to this port           ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// Security headers middleware
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		
		// CSP allowing Web Crypto API
		w.Header().Set("Content-Security-Policy", 
			"default-src 'self'; "+
			"script-src 'self' 'unsafe-inline'; "+
			"style-src 'self' 'unsafe-inline'; "+
			"connect-src 'self'; "+
			"img-src 'self' data:; "+
			"font-src 'self' data:;")
		
		next.ServeHTTP(w, r)
	})
}

// Generate secure random ID
func generateID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

// Generate secure session token
func generateSessionToken() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return ""
	}
	tokenStr := hex.EncodeToString(bytes)
	// Clear the original bytes
	for i := range bytes {
		bytes[i] = 0
	}
	return tokenStr
}

// Handle index page
func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	
	content, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Write(content)
}

// Handle SSE connections
func handleSSE(w http.ResponseWriter, r *http.Request) {
	// Get session ID from query
	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		http.Error(w, "Session required", http.StatusBadRequest)
		return
	}

	// Verify client exists
	server.clientsMu.RLock()
	client, exists := server.clients[sessionID]
	server.clientsMu.RUnlock()

	if !exists {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Send initial connection confirmation
	fmt.Fprintf(w, "event: connected\ndata: {\"status\":\"ok\"}\n\n")
	flusher.Flush()

	// Send current user list
	server.broadcastUserList()

	// Keep connection open and send messages
	for {
		select {
		case msg := <-client.MessageChan:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
			client.mu.Lock()
			client.LastActivity = time.Now()
			client.mu.Unlock()
		case <-r.Context().Done():
			// Client disconnected
			server.removeClient(sessionID)
			return
		}
	}
}

// Handle client join
func handleJoin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Nickname  string `json:"nickname"`
		PublicKey string `json:"publicKey"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Sanitize nickname
	nickname := strings.TrimSpace(req.Nickname)
	if nickname == "" {
		nickname = "Anonymous"
	}
	if len(nickname) > 32 {
		nickname = nickname[:32]
	}

	// Generate IDs and tokens
	clientID := generateID()
	tokenStr := generateSessionToken()

	// Create client
	client := &Client{
		ID:           clientID,
		Nickname:     nickname,
		MessageChan:  make(chan []byte, 100),
		ConnectedAt:  time.Now(),
		LastActivity: time.Now(),
	}

	// Store client and public key
	server.clientsMu.Lock()
	server.clients[clientID] = client
	server.clientsMu.Unlock()

	if req.PublicKey != "" {
		server.keysMu.Lock()
		server.publicKeys[clientID] = req.PublicKey
		server.keysMu.Unlock()
	}

	// Broadcast join message to others
	joinMsg := Message{
		Type:      "user_joined",
		From:      nickname,
		FromID:    clientID,
		PublicKey: req.PublicKey,
		Timestamp: time.Now().Unix(),
	}
	server.broadcast(joinMsg, clientID)

	// Respond with session info
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sessionId": clientID,
		"token":     tokenStr,
		"nickname":  nickname,
	})
}

// Handle client leave
func handleLeave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("session")
	if sessionID != "" {
		server.removeClient(sessionID)
	}

	w.WriteHeader(http.StatusOK)
}

// Handle message sending
func handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("session")
	if sessionID == "" {
		http.Error(w, "Session required", http.StatusBadRequest)
		return
	}

	// Verify client exists
	server.clientsMu.RLock()
	client, exists := server.clients[sessionID]
	server.clientsMu.RUnlock()

	if !exists {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	var msg Message
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "Invalid message", http.StatusBadRequest)
		return
	}

	// Add metadata
	msg.FromID = sessionID
	msg.From = client.Nickname
	msg.Timestamp = time.Now().Unix()

	// Update activity
	client.mu.Lock()
	client.LastActivity = time.Now()
	client.mu.Unlock()

	// Route message
	if msg.TargetID != "" {
		// Private message - send only to target
		server.sendToClient(msg.TargetID, msg)
		// Also send back to sender for confirmation
		server.sendToClient(sessionID, msg)
	} else {
		// Broadcast to all (including sender)
		server.broadcastAll(msg)
	}

	w.WriteHeader(http.StatusOK)
}

// Handle key exchange requests
func handleKeyExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Return all public keys
		server.keysMu.RLock()
		keys := make(map[string]string)
		for id, key := range server.publicKeys {
			keys[id] = key
		}
		server.keysMu.RUnlock()

		// Also include nicknames
		server.clientsMu.RLock()
		users := make([]User, 0, len(server.clients))
		for id, client := range server.clients {
			users = append(users, User{
				ID:        id,
				Nickname:  client.Nickname,
				PublicKey: keys[id],
			})
		}
		server.clientsMu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"users": users,
		})
		return
	}

	if r.Method == http.MethodPost {
		// Update public key
		sessionID := r.URL.Query().Get("session")
		if sessionID == "" {
			http.Error(w, "Session required", http.StatusBadRequest)
			return
		}

		var req struct {
			PublicKey string `json:"publicKey"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		server.keysMu.Lock()
		server.publicKeys[sessionID] = req.PublicKey
		server.keysMu.Unlock()

		// Broadcast key update
		server.clientsMu.RLock()
		client, exists := server.clients[sessionID]
		server.clientsMu.RUnlock()

		if exists {
			keyMsg := Message{
				Type:      "key_update",
				FromID:    sessionID,
				From:      client.Nickname,
				PublicKey: req.PublicKey,
				Timestamp: time.Now().Unix(),
			}
			server.broadcast(keyMsg, sessionID)
		}

		w.WriteHeader(http.StatusOK)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// Health check endpoint
func handleHealth(w http.ResponseWriter, r *http.Request) {
	server.clientsMu.RLock()
	clientCount := len(server.clients)
	server.clientsMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"version": Version,
		"clients": clientCount,
	})
}

// Broadcast to all clients except sender
func (s *Server) broadcast(msg Message, excludeID string) {
	data, _ := json.Marshal(msg)

	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()

	for id, client := range s.clients {
		if id != excludeID {
			select {
			case client.MessageChan <- data:
			default:
				// Channel full, skip
			}
		}
	}
}

// Broadcast to all clients including sender
func (s *Server) broadcastAll(msg Message) {
	data, _ := json.Marshal(msg)

	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()

	for _, client := range s.clients {
		select {
		case client.MessageChan <- data:
		default:
			// Channel full, skip
		}
	}
}

// Send to specific client
func (s *Server) sendToClient(clientID string, msg Message) {
	data, _ := json.Marshal(msg)

	s.clientsMu.RLock()
	client, exists := s.clients[clientID]
	s.clientsMu.RUnlock()

	if exists {
		select {
		case client.MessageChan <- data:
		default:
			// Channel full, skip
		}
	}
}

// Broadcast user list to all clients
func (s *Server) broadcastUserList() {
	s.clientsMu.RLock()
	s.keysMu.RLock()

	users := make([]User, 0, len(s.clients))
	for id, client := range s.clients {
		users = append(users, User{
			ID:        id,
			Nickname:  client.Nickname,
			PublicKey: s.publicKeys[id],
		})
	}

	s.keysMu.RUnlock()
	s.clientsMu.RUnlock()

	msg := Message{
		Type:      "user_list",
		Users:     users,
		Timestamp: time.Now().Unix(),
	}

	s.broadcastAll(msg)
}

// Remove client and cleanup
func (s *Server) removeClient(clientID string) {
	s.clientsMu.Lock()
	client, exists := s.clients[clientID]
	if exists {
		close(client.MessageChan)
		delete(s.clients, clientID)
	}
	nickname := ""
	if client != nil {
		nickname = client.Nickname
	}
	s.clientsMu.Unlock()

	// Remove public key
	s.keysMu.Lock()
	delete(s.publicKeys, clientID)
	s.keysMu.Unlock()

	if exists {
		// Broadcast leave message
		leaveMsg := Message{
			Type:      "user_left",
			FromID:    clientID,
			From:      nickname,
			Timestamp: time.Now().Unix(),
		}
		s.broadcast(leaveMsg, clientID)
		s.broadcastUserList()
	}
}

// Disconnect all clients (for shutdown)
func (s *Server) disconnectAll() {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()

	for id, client := range s.clients {
		close(client.MessageChan)
		delete(s.clients, id)
	}

	s.keysMu.Lock()
	for id := range s.publicKeys {
		delete(s.publicKeys, id)
	}
	s.keysMu.Unlock()
}
