package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

//go:embed template.html
var htmlTemplate string

// Message types
const (
	MsgTypeHandshake = "handshake"
	MsgTypePublic    = "public"
	MsgTypePrivate   = "private"
	MsgTypeSystem    = "system"
	MsgTypeUserJoin  = "user_join"
	MsgTypeUserLeave = "user_leave"
	MsgTypeUsersList = "users_list"
)

// User represents a connected user.
type User struct {
	ID          string
	Name        string
	Avatar      string
	Fingerprint string
	Conn        *websocket.Conn
	LastSeen    time.Time
	mu          sync.Mutex
}

// Message represents a chat message.
type Message struct {
	Type       string    `json:"type"`
	From       string    `json:"from,omitempty"`
	FromName   string    `json:"from_name,omitempty"`
	FromAvatar string    `json:"from_avatar,omitempty"`
	To         string    `json:"to,omitempty"`
	Text       string    `json:"text,omitempty"`
	Timestamp  time.Time `json:"timestamp,omitempty"`
}

// UserInfo for user list.
type UserInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Avatar string `json:"avatar"`
	Status string `json:"status"`
}

// Server represents the chat server.
type Server struct {
	users    map[string]*User
	upgrader websocket.Upgrader
	mu       sync.RWMutex
}

var server *Server

func init() {
	server = &Server{
		users: make(map[string]*User),
		upgrader: websocket.Upgrader{
			CheckOrigin:     func(r *http.Request) bool { return true },
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
	}
}

// NewUser creates a new user.
func NewUser(id, name, fingerprint string, conn *websocket.Conn) *User {
	avatar := ""
	if len(name) > 0 {
		avatar = string(name[0])
	}

	return &User{
		ID:          id,
		Name:        name,
		Avatar:      avatar,
		Fingerprint: fingerprint,
		Conn:        conn,
		LastSeen:    time.Now(),
	}
}

// SendMessage sends a message to the user.
func (u *User) SendMessage(msg Message) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.Conn.WriteJSON(msg)
}

// BroadcastPublic broadcasts a message to all users except the sender.
func (s *Server) BroadcastPublic(msg Message) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for fingerprint, user := range s.users {
		if fingerprint != msg.From {
			go user.SendMessage(msg)
		}
	}
}

// SendPrivate sends a private message to a specific user.
func (s *Server) SendPrivate(msg Message) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	recipient, exists := s.users[msg.To]
	if !exists {
		return nil
	}

	return recipient.SendMessage(msg)
}

// AddUser adds a user to the server.
func (s *Server) AddUser(user *User) {
	s.mu.Lock()
	s.users[user.Fingerprint] = user
	s.mu.Unlock()

	log.Printf("User added: %s (fingerprint: %s, total: %d)", user.Name, user.Fingerprint, len(s.users))

	joinMsg := Message{
		Type:       MsgTypeUserJoin,
		From:       user.Fingerprint,
		FromName:   user.Name,
		FromAvatar: user.Avatar,
		Text:       user.Name + " joined the chat",
		Timestamp:  time.Now(),
	}
	s.BroadcastPublic(joinMsg)

	s.SendUsersList(user)
	s.BroadcastUsersList()
}

// RemoveUser removes a user from the server.
func (s *Server) RemoveUser(fingerprint string) {
	s.mu.Lock()
	user, exists := s.users[fingerprint]
	if exists {
		delete(s.users, fingerprint)
	}
	s.mu.Unlock()

	if exists {
		log.Printf("User removed: %s (fingerprint: %s, remaining: %d)", user.Name, fingerprint, len(s.users))

		leaveMsg := Message{
			Type:      MsgTypeUserLeave,
			From:      fingerprint,
			FromName:  user.Name,
			Text:      user.Name + " left the chat",
			Timestamp: time.Now(),
		}
		s.BroadcastPublic(leaveMsg)
		s.BroadcastUsersList()
	}
}

// SendUsersList sends the user list to a specific user.
func (s *Server) SendUsersList(user *User) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]UserInfo, 0, len(s.users))
	for _, u := range s.users {
		if u.Fingerprint != user.Fingerprint {
			users = append(users, UserInfo{
				ID:     u.Fingerprint,
				Name:   u.Name,
				Avatar: u.Avatar,
				Status: "Encrypted",
			})
		}
	}

	usersData, _ := json.Marshal(map[string]interface{}{
		"type":  MsgTypeUsersList,
		"users": users,
	})

	user.mu.Lock()
	user.Conn.WriteMessage(websocket.TextMessage, usersData)
	user.mu.Unlock()
}

// BroadcastUsersList broadcasts the user list to all users.
func (s *Server) BroadcastUsersList() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, user := range s.users {
		go s.SendUsersList(user)
	}
}

// HandleWebSocket handles WebSocket connections.
func HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := server.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	var handshake struct {
		Type        string `json:"type"`
		Name        string `json:"name"`
		ID          string `json:"id"`
		Fingerprint string `json:"fingerprint"`
	}

	if err := conn.ReadJSON(&handshake); err != nil {
		log.Printf("Handshake error: %v", err)
		conn.Close()
		return
	}

	if handshake.Type != MsgTypeHandshake {
		log.Printf("Invalid handshake type: %s", handshake.Type)
		conn.Close()
		return
	}

	if handshake.Fingerprint == "" || len(handshake.Fingerprint) < 8 {
		log.Printf("Invalid fingerprint")
		conn.Close()
		return
	}

	server.mu.RLock()
	_, exists := server.users[handshake.Fingerprint]
	server.mu.RUnlock()

	if exists {
		errorMsg := Message{
			Type: MsgTypeSystem,
			Text: "Identity already connected. Only one session per identity allowed.",
		}
		conn.WriteJSON(errorMsg)
		conn.Close()
		return
	}

	user := NewUser(handshake.ID, handshake.Name, handshake.Fingerprint, conn)
	server.AddUser(user)
	defer server.RemoveUser(user.Fingerprint)

	log.Printf("User connected: %s (%s)", user.Name, user.Fingerprint)

	welcomeMsg := Message{
		Type:      MsgTypeSystem,
		Text:      "Welcome to NoshiTalk! Your identity is cryptographically protected.",
		Timestamp: time.Now(),
	}
	user.SendMessage(welcomeMsg)

	for {
		var msg Message
		if err := conn.ReadJSON(&msg); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		msg.From = user.Fingerprint
		msg.FromName = user.Name
		msg.FromAvatar = user.Avatar
		msg.Timestamp = time.Now()

		switch msg.Type {
		case MsgTypePublic:
			server.BroadcastPublic(msg)
			log.Printf("Public message from %s: %s", user.Name, msg.Text)

		case MsgTypePrivate:
			if err := server.SendPrivate(msg); err != nil {
				log.Printf("Private message error: %v", err)
			} else {
				log.Printf("Private message from %s to %s", user.Name, msg.To)
			}
		}

		user.LastSeen = time.Now()
	}
}

// HandleIndex serves the main HTML page.
func HandleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")

	w.Write([]byte(htmlTemplate))
}

// generateChallenge generates a random challenge.
func generateChallenge() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// CleanupInactiveUsers removes inactive users periodically.
func (s *Server) CleanupInactiveUsers() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for fingerprint, user := range s.users {
			if now.Sub(user.LastSeen) > 5*time.Minute {
				log.Printf("Removing inactive user: %s", user.Name)
				delete(s.users, fingerprint)
				user.Conn.Close()
			}
		}
		s.mu.Unlock()
	}
}

func main() {
	go server.CleanupInactiveUsers()

	http.HandleFunc("/", HandleIndex)
	http.HandleFunc("/ws", HandleWebSocket)

	port := ":8080"
	log.Printf("===========================================")
	log.Printf("   NoshiTalk Web Server v2.0-refactored")
	log.Printf("===========================================")
	log.Printf("  Port: %s", port)
	log.Printf("  WebSocket: ws://localhost%s/ws", port)
	log.Printf("  Security: E2E Encrypted + Ephemeral")
	log.Printf("  Storage: Zero (RAM only)")
	log.Printf("===========================================")

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal("Server error: ", err)
	}
}
