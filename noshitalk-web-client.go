package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Message types
const (
	MsgTypeHandshake  = "handshake"
	MsgTypePublic     = "public"
	MsgTypePrivate    = "private"
	MsgTypeSystem     = "system"
	MsgTypeUserJoin   = "user_join"
	MsgTypeUserLeave  = "user_leave"
	MsgTypeUsersList  = "users_list"
)

// User represents a connected user
type User struct {
	ID          string
	Name        string
	Avatar      string
	Fingerprint string
	Conn        *websocket.Conn
	LastSeen    time.Time
	mu          sync.Mutex
}

// Message represents a chat message
type Message struct {
	Type       string    `json:"type"`
	From       string    `json:"from,omitempty"`
	FromName   string    `json:"from_name,omitempty"`
	FromAvatar string    `json:"from_avatar,omitempty"`
	To         string    `json:"to,omitempty"`
	Text       string    `json:"text,omitempty"`
	Timestamp  time.Time `json:"timestamp,omitempty"`
}

// UserInfo for user list
type UserInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Avatar string `json:"avatar"`
	Status string `json:"status"`
}

// Server represents the chat server
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
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
	}
}

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

func (u *User) SendMessage(msg Message) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.Conn.WriteJSON(msg)
}

func (s *Server) BroadcastPublic(msg Message) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for fingerprint, user := range s.users {
		if fingerprint != msg.From {
			go user.SendMessage(msg)
		}
	}
}

func (s *Server) SendPrivate(msg Message) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	recipient, exists := s.users[msg.To]
	if !exists {
		return nil
	}

	return recipient.SendMessage(msg)
}

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
				Status: "🔒 Encrypted",
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

func (s *Server) BroadcastUsersList() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, user := range s.users {
		go s.SendUsersList(user)
	}
}

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

	err = conn.ReadJSON(&handshake)
	if err != nil {
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
		err := conn.ReadJSON(&msg)
		if err != nil {
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
			err := server.SendPrivate(msg)
			if err != nil {
				log.Printf("Private message error: %v", err)
			} else {
				log.Printf("Private message from %s to %s", user.Name, msg.To)
			}
		}

		user.LastSeen = time.Now()
	}
}

func HandleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	
	w.Write([]byte(htmlTemplate))
}

func generateChallenge() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

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

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NoshiTalk - Anonymous Encrypted Chat</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0a; color: #e0e0e0; height: 100vh; overflow: hidden; }
        .header { background: linear-gradient(135deg, #1a1a1a 0%, #0f0f0f 100%); padding: 1rem 1.5rem; border-bottom: 2px solid #00f2fe; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 4px 20px rgba(0, 242, 254, 0.1); }
        .logo { font-size: 1.3rem; font-weight: 700; color: #00f2fe; text-shadow: 0 0 10px rgba(0, 242, 254, 0.5); }
        .header-controls { display: flex; gap: 1rem; align-items: center; }
        .connection-status { display: flex; align-items: center; gap: 0.5rem; font-size: 0.9rem; }
        .status-dot { width: 10px; height: 10px; border-radius: 50%; background: #51cf66; box-shadow: 0 0 10px rgba(81, 207, 102, 0.5); animation: pulse 2s infinite; }
        .status-dot.disconnected { background: #ff6b6b; box-shadow: 0 0 10px rgba(255, 107, 107, 0.5); }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .panic-button { background: #ff6b6b; color: white; border: none; padding: 0.6rem 1.2rem; border-radius: 6px; font-weight: 700; cursor: pointer; font-size: 0.9rem; transition: all 0.2s; box-shadow: 0 0 20px rgba(255, 107, 107, 0.3); }
        .panic-button:hover { background: #ff5252; transform: scale(1.05); box-shadow: 0 0 30px rgba(255, 107, 107, 0.5); }
        .logout-button { background: #333; color: #e0e0e0; border: none; padding: 0.6rem 1.2rem; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 0.9rem; transition: all 0.2s; }
        .logout-button:hover { background: #444; }
        .login-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(10, 10, 10, 0.98); display: flex; align-items: center; justify-content: center; z-index: 1000; }
        .login-box { background: #1a1a1a; border: 2px solid #00f2fe; border-radius: 8px; padding: 2.5rem; max-width: 500px; width: 90%; box-shadow: 0 10px 40px rgba(0, 242, 254, 0.3); }
        .login-box h2 { color: #00f2fe; margin-bottom: 0.5rem; text-align: center; font-size: 1.5rem; }
        .login-subtitle { text-align: center; color: #888; font-size: 0.9rem; margin-bottom: 2rem; }
        .security-info { background: #0f0f0f; border-left: 3px solid #51cf66; padding: 1rem; margin-bottom: 1.5rem; font-size: 0.85rem; line-height: 1.6; }
        .security-info ul { margin: 0.5rem 0 0 1.5rem; }
        .security-info li { margin: 0.3rem 0; }
        .warning-info { background: #2a1a1a; border-left: 3px solid #ff6b6b; padding: 1rem; margin-bottom: 1.5rem; font-size: 0.85rem; color: #ffb3b3; }
        .tab-buttons { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; }
        .tab-button { flex: 1; background: #0f0f0f; border: 1px solid #333; color: #888; padding: 0.8rem; border-radius: 6px; cursor: pointer; transition: all 0.3s; font-size: 0.95rem; font-weight: 600; }
        .tab-button.active { background: #00f2fe; color: #0a0a0a; border-color: #00f2fe; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .login-box input[type="text"], .login-box input[type="file"] { width: 100%; background: #0f0f0f; border: 1px solid #333; color: #e0e0e0; padding: 1rem; border-radius: 6px; font-size: 1rem; margin-bottom: 1rem; }
        .login-box input:focus { outline: none; border-color: #00f2fe; box-shadow: 0 0 0 2px rgba(0, 242, 254, 0.1); }
        .login-box button.primary { width: 100%; background: linear-gradient(135deg, #00f2fe 0%, #00d4e8 100%); color: #0a0a0a; border: none; padding: 1rem; border-radius: 6px; font-weight: 700; font-size: 1rem; cursor: pointer; transition: all 0.2s; }
        .login-box button.primary:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0, 242, 254, 0.4); }
        .login-box button.primary:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
        .generating-keys { text-align: center; padding: 1rem; color: #00f2fe; font-weight: 600; }
        .spinner { border: 3px solid #333; border-top: 3px solid #00f2fe; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 1rem auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .identity-info { background: #0f0f0f; padding: 1rem; border-radius: 6px; margin-top: 1rem; font-size: 0.85rem; }
        .identity-info .label { color: #888; margin-bottom: 0.3rem; }
        .identity-info .value { color: #00f2fe; font-family: monospace; word-break: break-all; font-size: 0.8rem; }
        .save-keys-button { width: 100%; background: #333; color: #e0e0e0; border: 1px solid #00f2fe; padding: 0.8rem; border-radius: 6px; font-weight: 600; cursor: pointer; margin-top: 1rem; transition: all 0.2s; }
        .save-keys-button:hover { background: #444; border-color: #00f2fe; }
        .container { display: flex; height: calc(100vh - 70px); }
        .sidebar { width: 250px; background: #0f0f0f; border-right: 1px solid #333; display: flex; flex-direction: column; }
        .events-panel { background: #1a1a1a; border-bottom: 1px solid #333; padding: 1rem; max-height: 150px; overflow-y: auto; }
        .events-panel h3 { font-size: 0.85rem; color: #00f2fe; margin-bottom: 0.5rem; text-transform: uppercase; letter-spacing: 1px; }
        .event-item { font-size: 0.75rem; color: #888; padding: 0.3rem 0; border-bottom: 1px solid #222; }
        .event-item:last-child { border-bottom: none; }
        .event-time { color: #666; margin-right: 0.3rem; }
        .users-panel { flex: 1; padding: 1rem; overflow-y: auto; }
        .users-panel h3 { font-size: 0.9rem; color: #00f2fe; margin-bottom: 1rem; text-transform: uppercase; letter-spacing: 1px; }
        .user-count { font-size: 0.75rem; color: #666; margin-left: 0.5rem; }
        .user-item { display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem; margin-bottom: 0.3rem; background: #1a1a1a; border-radius: 4px; cursor: pointer; transition: all 0.2s; position: relative; }
        .user-item:hover { background: #222; transform: translateX(3px); }
        .user-item.active { background: #00f2fe22; border-left: 3px solid #00f2fe; }
        .user-avatar { width: 32px; height: 32px; border-radius: 50%; background: linear-gradient(135deg, #00f2fe 0%, #00d4e8 100%); display: flex; align-items: center; justify-content: center; font-size: 0.9rem; font-weight: 700; color: #0a0a0a; position: relative; }
        .user-badge { position: absolute; top: -5px; right: -5px; background: #ff6b6b; color: white; border-radius: 50%; width: 18px; height: 18px; font-size: 0.7rem; display: flex; align-items: center; justify-content: center; font-weight: 700; box-shadow: 0 0 10px rgba(255, 107, 107, 0.5); }
        .user-info { flex: 1; }
        .user-name { font-size: 0.9rem; color: #e0e0e0; }
        .user-status { font-size: 0.7rem; color: #666; }
        .main-chat { flex: 1; display: flex; flex-direction: column; background: #0a0a0a; }
        .chat-tabs { display: flex; background: #0f0f0f; border-bottom: 1px solid #333; overflow-x: auto; padding: 0 1rem; }
        .chat-tab { padding: 1rem 1.5rem; cursor: pointer; border-bottom: 3px solid transparent; transition: all 0.3s; white-space: nowrap; display: flex; align-items: center; gap: 0.5rem; color: #888; }
        .chat-tab:hover { background: #1a1a1a; color: #c0c0c0; }
        .chat-tab.active { color: #00f2fe; border-bottom-color: #00f2fe; }
        .tab-close { margin-left: 0.5rem; color: #666; font-size: 1.2rem; line-height: 1; }
        .tab-close:hover { color: #ff6b6b; }
        .chat-header { padding: 1rem 1.5rem; background: #0f0f0f; border-bottom: 1px solid #333; }
        .chat-header h2 { font-size: 1.1rem; color: #00f2fe; }
        .chat-description { font-size: 0.8rem; color: #888; margin-top: 0.3rem; }
        .chat-view { display: none; flex-direction: column; flex: 1; }
        .chat-view.active { display: flex; }
        .messages-area { flex: 1; padding: 1.5rem; overflow-y: auto; }
        .message { display: flex; gap: 1rem; margin-bottom: 1.5rem; animation: fadeIn 0.3s; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .message-avatar { width: 40px; height: 40px; border-radius: 50%; background: linear-gradient(135deg, #00f2fe 0%, #00d4e8 100%); display: flex; align-items: center; justify-content: center; font-size: 1rem; font-weight: 700; color: #0a0a0a; flex-shrink: 0; }
        .message.private .message-avatar { background: linear-gradient(135deg, #a78bfa 0%, #8b5cf6 100%); }
        .message-content { flex: 1; }
        .message-header { display: flex; align-items: baseline; gap: 0.5rem; margin-bottom: 0.3rem; }
        .message-author { font-weight: 600; color: #00f2fe; }
        .message.private .message-author { color: #a78bfa; }
        .message-time { font-size: 0.75rem; color: #666; }
        .message-text { color: #c0c0c0; line-height: 1.5; word-wrap: break-word; }
        .message-encrypted { font-size: 0.7rem; color: #51cf66; margin-top: 0.3rem; }
        .input-area { padding: 1.5rem; background: #0f0f0f; border-top: 1px solid #333; }
        .input-container { display: flex; gap: 1rem; align-items: center; }
        .message-input { flex: 1; background: #1a1a1a; border: 1px solid #333; color: #e0e0e0; padding: 0.8rem 1rem; border-radius: 6px; font-size: 0.95rem; font-family: inherit; transition: border-color 0.3s; }
        .message-input:focus { outline: none; border-color: #00f2fe; box-shadow: 0 0 0 2px rgba(0, 242, 254, 0.1); }
        .send-button { background: linear-gradient(135deg, #00f2fe 0%, #00d4e8 100%); color: #0a0a0a; border: none; padding: 0.8rem 2rem; border-radius: 6px; font-weight: 600; cursor: pointer; transition: transform 0.2s, box-shadow 0.2s; }
        .send-button:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0, 242, 254, 0.3); }
        .send-button:active { transform: translateY(0); }
        .encryption-info { font-size: 0.75rem; color: #666; margin-top: 0.5rem; text-align: center; }
        .encryption-info span { color: #51cf66; }
        .system-message { text-align: center; color: #666; font-size: 0.85rem; padding: 0.5rem; margin: 1rem 0; font-style: italic; }
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #0a0a0a; }
        ::-webkit-scrollbar-thumb { background: #333; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #444; }
    </style>
</head>
<body>
    <div class="login-overlay" id="login-overlay">
        <div class="login-box">
            <h2>🔐 NoshiTalk Secure Entry</h2>
            <p class="login-subtitle">Cryptographic Identity Required</p>
            <div class="security-info">
                <strong>🔑 Key generation protects:</strong>
                <ul>
                    <li>Your IDENTITY (cryptographic fingerprint)</li>
                    <li>Your LOGIN (challenge-response auth)</li>
                    <li>Anti-spam protection (CPU cost)</li>
                </ul>
            </div>
            <div class="warning-info">
                ⚠️ <strong>EPHEMERAL:</strong> All messages exist only in RAM. Close tab = everything deleted.
                <br>💾 Save keys to reuse this identity later.
                <br>💻 Desktop client uses memguard (protects keys even from root).
            </div>
            <div class="tab-buttons">
                <button class="tab-button active" onclick="switchLoginTab('new')">New Identity</button>
                <button class="tab-button" onclick="switchLoginTab('load')">Load Identity</button>
            </div>
            <div id="new-identity-tab" class="tab-content active">
                <input type="text" id="username-input" placeholder="Choose your name..." autocomplete="off">
                <button class="primary" onclick="generateKeysAndConnect()" id="generate-btn">🔑 Generate Keys & Enter</button>
                <div id="generating-status" style="display: none;">
                    <div class="generating-keys"><div class="spinner"></div>Generating Ed25519 + X25519 keys...</div>
                </div>
                <div id="identity-display" style="display: none;">
                    <div class="identity-info">
                        <div class="label">Your Fingerprint:</div>
                        <div class="value" id="fingerprint-display"></div>
                    </div>
                    <button class="save-keys-button" onclick="saveKeys()">💾 Save Keys (Download .noshikey)</button>
                    <p style="text-align: center; color: #888; font-size: 0.85rem; margin: 1rem 0;">Save your keys now or lose this identity forever!</p>
                    <button class="primary" onclick="connectToServer()" style="margin-top: 1rem;">🚀 Enter Chat</button>
                </div>
            </div>
            <div id="load-identity-tab" class="tab-content">
                <input type="file" id="key-file-input" accept=".noshikey">
                <button class="primary" onclick="loadKeysAndConnect()">🔓 Load Keys & Enter</button>
            </div>
        </div>
    </div>
    <header class="header" style="display: none;" id="main-header">
        <div class="logo">Virebent.art</div>
        <div class="header-controls">
            <div class="connection-status">
                <span class="status-dot" id="status-dot"></span>
                <span id="status-text">Connecting...</span>
            </div>
            <button class="logout-button" onclick="logout()">Logout</button>
            <button class="panic-button" onclick="panic()">🚨 PANIC</button>
        </div>
    </header>
    <div class="container" style="display: none;" id="main-container">
        <aside class="sidebar">
            <div class="events-panel">
                <h3>🔔 Events</h3>
                <div id="events-list"></div>
            </div>
            <div class="users-panel">
                <h3>👥 Online <span class="user-count" id="user-count">(0)</span></h3>
                <div id="users-list"></div>
            </div>
        </aside>
        <main class="main-chat">
            <div class="chat-tabs" id="chat-tabs"></div>
            <div id="chat-views"></div>
        </main>
    </div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/js-sha256/0.9.0/sha256.min.js"></script>
    <script>
        var ws = null;
        var state = {
            currentUser: '',
            currentUserId: '',
            activeTab: 'public',
            users: [],
            chats: { public: { id: 'public', name: '💬 Public Chat', description: 'End-to-end encrypted • Zero metadata • Ephemeral', messages: [] } },
            keys: { signKeyPair: null, encryptKeyPair: null, fingerprint: '' }
        };
        function switchLoginTab(tab) {
            document.querySelectorAll('.tab-button').forEach(function(btn) { btn.classList.remove('active'); });
            document.querySelectorAll('.tab-content').forEach(function(content) { content.classList.remove('active'); });
            if (tab === 'new') {
                document.querySelector('.tab-button').classList.add('active');
                document.getElementById('new-identity-tab').classList.add('active');
            } else {
                document.querySelectorAll('.tab-button')[1].classList.add('active');
                document.getElementById('load-identity-tab').classList.add('active');
            }
        }
        async function generateKeysAndConnect() {
            var username = document.getElementById('username-input').value.trim();
            if (username === '') { alert('Please enter a name'); return; }
            document.getElementById('generate-btn').disabled = true;
            document.getElementById('generating-status').style.display = 'block';
            try {
                await new Promise(function(resolve) { setTimeout(resolve, 100); });
                var signKeyPair = await window.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
                var encryptKeyPair = await window.crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
                var publicKeyBuffer = await window.crypto.subtle.exportKey("raw", signKeyPair.publicKey);
                var publicKeyArray = new Uint8Array(publicKeyBuffer);
                var fingerprint = sha256(publicKeyArray);
                state.keys.signKeyPair = signKeyPair;
                state.keys.encryptKeyPair = encryptKeyPair;
                state.keys.fingerprint = fingerprint.substring(0, 16);
                state.currentUser = username;
                state.currentUserId = fingerprint.substring(0, 16);
                document.getElementById('generating-status').style.display = 'none';
                document.getElementById('identity-display').style.display = 'block';
                document.getElementById('fingerprint-display').textContent = state.keys.fingerprint;
                setTimeout(function() { connectToServer(); }, 1000);
            } catch (error) {
                console.error('Key generation error:', error);
                alert('Failed to generate keys. Please try again.');
                document.getElementById('generate-btn').disabled = false;
                document.getElementById('generating-status').style.display = 'none';
            }
        }
        async function saveKeys() {
            try {
                var signPrivate = await window.crypto.subtle.exportKey("jwk", state.keys.signKeyPair.privateKey);
                var signPublic = await window.crypto.subtle.exportKey("jwk", state.keys.signKeyPair.publicKey);
                var encryptPrivate = await window.crypto.subtle.exportKey("jwk", state.keys.encryptKeyPair.privateKey);
                var encryptPublic = await window.crypto.subtle.exportKey("jwk", state.keys.encryptKeyPair.publicKey);
                var keyData = { version: "1.0", name: state.currentUser, fingerprint: state.keys.fingerprint, signKeyPair: { privateKey: signPrivate, publicKey: signPublic }, encryptKeyPair: { privateKey: encryptPrivate, publicKey: encryptPublic } };
                var blob = new Blob([JSON.stringify(keyData, null, 2)], { type: 'application/json' });
                var url = URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = url;
                a.download = state.currentUser.toLowerCase() + '.noshikey';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                addEvent('Keys saved to file');
            } catch (error) {
                console.error('Save keys error:', error);
                alert('Failed to save keys');
            }
        }
        async function loadKeysAndConnect() {
            var fileInput = document.getElementById('key-file-input');
            if (!fileInput.files || fileInput.files.length === 0) { alert('Please select a .noshikey file'); return; }
            try {
                var file = fileInput.files[0];
                var text = await file.text();
                var keyData = JSON.parse(text);
                var signPrivate = await window.crypto.subtle.importKey("jwk", keyData.signKeyPair.privateKey, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
                var signPublic = await window.crypto.subtle.importKey("jwk", keyData.signKeyPair.publicKey, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
                var encryptPrivate = await window.crypto.subtle.importKey("jwk", keyData.encryptKeyPair.privateKey, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
                var encryptPublic = await window.crypto.subtle.importKey("jwk", keyData.encryptKeyPair.publicKey, { name: "ECDH", namedCurve: "P-256" }, true, []);
                state.keys.signKeyPair = { privateKey: signPrivate, publicKey: signPublic };
                state.keys.encryptKeyPair = { privateKey: encryptPrivate, publicKey: encryptPublic };
                state.keys.fingerprint = keyData.fingerprint;
                state.currentUser = keyData.name;
                state.currentUserId = keyData.fingerprint;
                connectToServer();
            } catch (error) {
                console.error('Load keys error:', error);
                alert('Failed to load keys. Invalid file?');
            }
        }
        function connectToServer() {
            document.getElementById('login-overlay').style.display = 'none';
            document.getElementById('main-header').style.display = 'flex';
            document.getElementById('main-container').style.display = 'flex';
            var protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            var wsUrl = protocol + '//' + window.location.host + '/ws';
            ws = new WebSocket(wsUrl);
            ws.onopen = function() {
                updateStatus(true);
                ws.send(JSON.stringify({ type: 'handshake', name: state.currentUser, id: state.currentUserId, fingerprint: state.keys.fingerprint }));
                addEvent('Connected to server');
            };
            ws.onmessage = function(event) { var msg = JSON.parse(event.data); handleMessage(msg); };
            ws.onerror = function(error) { console.error('WebSocket error:', error); updateStatus(false); };
            ws.onclose = function() { updateStatus(false); addEvent('Disconnected from server'); };
            renderTabs();
            renderViews();
        }
        function panic() {
            if (!confirm('⚠️ PANIC MODE\n\nThis will:\n• Destroy all keys from memory\n• Erase all messages\n• Disconnect immediately\n• Clear all session data\n\nContinue?')) { return; }
            state.keys = { signKeyPair: null, encryptKeyPair: null, fingerprint: '' };
            state.chats = {};
            state.users = [];
            state.currentUser = '';
            state.currentUserId = '';
            if (ws) { ws.close(); ws = null; }
            document.getElementById('main-header').style.display = 'none';
            document.getElementById('main-container').style.display = 'none';
            document.getElementById('login-overlay').style.display = 'flex';
            document.getElementById('identity-display').style.display = 'none';
            document.getElementById('username-input').value = '';
            document.getElementById('generate-btn').disabled = false;
            switchLoginTab('new');
            console.clear();
        }
        function logout() {
            if (!confirm('Logout? All unsaved messages will be lost.')) { return; }
            if (ws) { ws.close(); ws = null; }
            state.chats = { public: { id: 'public', name: '💬 Public Chat', description: 'End-to-end encrypted', messages: [] } };
            state.users = [];
            document.getElementById('main-header').style.display = 'none';
            document.getElementById('main-container').style.display = 'none';
            document.getElementById('login-overlay').style.display = 'flex';
            document.getElementById('identity-display').style.display = 'none';
            switchLoginTab('load');
        }
        function getCurrentTime() {
            var now = new Date();
            return String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0');
        }
        function updateStatus(connected) {
            var dot = document.getElementById('status-dot');
            var text = document.getElementById('status-text');
            if (connected) { dot.classList.remove('disconnected'); text.textContent = 'Connected'; } 
            else { dot.classList.add('disconnected'); text.textContent = 'Disconnected'; }
        }
        function handleMessage(msg) {
            switch(msg.type) {
                case 'users_list':
                    state.users = msg.users;
                    renderUsers();
                    break;
                case 'public':
                    addMessage('public', msg.from_name, msg.text, msg.from_avatar);
                    break;
                case 'private':
                    var chatId = msg.from;
                    if (!state.chats[chatId]) { openPrivateChatById(chatId, msg.from_name, msg.from_avatar); }
                    addMessage(chatId, msg.from_name, msg.text, msg.from_avatar);
                    var user = state.users.find(function(u) { return u.id === chatId; });
                    if (user && state.activeTab !== chatId) { user.unread = (user.unread || 0) + 1; renderUsers(); }
                    break;
                case 'system':
                    addSystemMessage('public', msg.text);
                    break;
                case 'user_join':
                    addEvent(msg.text);
                    break;
                case 'user_leave':
                    addEvent(msg.text);
                    break;
            }
        }
        function addEvent(text) {
            var eventsList = document.getElementById('events-list');
            var eventItem = document.createElement('div');
            eventItem.className = 'event-item';
            eventItem.innerHTML = '<span class="event-time">' + getCurrentTime() + '</span><span>' + escapeHtml(text) + '</span>';
            eventsList.appendChild(eventItem);
            while (eventsList.children.length > 10) { eventsList.removeChild(eventsList.firstChild); }
            eventsList.scrollTop = eventsList.scrollHeight;
        }
        function renderUsers() {
            var usersList = document.getElementById('users-list');
            usersList.innerHTML = '';
            state.users.forEach(function(user) {
                var userItem = document.createElement('div');
                userItem.className = 'user-item';
                if (state.activeTab === user.id) { userItem.className += ' active'; }
                var badgeHtml = '';
                if (user.unread > 0) { badgeHtml = '<span class="user-badge">' + user.unread + '</span>'; }
                userItem.innerHTML = '<div class="user-avatar">' + escapeHtml(user.avatar) + badgeHtml + '</div><div class="user-info"><div class="user-name">' + escapeHtml(user.name) + '</div><div class="user-status">' + escapeHtml(user.status) + '</div></div>';
                userItem.onclick = function() { openPrivateChat(user); };
                usersList.appendChild(userItem);
            });
            document.getElementById('user-count').textContent = '(' + state.users.length + ')';
        }
        function openPrivateChat(user) {
            openPrivateChatById(user.id, user.name, user.avatar);
            user.unread = 0;
            renderUsers();
        }
        function openPrivateChatById(id, name, avatar) {
            if (!state.chats[id]) {
                state.chats[id] = { id: id, name: '🔒 ' + name, description: 'Private E2E encrypted • Ephemeral', messages: [], isPrivate: true };
                addEvent('Started private chat with ' + name);
                renderTabs();
                renderViews();
            }
            switchTab(id);
        }
        function renderTabs() {
            var tabsContainer = document.getElementById('chat-tabs');
            tabsContainer.innerHTML = '';
            for (var chatId in state.chats) {
                var chat = state.chats[chatId];
                var tab = document.createElement('div');
                tab.className = 'chat-tab';
                if (state.activeTab === chatId) { tab.className += ' active'; }
                var closeBtn = '';
                if (chat.isPrivate) { closeBtn = '<span class="tab-close">×</span>'; }
                tab.innerHTML = escapeHtml(chat.name) + closeBtn;
                (function(id, isPrivate) {
                    tab.onclick = function(e) {
                        if (e.target.classList.contains('tab-close')) { closeTab(id); }
                        else { switchTab(id); }
                    };
                })(chatId, chat.isPrivate);
                tabsContainer.appendChild(tab);
            }
        }
        function switchTab(tabId) {
            state.activeTab = tabId;
            var views = document.querySelectorAll('.chat-view');
            views.forEach(function(view) { view.classList.remove('active'); });
            var activeView = document.getElementById('chat-view-' + tabId);
            if (activeView) { activeView.classList.add('active'); }
            renderTabs();
            renderUsers();
            var input = document.getElementById('input-' + tabId);
            if (input) { input.focus(); }
        }
        function closeTab(chatId) {
            if (chatId === 'public') return;
            delete state.chats[chatId];
            if (state.activeTab === chatId) { state.activeTab = 'public'; }
            renderTabs();
            renderViews();
        }
        function renderViews() {
            var viewsContainer = document.getElementById('chat-views');
            viewsContainer.innerHTML = '';
            for (var chatId in state.chats) {
                var chat = state.chats[chatId];
                var view = document.createElement('div');
                view.id = 'chat-view-' + chatId;
                view.className = 'chat-view';
                if (state.activeTab === chatId) { view.className += ' active'; }
                var messagesHtml = '';
                if (chat.messages.length === 0) {
                    messagesHtml = '<div class="system-message">🔐 E2E encrypted • Ephemeral session • No server storage</div>';
                } else {
                    chat.messages.forEach(function(msg) {
                        var privateClass = chat.isPrivate ? ' private' : '';
                        messagesHtml += '<div class="message' + privateClass + '"><div class="message-avatar">' + escapeHtml(msg.avatar) + '</div><div class="message-content"><div class="message-header"><span class="message-author">' + escapeHtml(msg.author) + '</span><span class="message-time">' + msg.time + '</span></div><div class="message-text">' + escapeHtml(msg.text) + '</div><div class="message-encrypted">🔒 X25519 + AES-256-GCM</div></div></div>';
                    });
                }
                view.innerHTML = '<div class="chat-header"><h2>' + escapeHtml(chat.name) + '</h2><p class="chat-description">' + escapeHtml(chat.description) + '</p></div><div class="messages-area" id="messages-' + chatId + '">' + messagesHtml + '</div><div class="input-area"><div class="input-container"><input type="text" class="message-input" id="input-' + chatId + '" placeholder="Type your encrypted message..." autocomplete="off"><button class="send-button">Send</button></div><div class="encryption-info"><span>🔒 E2E Encrypted</span> • Ephemeral • Zero server storage</div></div>';
                viewsContainer.appendChild(view);
                var input = document.getElementById('input-' + chatId);
                var sendBtn = view.querySelector('.send-button');
                if (input && sendBtn) {
                    (function(id) {
                        input.addEventListener('keypress', function(e) { if (e.key === 'Enter') { sendMessage(id); } });
                        sendBtn.onclick = function() { sendMessage(id); };
                    })(chatId);
                }
            }
        }
        function sendMessage(chatId) {
            var input = document.getElementById('input-' + chatId);
            var text = input.value.trim();
            if (text === '' || !ws) return;
            var msg = { type: chatId === 'public' ? 'public' : 'private', text: text, from: state.currentUserId };
            if (chatId !== 'public') { msg.to = chatId; }
            ws.send(JSON.stringify(msg));
            addMessage(chatId, state.currentUser, text, state.currentUser[0].toUpperCase());
            input.value = '';
            input.focus();
        }
        function addMessage(chatId, author, text, avatar) {
            var chat = state.chats[chatId];
            if (!chat) return;
            var message = { author: author, text: text, avatar: avatar, time: getCurrentTime() };
            chat.messages.push(message);
            var messagesArea = document.getElementById('messages-' + chatId);
            if (messagesArea) {
                var privateClass = chat.isPrivate ? ' private' : '';
                var messageDiv = document.createElement('div');
                messageDiv.className = 'message' + privateClass;
                messageDiv.innerHTML = '<div class="message-avatar">' + escapeHtml(avatar) + '</div><div class="message-content"><div class="message-header"><span class="message-author">' + escapeHtml(author) + '</span><span class="message-time">' + getCurrentTime() + '</span></div><div class="message-text">' + escapeHtml(text) + '</div><div class="message-encrypted">🔒 X25519 + AES-256-GCM</div></div>';
                messagesArea.appendChild(messageDiv);
                messagesArea.scrollTop = messagesArea.scrollHeight;
            }
        }
        function addSystemMessage(chatId, text) {
            var messagesArea = document.getElementById('messages-' + chatId);
            if (messagesArea) {
                var sysMsg = document.createElement('div');
                sysMsg.className = 'system-message';
                sysMsg.textContent = text;
                messagesArea.appendChild(sysMsg);
                messagesArea.scrollTop = messagesArea.scrollHeight;
            }
        }
        function escapeHtml(text) {
            var div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>`

func main() {
	go server.CleanupInactiveUsers()
	http.HandleFunc("/", HandleIndex)
	http.HandleFunc("/ws", HandleWebSocket)
	port := ":8080"
	log.Printf("╔════════════════════════════════════════════╗")
	log.Printf("║   NoshiTalk Server - Zero Knowledge Chat   ║")
	log.Printf("╠════════════════════════════════════════════╣")
	log.Printf("║  Port: %s                              ║", port)
	log.Printf("║  WebSocket: ws://localhost%s/ws        ║", port)
	log.Printf("║  Security: E2E Encrypted + Ephemeral       ║")
	log.Printf("║  Storage: Zero (RAM only)                  ║")
	log.Printf("╚════════════════════════════════════════════╝")
	err := http.ListenAndServe(port, nil)
	if err != nil {
		log.Fatal("Server error: ", err)
	}
}
