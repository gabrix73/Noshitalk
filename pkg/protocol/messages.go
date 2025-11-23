// Package protocol defines the message structures and types for NoshiTalk communication.
package protocol

import (
	"encoding/json"
	"time"
)

// Message types
const (
	TypeMessage      = "message"
	TypePrivate      = "private"
	TypeSystem       = "system"
	TypeError        = "error"
	TypeUserList     = "user_list"
	TypeUserJoin     = "user_join"
	TypeUserLeave    = "user_leave"
	TypeHandshake    = "handshake"
	TypePublic       = "public"
	TypeKeyRotation  = "key_rotation"
	TypeFileOffer    = "file_offer"
	TypeFileChunk    = "file_chunk"
	TypeFileAccept   = "file_accept"
	TypeFileReject   = "file_reject"
	TypeFileComplete = "file_complete"
)

// Message represents a chat message.
type Message struct {
	From    string `json:"from"`
	To      string `json:"to,omitempty"`
	Content string `json:"content"`
	Time    string `json:"time"`
	Type    string `json:"type"`
}

// UserListMessage represents a list of online users.
type UserListMessage struct {
	Type  string   `json:"type"`
	Users []string `json:"users"`
	Time  string   `json:"time"`
}

// FileOfferMessage represents a file transfer offer.
type FileOfferMessage struct {
	Type        string `json:"type"`
	From        string `json:"from"`
	To          string `json:"to"`
	FileID      string `json:"file_id"`
	Filename    string `json:"filename"`
	Size        int64  `json:"size"`
	TotalChunks int    `json:"total_chunks"`
	SHA256      string `json:"sha256"`
	Compressed  bool   `json:"compressed"`
	Time        string `json:"time"`
}

// FileChunkMessage represents a chunk of file data.
type FileChunkMessage struct {
	Type        string `json:"type"`
	FileID      string `json:"file_id"`
	ChunkIndex  int    `json:"chunk_index"`
	TotalChunks int    `json:"total_chunks"`
	Data        string `json:"data"`
	Time        string `json:"time"`
}

// FileResponseMessage represents a response to a file transfer.
type FileResponseMessage struct {
	Type    string `json:"type"`
	FileID  string `json:"file_id"`
	From    string `json:"from"`
	Status  string `json:"status"`
	Message string `json:"message"`
	SHA256  string `json:"sha256,omitempty"`
	Time    string `json:"time"`
}

// KeyRotationMessage represents a key rotation request.
type KeyRotationMessage struct {
	Type      string `json:"type"`
	PublicKey []byte `json:"public_key"`
	Nonce     []byte `json:"nonce"`
	Signature []byte `json:"signature"`
	Time      string `json:"time"`
}

// NewMessage creates a new message with the current timestamp.
func NewMessage(from, to, content, msgType string) *Message {
	return &Message{
		From:    from,
		To:      to,
		Content: content,
		Time:    time.Now().Format("15:04:05"),
		Type:    msgType,
	}
}

// NewSystemMessage creates a new system message.
func NewSystemMessage(content string) *Message {
	return NewMessage("System", "", content, TypeSystem)
}

// NewErrorMessage creates a new error message.
func NewErrorMessage(content string) *Message {
	return NewMessage("System", "", content, TypeError)
}

// NewUserListMessage creates a new user list message.
func NewUserListMessage(users []string) *UserListMessage {
	return &UserListMessage{
		Type:  TypeUserList,
		Users: users,
		Time:  time.Now().Format("15:04:05"),
	}
}

// ToJSON marshals the message to JSON.
func (m *Message) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// ToJSON marshals the user list message to JSON.
func (m *UserListMessage) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// ToJSON marshals the file offer message to JSON.
func (m *FileOfferMessage) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// ToJSON marshals the file chunk message to JSON.
func (m *FileChunkMessage) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// ToJSON marshals the file response message to JSON.
func (m *FileResponseMessage) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// ToJSON marshals the key rotation message to JSON.
func (m *KeyRotationMessage) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// ParseMessage parses a JSON message and returns its type and raw data.
func ParseMessage(data []byte) (string, map[string]interface{}, error) {
	var generic map[string]interface{}
	if err := json.Unmarshal(data, &generic); err != nil {
		return "", nil, err
	}

	msgType, ok := generic["type"].(string)
	if !ok {
		msgType = TypeMessage
	}

	return msgType, generic, nil
}

// ParseAsMessage parses JSON data as a Message.
func ParseAsMessage(data []byte) (*Message, error) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// ParseAsUserList parses JSON data as a UserListMessage.
func ParseAsUserList(data []byte) (*UserListMessage, error) {
	var msg UserListMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// ParseAsFileOffer parses JSON data as a FileOfferMessage.
func ParseAsFileOffer(data []byte) (*FileOfferMessage, error) {
	var msg FileOfferMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// ParseAsFileChunk parses JSON data as a FileChunkMessage.
func ParseAsFileChunk(data []byte) (*FileChunkMessage, error) {
	var msg FileChunkMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// ParseAsFileResponse parses JSON data as a FileResponseMessage.
func ParseAsFileResponse(data []byte) (*FileResponseMessage, error) {
	var msg FileResponseMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}
