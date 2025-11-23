package protocol

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewMessage(t *testing.T) {
	msg := NewMessage("alice", "bob", "Hello!", TypePrivate)

	if msg.From != "alice" {
		t.Errorf("From = %q, want 'alice'", msg.From)
	}
	if msg.To != "bob" {
		t.Errorf("To = %q, want 'bob'", msg.To)
	}
	if msg.Content != "Hello!" {
		t.Errorf("Content = %q, want 'Hello!'", msg.Content)
	}
	if msg.Type != TypePrivate {
		t.Errorf("Type = %q, want %q", msg.Type, TypePrivate)
	}
	if msg.Time == "" {
		t.Error("Time should not be empty")
	}
}

func TestNewSystemMessage(t *testing.T) {
	msg := NewSystemMessage("Server restarting")

	if msg.From != "System" {
		t.Errorf("From = %q, want 'System'", msg.From)
	}
	if msg.Content != "Server restarting" {
		t.Errorf("Content = %q, want 'Server restarting'", msg.Content)
	}
	if msg.Type != TypeSystem {
		t.Errorf("Type = %q, want %q", msg.Type, TypeSystem)
	}
}

func TestNewErrorMessage(t *testing.T) {
	msg := NewErrorMessage("Connection failed")

	if msg.From != "System" {
		t.Errorf("From = %q, want 'System'", msg.From)
	}
	if msg.Type != TypeError {
		t.Errorf("Type = %q, want %q", msg.Type, TypeError)
	}
}

func TestNewUserListMessage(t *testing.T) {
	users := []string{"alice", "bob", "charlie"}
	msg := NewUserListMessage(users)

	if msg.Type != TypeUserList {
		t.Errorf("Type = %q, want %q", msg.Type, TypeUserList)
	}
	if len(msg.Users) != 3 {
		t.Errorf("Users count = %d, want 3", len(msg.Users))
	}
	if msg.Time == "" {
		t.Error("Time should not be empty")
	}
}

func TestMessage_ToJSON(t *testing.T) {
	msg := NewMessage("alice", "bob", "Test", TypeMessage)

	data, err := msg.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	// Should be valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}

	if parsed["from"] != "alice" {
		t.Errorf("JSON from = %v, want 'alice'", parsed["from"])
	}
	if parsed["type"] != TypeMessage {
		t.Errorf("JSON type = %v, want %q", parsed["type"], TypeMessage)
	}
}

func TestUserListMessage_ToJSON(t *testing.T) {
	msg := NewUserListMessage([]string{"alice", "bob"})

	data, err := msg.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}

	if parsed["type"] != TypeUserList {
		t.Errorf("JSON type = %v, want %q", parsed["type"], TypeUserList)
	}

	users, ok := parsed["users"].([]interface{})
	if !ok || len(users) != 2 {
		t.Errorf("JSON users incorrect: %v", parsed["users"])
	}
}

func TestFileOfferMessage_ToJSON(t *testing.T) {
	msg := FileOfferMessage{
		Type:        TypeFileOffer,
		From:        "alice",
		To:          "bob",
		FileID:      "abc123",
		Filename:    "test.txt",
		Size:        1024,
		TotalChunks: 4,
		SHA256:      "deadbeef",
		Compressed:  true,
		Time:        time.Now().Format("15:04:05"),
	}

	data, err := msg.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	var parsed FileOfferMessage
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}

	if parsed.FileID != "abc123" {
		t.Errorf("FileID = %q, want 'abc123'", parsed.FileID)
	}
	if parsed.Size != 1024 {
		t.Errorf("Size = %d, want 1024", parsed.Size)
	}
	if !parsed.Compressed {
		t.Error("Compressed should be true")
	}
}

func TestFileChunkMessage_ToJSON(t *testing.T) {
	msg := FileChunkMessage{
		Type:        TypeFileChunk,
		FileID:      "abc123",
		ChunkIndex:  2,
		TotalChunks: 10,
		Data:        "base64encodeddata",
		Time:        time.Now().Format("15:04:05"),
	}

	data, err := msg.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	var parsed FileChunkMessage
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}

	if parsed.ChunkIndex != 2 {
		t.Errorf("ChunkIndex = %d, want 2", parsed.ChunkIndex)
	}
	if parsed.TotalChunks != 10 {
		t.Errorf("TotalChunks = %d, want 10", parsed.TotalChunks)
	}
}

func TestFileResponseMessage_ToJSON(t *testing.T) {
	msg := FileResponseMessage{
		Type:    TypeFileAccept,
		FileID:  "abc123",
		From:    "bob",
		Status:  "accepted",
		Message: "Transfer starting",
		Time:    time.Now().Format("15:04:05"),
	}

	data, err := msg.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	var parsed FileResponseMessage
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}

	if parsed.Status != "accepted" {
		t.Errorf("Status = %q, want 'accepted'", parsed.Status)
	}
}

func TestKeyRotationMessage_ToJSON(t *testing.T) {
	msg := KeyRotationMessage{
		Type:      TypeKeyRotation,
		PublicKey: []byte{1, 2, 3, 4},
		Nonce:     []byte{5, 6, 7, 8},
		Signature: []byte{9, 10, 11, 12},
		Time:      time.Now().Format("15:04:05"),
	}

	data, err := msg.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	var parsed KeyRotationMessage
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}

	if len(parsed.PublicKey) != 4 {
		t.Errorf("PublicKey length = %d, want 4", len(parsed.PublicKey))
	}
}

func TestParseMessage(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantType string
		wantErr  bool
	}{
		{
			name:     "message type",
			input:    `{"type":"message","from":"alice","content":"hi"}`,
			wantType: TypeMessage,
		},
		{
			name:     "private type",
			input:    `{"type":"private","from":"alice","to":"bob"}`,
			wantType: TypePrivate,
		},
		{
			name:     "system type",
			input:    `{"type":"system","content":"welcome"}`,
			wantType: TypeSystem,
		},
		{
			name:     "no type field",
			input:    `{"from":"alice","content":"hi"}`,
			wantType: TypeMessage, // Default
		},
		{
			name:    "invalid json",
			input:   `not json`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgType, data, err := ParseMessage([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMessage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if msgType != tt.wantType {
				t.Errorf("ParseMessage() type = %q, want %q", msgType, tt.wantType)
			}
			if data == nil {
				t.Error("ParseMessage() data should not be nil")
			}
		})
	}
}

func TestParseAsMessage(t *testing.T) {
	input := `{"type":"message","from":"alice","to":"bob","content":"hello","time":"12:34:56"}`

	msg, err := ParseAsMessage([]byte(input))
	if err != nil {
		t.Fatalf("ParseAsMessage() error = %v", err)
	}

	if msg.From != "alice" {
		t.Errorf("From = %q, want 'alice'", msg.From)
	}
	if msg.To != "bob" {
		t.Errorf("To = %q, want 'bob'", msg.To)
	}
	if msg.Content != "hello" {
		t.Errorf("Content = %q, want 'hello'", msg.Content)
	}
}

func TestParseAsUserList(t *testing.T) {
	input := `{"type":"user_list","users":["alice","bob","charlie"],"time":"12:34:56"}`

	msg, err := ParseAsUserList([]byte(input))
	if err != nil {
		t.Fatalf("ParseAsUserList() error = %v", err)
	}

	if msg.Type != TypeUserList {
		t.Errorf("Type = %q, want %q", msg.Type, TypeUserList)
	}
	if len(msg.Users) != 3 {
		t.Errorf("Users count = %d, want 3", len(msg.Users))
	}
}

func TestParseAsFileOffer(t *testing.T) {
	input := `{"type":"file_offer","from":"alice","to":"bob","file_id":"abc","filename":"test.txt","size":100,"total_chunks":1}`

	msg, err := ParseAsFileOffer([]byte(input))
	if err != nil {
		t.Fatalf("ParseAsFileOffer() error = %v", err)
	}

	if msg.FileID != "abc" {
		t.Errorf("FileID = %q, want 'abc'", msg.FileID)
	}
	if msg.Filename != "test.txt" {
		t.Errorf("Filename = %q, want 'test.txt'", msg.Filename)
	}
}

func TestParseAsFileChunk(t *testing.T) {
	input := `{"type":"file_chunk","file_id":"abc","chunk_index":5,"total_chunks":10,"data":"base64"}`

	msg, err := ParseAsFileChunk([]byte(input))
	if err != nil {
		t.Fatalf("ParseAsFileChunk() error = %v", err)
	}

	if msg.ChunkIndex != 5 {
		t.Errorf("ChunkIndex = %d, want 5", msg.ChunkIndex)
	}
}

func TestParseAsFileResponse(t *testing.T) {
	input := `{"type":"file_accept","file_id":"abc","from":"bob","status":"accepted","message":"ok"}`

	msg, err := ParseAsFileResponse([]byte(input))
	if err != nil {
		t.Fatalf("ParseAsFileResponse() error = %v", err)
	}

	if msg.Status != "accepted" {
		t.Errorf("Status = %q, want 'accepted'", msg.Status)
	}
}

func TestParseAs_InvalidJSON(t *testing.T) {
	invalid := []byte("not json")

	_, err := ParseAsMessage(invalid)
	if err == nil {
		t.Error("ParseAsMessage should fail on invalid JSON")
	}

	_, err = ParseAsUserList(invalid)
	if err == nil {
		t.Error("ParseAsUserList should fail on invalid JSON")
	}

	_, err = ParseAsFileOffer(invalid)
	if err == nil {
		t.Error("ParseAsFileOffer should fail on invalid JSON")
	}

	_, err = ParseAsFileChunk(invalid)
	if err == nil {
		t.Error("ParseAsFileChunk should fail on invalid JSON")
	}

	_, err = ParseAsFileResponse(invalid)
	if err == nil {
		t.Error("ParseAsFileResponse should fail on invalid JSON")
	}
}

// Test message type constants
func TestMessageTypeConstants(t *testing.T) {
	types := map[string]string{
		"TypeMessage":      TypeMessage,
		"TypePrivate":      TypePrivate,
		"TypeSystem":       TypeSystem,
		"TypeError":        TypeError,
		"TypeUserList":     TypeUserList,
		"TypeUserJoin":     TypeUserJoin,
		"TypeUserLeave":    TypeUserLeave,
		"TypeHandshake":    TypeHandshake,
		"TypePublic":       TypePublic,
		"TypeKeyRotation":  TypeKeyRotation,
		"TypeFileOffer":    TypeFileOffer,
		"TypeFileChunk":    TypeFileChunk,
		"TypeFileAccept":   TypeFileAccept,
		"TypeFileReject":   TypeFileReject,
		"TypeFileComplete": TypeFileComplete,
	}

	for name, value := range types {
		if value == "" {
			t.Errorf("%s should not be empty", name)
		}
	}
}

// Benchmark
func BenchmarkMessage_ToJSON(b *testing.B) {
	msg := NewMessage("alice", "bob", "Test message content", TypeMessage)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg.ToJSON()
	}
}

func BenchmarkParseMessage(b *testing.B) {
	data := []byte(`{"type":"message","from":"alice","to":"bob","content":"hello","time":"12:34:56"}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseMessage(data)
	}
}
