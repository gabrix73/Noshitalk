package crypto

import (
	"bytes"
	"crypto/cipher"
	"net"
	"testing"
	"time"
)

func TestPadMessage(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		wantSize int // Expected padded size (2 + paddedLen)
	}{
		{"empty", []byte{}, 2 + MessageBlockSize},
		{"small", []byte("hello"), 2 + MessageBlockSize},
		{"exact block minus header", make([]byte, MessageBlockSize-2), 2 + MessageBlockSize},
		{"one block", make([]byte, MessageBlockSize), 2 + MessageBlockSize*2},
		{"large", make([]byte, MessageBlockSize*2+50), 2 + MessageBlockSize*3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padded, err := PadMessage(tt.input)
			if err != nil {
				t.Fatalf("PadMessage() error = %v", err)
			}

			if len(padded) != tt.wantSize {
				t.Errorf("PadMessage() size = %d, want %d", len(padded), tt.wantSize)
			}

			// Verify we can unpad correctly
			unpadded, err := UnpadMessage(padded)
			if err != nil {
				t.Fatalf("UnpadMessage() error = %v", err)
			}

			if !bytes.Equal(unpadded, tt.input) {
				t.Errorf("UnpadMessage() = %v, want %v", unpadded, tt.input)
			}
		})
	}
}

func TestUnpadMessage_Errors(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{"nil", nil, true},
		{"empty", []byte{}, true},
		{"too short", []byte{0x00}, true},
		{"invalid length", []byte{0xFF, 0xFF, 0x00}, true}, // Claims 65535 bytes but only has 1
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnpadMessage(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnpadMessage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPadUnpadRoundTrip(t *testing.T) {
	messages := []string{
		"",
		"Hello, World!",
		"This is a longer message that spans multiple words",
		string(make([]byte, 1000)), // Large message
	}

	for _, msg := range messages {
		padded, err := PadMessage([]byte(msg))
		if err != nil {
			t.Fatalf("PadMessage(%q) error = %v", msg, err)
		}

		unpadded, err := UnpadMessage(padded)
		if err != nil {
			t.Fatalf("UnpadMessage() error = %v", err)
		}

		if string(unpadded) != msg {
			t.Errorf("Round trip failed: got %q, want %q", string(unpadded), msg)
		}
	}
}

func TestDeriveIdentity(t *testing.T) {
	pubKey := []byte("test-public-key-32-bytes-long!!!")

	identity := DeriveIdentity(pubKey)

	// Should start with "anon_"
	if len(identity) < 5 || identity[:5] != "anon_" {
		t.Errorf("DeriveIdentity() = %q, should start with 'anon_'", identity)
	}

	// Should be deterministic
	identity2 := DeriveIdentity(pubKey)
	if identity != identity2 {
		t.Errorf("DeriveIdentity() not deterministic: %q != %q", identity, identity2)
	}

	// Different input should produce different output
	identity3 := DeriveIdentity([]byte("different-key-32-bytes-long!!!!"))
	if identity == identity3 {
		t.Error("DeriveIdentity() should produce different output for different input")
	}
}

func TestDeriveFingerprint(t *testing.T) {
	pubKey := []byte("test-public-key-32-bytes-long!!!")

	fp := DeriveFingerprint(pubKey)

	// Should be 32 hex chars (16 bytes)
	if len(fp) != 32 {
		t.Errorf("DeriveFingerprint() length = %d, want 32", len(fp))
	}

	// Should be deterministic
	fp2 := DeriveFingerprint(pubKey)
	if fp != fp2 {
		t.Errorf("DeriveFingerprint() not deterministic: %q != %q", fp, fp2)
	}
}

func TestSetupAESGCM(t *testing.T) {
	// Valid 32-byte key
	validKey := make([]byte, 32)
	for i := range validKey {
		validKey[i] = byte(i)
	}

	gcm, err := SetupAESGCM(validKey)
	if err != nil {
		t.Fatalf("SetupAESGCM() error = %v", err)
	}

	if gcm == nil {
		t.Error("SetupAESGCM() returned nil")
	}

	// Too short key
	_, err = SetupAESGCM([]byte("short"))
	if err == nil {
		t.Error("SetupAESGCM() should fail with short key")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	gcm, err := SetupAESGCM(key)
	if err != nil {
		t.Fatalf("SetupAESGCM() error = %v", err)
	}

	plaintext := []byte("Hello, secure world!")

	// Encrypt
	ciphertext, err := Encrypt(gcm, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Ciphertext should be different from plaintext
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("Encrypt() ciphertext equals plaintext")
	}

	// Should include nonce (12 bytes) + ciphertext + tag
	if len(ciphertext) < NonceSize+len(plaintext) {
		t.Errorf("Encrypt() ciphertext too short: %d", len(ciphertext))
	}

	// Decrypt
	decrypted, err := Decrypt(gcm, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypt() = %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestEncryptDecrypt_DifferentNonces(t *testing.T) {
	key := make([]byte, 32)
	gcm, _ := SetupAESGCM(key)

	plaintext := []byte("Same message")

	// Encrypt twice
	ct1, _ := Encrypt(gcm, plaintext)
	ct2, _ := Encrypt(gcm, plaintext)

	// Ciphertexts should be different (different nonces)
	if bytes.Equal(ct1, ct2) {
		t.Error("Encrypt() should produce different ciphertext each time (different nonces)")
	}

	// But both should decrypt to same plaintext
	pt1, _ := Decrypt(gcm, ct1)
	pt2, _ := Decrypt(gcm, ct2)

	if !bytes.Equal(pt1, pt2) {
		t.Error("Both ciphertexts should decrypt to same plaintext")
	}
}

func TestDecrypt_Errors(t *testing.T) {
	key := make([]byte, 32)
	gcm, _ := SetupAESGCM(key)

	tests := []struct {
		name  string
		input []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"too short", []byte("short")},
		{"invalid ciphertext", make([]byte, 50)}, // Random bytes won't decrypt
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decrypt(gcm, tt.input)
			if err == nil {
				t.Error("Decrypt() should fail")
			}
		})
	}
}

func TestEncryptDecryptMessage(t *testing.T) {
	key := make([]byte, 32)
	gcm, _ := SetupAESGCM(key)

	message := "Hello, this is a test message!"

	// Encrypt (note: this includes random delay, may be slow)
	encrypted, err := EncryptMessage(gcm, message)
	if err != nil {
		t.Fatalf("EncryptMessage() error = %v", err)
	}

	// Decrypt
	decrypted, err := DecryptMessage(gcm, encrypted)
	if err != nil {
		t.Fatalf("DecryptMessage() error = %v", err)
	}

	if decrypted != message {
		t.Errorf("DecryptMessage() = %q, want %q", decrypted, message)
	}
}

func TestGenerateX25519KeyPair(t *testing.T) {
	key1, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair() error = %v", err)
	}

	if key1 == nil {
		t.Fatal("GenerateX25519KeyPair() returned nil")
	}

	// Public key should be 32 bytes
	pubKey := key1.PublicKey().Bytes()
	if len(pubKey) != 32 {
		t.Errorf("Public key length = %d, want 32", len(pubKey))
	}

	// Generate another - should be different
	key2, _ := GenerateX25519KeyPair()
	if bytes.Equal(key1.PublicKey().Bytes(), key2.PublicKey().Bytes()) {
		t.Error("Two generated keys should be different")
	}
}

func TestPerformECDH(t *testing.T) {
	// Generate two key pairs
	aliceKey, _ := GenerateX25519KeyPair()
	bobKey, _ := GenerateX25519KeyPair()

	// Alice computes shared secret with Bob's public key
	aliceShared, err := PerformECDH(aliceKey, bobKey.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("PerformECDH(alice) error = %v", err)
	}

	// Bob computes shared secret with Alice's public key
	bobShared, err := PerformECDH(bobKey, aliceKey.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("PerformECDH(bob) error = %v", err)
	}

	// Both should arrive at the same shared secret
	if !bytes.Equal(aliceShared, bobShared) {
		t.Error("ECDH shared secrets don't match")
	}

	// Shared secret should be 32 bytes
	if len(aliceShared) != 32 {
		t.Errorf("Shared secret length = %d, want 32", len(aliceShared))
	}
}

func TestPerformECDH_InvalidKey(t *testing.T) {
	aliceKey, _ := GenerateX25519KeyPair()

	// Invalid public key (wrong size)
	_, err := PerformECDH(aliceKey, []byte("too short"))
	if err == nil {
		t.Error("PerformECDH() should fail with invalid public key")
	}
}

func TestSecureBuffer(t *testing.T) {
	secret := []byte("super-secret-data-here!")

	enclave := SecureBuffer(secret)
	if enclave == nil {
		t.Fatal("SecureBuffer() returned nil")
	}

	// Original data should be zeroed (memguard behavior)
	// We can't easily test this without accessing memguard internals
}

// Mock connection for auth tests
type mockConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
}

func newMockConnPair() (*mockConn, *mockConn) {
	buf1 := &bytes.Buffer{}
	buf2 := &bytes.Buffer{}
	return &mockConn{readBuf: buf1, writeBuf: buf2},
		&mockConn{readBuf: buf2, writeBuf: buf1}
}

func (m *mockConn) Read(b []byte) (n int, err error)   { return m.readBuf.Read(b) }
func (m *mockConn) Write(b []byte) (n int, err error)  { return m.writeBuf.Write(b) }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestMutualAuth(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	// Create connected mock pair
	serverConn, clientConn := newMockConnPair()

	// Run server auth in goroutine
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- PerformServerAuth(serverConn, sharedSecret)
	}()

	// Small delay to ensure server sends challenge first
	time.Sleep(10 * time.Millisecond)

	// Run client auth
	err := PerformClientAuth(clientConn, sharedSecret)
	if err != nil {
		t.Fatalf("PerformClientAuth() error = %v", err)
	}

	// Check server result
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("PerformServerAuth() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Server auth timed out")
	}
}

func TestRandomDelay(t *testing.T) {
	start := time.Now()
	err := RandomDelay()
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("RandomDelay() error = %v", err)
	}

	// Should be at least MinRandomDelay
	if elapsed < time.Duration(MinRandomDelay)*time.Millisecond {
		t.Errorf("RandomDelay() too fast: %v", elapsed)
	}

	// Should be at most MaxRandomDelay (with some buffer)
	if elapsed > time.Duration(MaxRandomDelay+50)*time.Millisecond {
		t.Errorf("RandomDelay() too slow: %v", elapsed)
	}
}

// Benchmark tests
func BenchmarkPadMessage(b *testing.B) {
	msg := []byte("This is a test message for benchmarking")
	for i := 0; i < b.N; i++ {
		PadMessage(msg)
	}
}

func BenchmarkEncryptDecrypt(b *testing.B) {
	key := make([]byte, 32)
	gcm, _ := SetupAESGCM(key)
	plaintext := []byte("Benchmark message for encryption testing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct, _ := Encrypt(gcm, plaintext)
		Decrypt(gcm, ct)
	}
}

// Helper to satisfy cipher.AEAD interface check
var _ cipher.AEAD = (cipher.AEAD)(nil)
