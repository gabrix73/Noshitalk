// Package crypto provides shared cryptographic functions for NoshiTalk.
// Includes message padding, AES-GCM encryption/decryption, and traffic obfuscation.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/awnumar/memguard"
)

const (
	// MessageBlockSize is the padding block size for traffic analysis resistance
	MessageBlockSize = 256

	// MinRandomDelay is the minimum delay in milliseconds for timing attack mitigation
	MinRandomDelay = 50

	// MaxRandomDelay is the maximum delay in milliseconds for timing attack mitigation
	MaxRandomDelay = 200

	// NonceSize is the size of the GCM nonce
	NonceSize = 12

	// KeySize is the size of the AES-256 key
	KeySize = 32

	// ChallengeSize is the size of HMAC challenge/response
	ChallengeSize = 32

	// HandshakeTimeout is the timeout for key exchange and authentication
	HandshakeTimeout = 30 * time.Second
)

// PadMessage pads a plaintext message to fixed block size to prevent traffic analysis.
// Format: [2 bytes length][plaintext][random padding]
func PadMessage(plaintext []byte) ([]byte, error) {
	currentLen := len(plaintext)
	paddedLen := ((currentLen / MessageBlockSize) + 1) * MessageBlockSize
	padLen := paddedLen - currentLen

	result := make([]byte, 2+paddedLen)
	binary.BigEndian.PutUint16(result[0:2], uint16(currentLen))
	copy(result[2:], plaintext)

	if padLen > 0 {
		padding := make([]byte, padLen)
		if _, err := cryptorand.Read(padding); err != nil {
			return nil, fmt.Errorf("failed to generate random padding: %w", err)
		}
		copy(result[2+currentLen:], padding)
	}

	return result, nil
}

// UnpadMessage removes padding from a padded message.
func UnpadMessage(paddedData []byte) ([]byte, error) {
	if len(paddedData) < 2 {
		return nil, fmt.Errorf("padded data too short")
	}

	originalLen := binary.BigEndian.Uint16(paddedData[0:2])
	if int(originalLen) > len(paddedData)-2 {
		return nil, fmt.Errorf("invalid padding length")
	}

	return paddedData[2 : 2+originalLen], nil
}

// RandomDelay introduces a random delay for timing attack mitigation.
// Uses crypto/rand for secure randomness.
func RandomDelay() error {
	var b [1]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		return err
	}
	// Map byte value to delay range
	delay := MinRandomDelay + int(b[0])%(MaxRandomDelay-MinRandomDelay)
	time.Sleep(time.Duration(delay) * time.Millisecond)
	return nil
}

// DeriveIdentity derives a user identity string from a public key.
// Format: "anon_" + first 8 bytes of SHA256(publicKey) in hex
func DeriveIdentity(publicKey []byte) string {
	hash := sha256.Sum256(publicKey)
	return fmt.Sprintf("anon_%s", hex.EncodeToString(hash[:8]))
}

// DeriveFingerprint derives a fingerprint from a public key.
// Returns first 16 bytes of SHA256 hash in hex.
func DeriveFingerprint(publicKey []byte) string {
	hash := sha256.Sum256(publicKey)
	return hex.EncodeToString(hash[:16])
}

// SetupAESGCM creates an AES-GCM cipher from a shared secret.
func SetupAESGCM(sharedSecret []byte) (cipher.AEAD, error) {
	if len(sharedSecret) < KeySize {
		return nil, fmt.Errorf("shared secret too short: need %d bytes, got %d", KeySize, len(sharedSecret))
	}

	block, err := aes.NewCipher(sharedSecret[:KeySize])
	if err != nil {
		return nil, fmt.Errorf("AES cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}

	return gcm, nil
}

// Encrypt encrypts a message using AES-GCM with random nonce.
// Returns: [12-byte nonce][ciphertext]
func Encrypt(gcm cipher.AEAD, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(cryptorand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// Decrypt decrypts a message encrypted with Encrypt.
// Expects: [12-byte nonce][ciphertext]
func Decrypt(gcm cipher.AEAD, data []byte) ([]byte, error) {
	if len(data) < NonceSize {
		return nil, fmt.Errorf("data too short")
	}

	nonce := data[:NonceSize]
	ciphertext := data[NonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// EncryptMessage encrypts a string message with padding and traffic obfuscation.
func EncryptMessage(gcm cipher.AEAD, message string) ([]byte, error) {
	// Apply random delay for timing attack mitigation
	if err := RandomDelay(); err != nil {
		return nil, err
	}

	// Pad the message
	padded, err := PadMessage([]byte(message))
	if err != nil {
		return nil, err
	}

	// Encrypt
	return Encrypt(gcm, padded)
}

// DecryptMessage decrypts and unpads an encrypted message.
func DecryptMessage(gcm cipher.AEAD, data []byte) (string, error) {
	// Decrypt
	padded, err := Decrypt(gcm, data)
	if err != nil {
		return "", err
	}

	// Unpad
	plaintext, err := UnpadMessage(padded)
	if err != nil {
		return "", fmt.Errorf("unpad failed: %w", err)
	}

	return string(plaintext), nil
}

// GenerateX25519KeyPair generates a new X25519 key pair for ECDH.
func GenerateX25519KeyPair() (*ecdh.PrivateKey, error) {
	curve := ecdh.X25519()
	return curve.GenerateKey(cryptorand.Reader)
}

// PerformECDH performs ECDH key exchange with a peer's public key.
func PerformECDH(privateKey *ecdh.PrivateKey, peerPublicKeyBytes []byte) ([]byte, error) {
	curve := ecdh.X25519()
	peerPublicKey, err := curve.NewPublicKey(peerPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid peer public key: %w", err)
	}

	sharedSecret, err := privateKey.ECDH(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	return sharedSecret, nil
}

// SecureBuffer wraps sensitive data in memguard for protection.
func SecureBuffer(data []byte) *memguard.Enclave {
	buf := memguard.NewBufferFromBytes(data)
	enclave := buf.Seal()
	return enclave
}

// PerformClientAuth performs client-side mutual authentication.
// Protocol:
// 1. Receive server challenge (32 bytes)
// 2. Compute HMAC response
// 3. Generate client challenge
// 4. Send response + challenge
// 5. Verify server response
func PerformClientAuth(conn net.Conn, sharedSecret []byte) error {
	conn.SetDeadline(time.Now().Add(HandshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	// Receive server challenge
	serverChallenge := make([]byte, ChallengeSize)
	if _, err := io.ReadFull(conn, serverChallenge); err != nil {
		return fmt.Errorf("receive server challenge failed: %w", err)
	}

	// Compute HMAC response
	h := hmac.New(sha256.New, sharedSecret)
	h.Write(serverChallenge)
	clientResponse := h.Sum(nil)

	// Generate client challenge
	clientChallenge := make([]byte, ChallengeSize)
	if _, err := cryptorand.Read(clientChallenge); err != nil {
		return fmt.Errorf("challenge generation failed: %w", err)
	}

	// Send response + challenge
	if _, err := conn.Write(clientResponse); err != nil {
		return fmt.Errorf("send client response failed: %w", err)
	}
	if _, err := conn.Write(clientChallenge); err != nil {
		return fmt.Errorf("send client challenge failed: %w", err)
	}

	// Receive and verify server response
	serverResponse := make([]byte, ChallengeSize)
	if _, err := io.ReadFull(conn, serverResponse); err != nil {
		return fmt.Errorf("receive server response failed: %w", err)
	}

	h.Reset()
	h.Write(clientChallenge)
	expectedServerMAC := h.Sum(nil)

	if !hmac.Equal(serverResponse, expectedServerMAC) {
		return fmt.Errorf("server authentication failed - HMAC mismatch")
	}

	return nil
}

// PerformServerAuth performs server-side mutual authentication.
func PerformServerAuth(conn net.Conn, sharedSecret []byte) error {
	conn.SetDeadline(time.Now().Add(HandshakeTimeout))
	defer conn.SetDeadline(time.Time{})

	// Generate and send server challenge
	serverChallenge := make([]byte, ChallengeSize)
	if _, err := cryptorand.Read(serverChallenge); err != nil {
		return fmt.Errorf("challenge generation failed: %w", err)
	}

	if _, err := conn.Write(serverChallenge); err != nil {
		return fmt.Errorf("challenge send failed: %w", err)
	}

	// Receive client response
	clientResponse := make([]byte, ChallengeSize)
	if _, err := io.ReadFull(conn, clientResponse); err != nil {
		return fmt.Errorf("client response read failed: %w", err)
	}

	// Receive client challenge
	clientChallenge := make([]byte, ChallengeSize)
	if _, err := io.ReadFull(conn, clientChallenge); err != nil {
		return fmt.Errorf("client challenge read failed: %w", err)
	}

	// Verify client response
	h := hmac.New(sha256.New, sharedSecret)
	h.Write(serverChallenge)
	expectedClientMAC := h.Sum(nil)

	if !hmac.Equal(clientResponse, expectedClientMAC) {
		return fmt.Errorf("client authentication failed")
	}

	// Send server response
	h.Reset()
	h.Write(clientChallenge)
	serverResponse := h.Sum(nil)

	if _, err := conn.Write(serverResponse); err != nil {
		return fmt.Errorf("server response send failed: %w", err)
	}

	return nil
}
