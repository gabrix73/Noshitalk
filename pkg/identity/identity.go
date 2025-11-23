// Package identity provides persistent cryptographic identity management for NoshiTalk.
package identity

import (
	"crypto/ecdh"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"noshitalk/pkg/crypto"
)

const (
	// DefaultKeyDir is the default directory for storing keys
	DefaultKeyDir = ".noshitalk"

	// IdentityVersion is the current identity file format version
	IdentityVersion = "1.0"
)

// Identity represents a user's cryptographic identity.
type Identity struct {
	PrivateKey  *ecdh.PrivateKey
	PublicKey   *ecdh.PublicKey
	Username    string
	Fingerprint string
}

// IdentityFile represents the on-disk format for storing identity.
type IdentityFile struct {
	Version        string  `json:"version"`
	Username       string  `json:"username"`
	Fingerprint    string  `json:"fingerprint"`
	SignKeyPair    KeyPair `json:"signKeyPair,omitempty"`
	EncryptKeyPair KeyPair `json:"encryptKeyPair,omitempty"`
	PrivateKey     string  `json:"privateKey,omitempty"` // For simple format
}

// KeyPair represents a public/private key pair in hex encoding.
type KeyPair struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

// GetDefaultKeyPath returns the default path for storing identity keys.
func GetDefaultKeyPath(filename string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(homeDir, DefaultKeyDir, filename), nil
}

// New generates a new random identity.
func New(usernamePrefix string) (*Identity, error) {
	privateKey, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	publicKey := privateKey.PublicKey()
	fingerprint := crypto.DeriveFingerprint(publicKey.Bytes())
	username := fmt.Sprintf("%s_%s", usernamePrefix, fingerprint[:8])

	return &Identity{
		PrivateKey:  privateKey,
		PublicKey:   publicKey,
		Username:    username,
		Fingerprint: fingerprint,
	}, nil
}

// LoadOrCreate loads an existing identity from file or creates a new one.
func LoadOrCreate(keyPath, usernamePrefix string) (*Identity, error) {
	// Try to load existing
	if _, err := os.Stat(keyPath); err == nil {
		return Load(keyPath)
	}

	// Generate new
	identity, err := New(usernamePrefix)
	if err != nil {
		return nil, err
	}

	// Save it
	if err := identity.Save(keyPath); err != nil {
		return nil, fmt.Errorf("failed to save new identity: %w", err)
	}

	return identity, nil
}

// Load loads an identity from a file.
// Supports both simple format (just private key bytes) and JSON format.
func Load(keyPath string) (*Identity, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read identity file: %w", err)
	}

	curve := ecdh.X25519()

	// Try JSON format first
	var idFile IdentityFile
	if err := json.Unmarshal(data, &idFile); err == nil {
		// JSON format - check for different key storage formats
		var privateKeyBytes []byte

		if idFile.EncryptKeyPair.PrivateKey != "" {
			// GUI client format
			privateKeyBytes, err = hex.DecodeString(idFile.EncryptKeyPair.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("failed to decode encrypt private key: %w", err)
			}
		} else if idFile.SignKeyPair.PrivateKey != "" {
			// Alternative format
			privateKeyBytes, err = hex.DecodeString(idFile.SignKeyPair.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("failed to decode sign private key: %w", err)
			}
		} else if idFile.PrivateKey != "" {
			// Simple JSON format
			privateKeyBytes, err = hex.DecodeString(idFile.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("failed to decode private key: %w", err)
			}
		} else {
			return nil, fmt.Errorf("no private key found in identity file")
		}

		privateKey, err := curve.NewPrivateKey(privateKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}

		publicKey := privateKey.PublicKey()
		fingerprint := crypto.DeriveFingerprint(publicKey.Bytes())

		username := idFile.Username
		if username == "" {
			username = crypto.DeriveIdentity(publicKey.Bytes())
		}

		return &Identity{
			PrivateKey:  privateKey,
			PublicKey:   publicKey,
			Username:    username,
			Fingerprint: fingerprint,
		}, nil
	}

	// Try raw binary format (CLI client format)
	if len(data) == 32 {
		privateKey, err := curve.NewPrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse raw private key: %w", err)
		}

		publicKey := privateKey.PublicKey()
		fingerprint := crypto.DeriveFingerprint(publicKey.Bytes())
		username := crypto.DeriveIdentity(publicKey.Bytes())

		return &Identity{
			PrivateKey:  privateKey,
			PublicKey:   publicKey,
			Username:    username,
			Fingerprint: fingerprint,
		}, nil
	}

	return nil, fmt.Errorf("unrecognized identity file format")
}

// Save saves the identity to a file in JSON format.
func (id *Identity) Save(keyPath string) error {
	// Create directory if needed
	dir := filepath.Dir(keyPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	idFile := IdentityFile{
		Version:     IdentityVersion,
		Username:    id.Username,
		Fingerprint: id.Fingerprint,
		EncryptKeyPair: KeyPair{
			PrivateKey: hex.EncodeToString(id.PrivateKey.Bytes()),
			PublicKey:  hex.EncodeToString(id.PublicKey.Bytes()),
		},
	}

	data, err := json.MarshalIndent(idFile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal identity: %w", err)
	}

	if err := os.WriteFile(keyPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write identity file: %w", err)
	}

	return nil
}

// SaveRaw saves only the private key bytes (for CLI client compatibility).
func (id *Identity) SaveRaw(keyPath string) error {
	dir := filepath.Dir(keyPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	if err := os.WriteFile(keyPath, id.PrivateKey.Bytes(), 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// DeriveSharedIdentity derives a deterministic identity from a seed.
// This is useful for testing or when you want reproducible identities.
func DeriveSharedIdentity(seed string, usernamePrefix string) (*Identity, error) {
	// Hash the seed to get 32 bytes
	hash := sha256.Sum256([]byte(seed))

	curve := ecdh.X25519()
	privateKey, err := curve.NewPrivateKey(hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to derive private key: %w", err)
	}

	publicKey := privateKey.PublicKey()
	fingerprint := crypto.DeriveFingerprint(publicKey.Bytes())
	username := fmt.Sprintf("%s_%s", usernamePrefix, fingerprint[:8])

	return &Identity{
		PrivateKey:  privateKey,
		PublicKey:   publicKey,
		Username:    username,
		Fingerprint: fingerprint,
	}, nil
}

// GenerateChallenge generates a random challenge for authentication.
func GenerateChallenge() ([]byte, error) {
	challenge := make([]byte, 32)
	if _, err := cryptorand.Read(challenge); err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}
	return challenge, nil
}
