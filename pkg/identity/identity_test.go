package identity

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetDefaultKeyPath(t *testing.T) {
	path, err := GetDefaultKeyPath("test.key")
	if err != nil {
		t.Fatalf("GetDefaultKeyPath() error = %v", err)
	}

	if !strings.Contains(path, DefaultKeyDir) {
		t.Errorf("Path should contain %q: %s", DefaultKeyDir, path)
	}

	if !strings.HasSuffix(path, "test.key") {
		t.Errorf("Path should end with 'test.key': %s", path)
	}
}

func TestNew(t *testing.T) {
	id, err := New("test")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if id.PrivateKey == nil {
		t.Error("PrivateKey should not be nil")
	}
	if id.PublicKey == nil {
		t.Error("PublicKey should not be nil")
	}
	if !strings.HasPrefix(id.Username, "test_") {
		t.Errorf("Username should start with 'test_': %s", id.Username)
	}
	if len(id.Fingerprint) != 32 {
		t.Errorf("Fingerprint length = %d, want 32", len(id.Fingerprint))
	}
}

func TestNew_DifferentEachTime(t *testing.T) {
	id1, _ := New("test")
	id2, _ := New("test")

	if id1.Fingerprint == id2.Fingerprint {
		t.Error("Two New() calls should produce different identities")
	}
}

func TestIdentity_SaveAndLoad(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "noshitalk-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "test-identity.noshikey")

	// Create and save identity
	original, err := New("test")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = original.Save(keyPath)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("Key file was not created")
	}

	// Load identity
	loaded, err := Load(keyPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Compare
	if loaded.Username != original.Username {
		t.Errorf("Username mismatch: %q != %q", loaded.Username, original.Username)
	}
	if loaded.Fingerprint != original.Fingerprint {
		t.Errorf("Fingerprint mismatch: %q != %q", loaded.Fingerprint, original.Fingerprint)
	}

	// Private keys should be functionally equivalent
	origPubKey := original.PrivateKey.PublicKey().Bytes()
	loadedPubKey := loaded.PrivateKey.PublicKey().Bytes()
	if hex.EncodeToString(origPubKey) != hex.EncodeToString(loadedPubKey) {
		t.Error("Public keys derived from private keys don't match")
	}
}

func TestIdentity_SaveRaw(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "noshitalk-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "raw.key")

	// Create and save identity in raw format
	original, _ := New("test")
	err = original.SaveRaw(keyPath)
	if err != nil {
		t.Fatalf("SaveRaw() error = %v", err)
	}

	// Verify file is 32 bytes (raw private key)
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if len(data) != 32 {
		t.Errorf("Raw key file size = %d, want 32", len(data))
	}

	// Load it back
	loaded, err := Load(keyPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Fingerprints should match
	if loaded.Fingerprint != original.Fingerprint {
		t.Errorf("Fingerprint mismatch after raw save/load")
	}
}

func TestLoad_JSONFormat(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "noshitalk-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a valid JSON identity file manually
	id, _ := New("test")
	idFile := IdentityFile{
		Version:     IdentityVersion,
		Username:    id.Username,
		Fingerprint: id.Fingerprint,
		EncryptKeyPair: KeyPair{
			PrivateKey: hex.EncodeToString(id.PrivateKey.Bytes()),
			PublicKey:  hex.EncodeToString(id.PublicKey.Bytes()),
		},
	}

	data, _ := json.Marshal(idFile)
	keyPath := filepath.Join(tmpDir, "identity.json")
	os.WriteFile(keyPath, data, 0600)

	// Load it
	loaded, err := Load(keyPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if loaded.Username != id.Username {
		t.Errorf("Username mismatch")
	}
}

func TestLoad_SignKeyPairFormat(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "noshitalk-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create JSON with SignKeyPair instead of EncryptKeyPair
	id, _ := New("test")
	idFile := IdentityFile{
		Version:     IdentityVersion,
		Username:    id.Username,
		Fingerprint: id.Fingerprint,
		SignKeyPair: KeyPair{
			PrivateKey: hex.EncodeToString(id.PrivateKey.Bytes()),
			PublicKey:  hex.EncodeToString(id.PublicKey.Bytes()),
		},
	}

	data, _ := json.Marshal(idFile)
	keyPath := filepath.Join(tmpDir, "sign-format.json")
	os.WriteFile(keyPath, data, 0600)

	// Should still load
	loaded, err := Load(keyPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if loaded.Fingerprint != id.Fingerprint {
		t.Errorf("Fingerprint mismatch")
	}
}

func TestLoad_Errors(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "noshitalk-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name    string
		content []byte
		wantErr bool
	}{
		{
			name:    "nonexistent file",
			content: nil, // Don't create file
			wantErr: true,
		},
		{
			name:    "invalid json",
			content: []byte("not json at all"),
			wantErr: true,
		},
		{
			name:    "empty json",
			content: []byte("{}"),
			wantErr: true, // No private key
		},
		{
			name:    "invalid hex in private key",
			content: []byte(`{"encryptKeyPair":{"privateKey":"not-hex"}}`),
			wantErr: true,
		},
		{
			name:    "wrong size raw key",
			content: make([]byte, 16), // Should be 32
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPath := filepath.Join(tmpDir, tt.name+".key")

			if tt.content != nil {
				os.WriteFile(keyPath, tt.content, 0600)
			}

			_, err := Load(keyPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("Load() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadOrCreate_ExistingFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "noshitalk-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "identity.noshikey")

	// Create identity first
	original, _ := New("test")
	original.Save(keyPath)

	// LoadOrCreate should load existing
	loaded, err := LoadOrCreate(keyPath, "test")
	if err != nil {
		t.Fatalf("LoadOrCreate() error = %v", err)
	}

	if loaded.Fingerprint != original.Fingerprint {
		t.Error("LoadOrCreate should load existing file, not create new")
	}
}

func TestLoadOrCreate_NewFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "noshitalk-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "new-identity.noshikey")

	// File doesn't exist - should create
	created, err := LoadOrCreate(keyPath, "new")
	if err != nil {
		t.Fatalf("LoadOrCreate() error = %v", err)
	}

	if created == nil {
		t.Fatal("LoadOrCreate() returned nil identity")
	}

	// File should now exist
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("LoadOrCreate should create file if not exists")
	}

	// Loading again should get same identity
	loaded, _ := Load(keyPath)
	if loaded.Fingerprint != created.Fingerprint {
		t.Error("Saved and loaded fingerprints don't match")
	}
}

func TestDeriveSharedIdentity(t *testing.T) {
	// Same seed should produce same identity
	id1, err := DeriveSharedIdentity("my-secret-seed", "derived")
	if err != nil {
		t.Fatalf("DeriveSharedIdentity() error = %v", err)
	}

	id2, _ := DeriveSharedIdentity("my-secret-seed", "derived")

	if id1.Fingerprint != id2.Fingerprint {
		t.Error("Same seed should produce same fingerprint")
	}

	// Different seed should produce different identity
	id3, _ := DeriveSharedIdentity("different-seed", "derived")
	if id1.Fingerprint == id3.Fingerprint {
		t.Error("Different seeds should produce different fingerprints")
	}
}

func TestGenerateChallenge(t *testing.T) {
	challenge, err := GenerateChallenge()
	if err != nil {
		t.Fatalf("GenerateChallenge() error = %v", err)
	}

	if len(challenge) != 32 {
		t.Errorf("Challenge length = %d, want 32", len(challenge))
	}

	// Two challenges should be different
	challenge2, _ := GenerateChallenge()
	if string(challenge) == string(challenge2) {
		t.Error("Challenges should be random")
	}
}

func TestIdentityFile_JSONRoundTrip(t *testing.T) {
	original := IdentityFile{
		Version:     IdentityVersion,
		Username:    "testuser",
		Fingerprint: "abc123def456",
		EncryptKeyPair: KeyPair{
			PrivateKey: "0102030405060708",
			PublicKey:  "09101112131415",
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal error = %v", err)
	}

	var loaded IdentityFile
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}

	if loaded.Username != original.Username {
		t.Errorf("Username mismatch")
	}
	if loaded.Version != original.Version {
		t.Errorf("Version mismatch")
	}
}

func TestSave_CreatesDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "noshitalk-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Path with non-existent subdirectory
	keyPath := filepath.Join(tmpDir, "subdir", "deep", "identity.noshikey")

	id, _ := New("test")
	err = id.Save(keyPath)
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Should have created directories
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("Save should create parent directories")
	}
}

// Benchmark
func BenchmarkNew(b *testing.B) {
	for i := 0; i < b.N; i++ {
		New("bench")
	}
}

func BenchmarkSaveLoad(b *testing.B) {
	tmpDir, _ := os.MkdirTemp("", "noshitalk-bench-*")
	defer os.RemoveAll(tmpDir)

	id, _ := New("bench")
	keyPath := filepath.Join(tmpDir, "bench.key")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id.Save(keyPath)
		Load(keyPath)
	}
}
