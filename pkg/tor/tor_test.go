package tor

import (
	"strings"
	"testing"
)

func TestValidateOnionAddress(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		// Valid v3 .onion addresses (56 base32 chars + .onion)
		{
			name:    "valid v3 onion with port",
			addr:    "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:8080",
			wantErr: false,
		},
		{
			name:    "valid v3 onion without port",
			addr:    "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion",
			wantErr: false,
		},
		{
			name:    "valid v3 onion lowercase",
			addr:    "vwxyz234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklm.onion:443",
			wantErr: false,
		},

		// Invalid addresses
		{
			name:    "empty",
			addr:    "",
			wantErr: true,
		},
		{
			name:    "clearnet domain",
			addr:    "example.com:8080",
			wantErr: true,
		},
		{
			name:    "clearnet IP",
			addr:    "192.168.1.1:8080",
			wantErr: true,
		},
		{
			name:    "v2 onion (too short)",
			addr:    "abcdefghijklmnop.onion:8080",
			wantErr: true,
		},
		{
			name:    "uppercase not allowed",
			addr:    "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWX.onion",
			wantErr: true,
		},
		{
			name:    "invalid characters",
			addr:    "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst0189.onion",
			wantErr: true, // 0, 1, 8, 9 not in base32
		},
		{
			name:    "too long",
			addr:    "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyzab.onion",
			wantErr: true,
		},
		{
			name:    "missing .onion",
			addr:    "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx",
			wantErr: true,
		},
		{
			name:    "invalid port",
			addr:    "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:999999",
			wantErr: true,
		},
		{
			name:    "localhost",
			addr:    "localhost:8080",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateOnionAddress(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateOnionAddress(%q) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
			}
		})
	}
}

func TestValidateOnionAddress_ErrorMessages(t *testing.T) {
	tests := []struct {
		addr        string
		errContains string
	}{
		{"", "empty"},
		{"example.com", ".onion"},
		{"short.onion", "invalid"},
	}

	for _, tt := range tests {
		err := ValidateOnionAddress(tt.addr)
		if err == nil {
			t.Errorf("Expected error for %q", tt.addr)
			continue
		}
		if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.errContains)) {
			t.Errorf("Error %q should contain %q", err.Error(), tt.errContains)
		}
	}
}

func TestOnionRegex(t *testing.T) {
	// Valid patterns (56 base32 chars + .onion + optional port)
	validAddrs := []string{
		"abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion",
		"abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:80",
		"abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:8080",
		"abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:65535",
	}

	for _, addr := range validAddrs {
		if !OnionRegex.MatchString(addr) {
			t.Errorf("OnionRegex should match %q", addr)
		}
	}

	// Invalid patterns
	invalidAddrs := []string{
		"tooshort.onion",
		"example.com",
		"127.0.0.1:8080",
		"UPPERCASE.onion",
	}

	for _, addr := range invalidAddrs {
		if OnionRegex.MatchString(addr) {
			t.Errorf("OnionRegex should NOT match %q", addr)
		}
	}
}

func TestDefaultProxyAddresses(t *testing.T) {
	if len(DefaultProxyAddresses) == 0 {
		t.Error("DefaultProxyAddresses should not be empty")
	}

	for _, addr := range DefaultProxyAddresses {
		if !strings.HasPrefix(addr, "socks5://") {
			t.Errorf("Proxy address should start with socks5://: %s", addr)
		}
	}
}

func TestNewDialer(t *testing.T) {
	dialer := NewDialer()

	if dialer == nil {
		t.Fatal("NewDialer() returned nil")
	}

	if len(dialer.ProxyAddresses) == 0 {
		t.Error("Dialer should have default proxy addresses")
	}

	if dialer.Timeout == 0 {
		t.Error("Dialer should have default timeout")
	}

	if dialer.KeepAlive == 0 {
		t.Error("Dialer should have default keepalive")
	}
}

func TestDialer_CustomSettings(t *testing.T) {
	dialer := NewDialer()
	dialer.ProxyAddresses = []string{"socks5://custom:1234"}

	if len(dialer.ProxyAddresses) != 1 {
		t.Error("Should allow custom proxy addresses")
	}
}

// Note: These tests don't actually connect to Tor (that would require Tor running)
// They just test the validation and configuration logic

func TestConnect_InvalidAddress(t *testing.T) {
	_, err := Connect("invalid-address", nil)
	if err == nil {
		t.Error("Connect should fail with invalid address")
	}
}

func TestConnect_EmptyAddress(t *testing.T) {
	_, err := Connect("", nil)
	if err == nil {
		t.Error("Connect should fail with empty address")
	}
}

func TestDialer_Dial_InvalidAddress(t *testing.T) {
	dialer := NewDialer()
	_, err := dialer.Dial("not-an-onion")
	if err == nil {
		t.Error("Dial should fail with invalid address")
	}
}

func TestConnectWithCallback_InvalidAddress(t *testing.T) {
	var progressMessages []string
	callback := func(msg string) {
		progressMessages = append(progressMessages, msg)
	}

	_, err := ConnectWithCallback("invalid", nil, callback)
	if err == nil {
		t.Error("ConnectWithCallback should fail with invalid address")
	}
}

func TestTestProxyAvailable_InvalidURL(t *testing.T) {
	err := TestProxyAvailable("not-a-valid-url")
	if err == nil {
		t.Error("TestProxyAvailable should fail with invalid URL")
	}
}

func TestTestProxyAvailable_NotRunning(t *testing.T) {
	// This proxy shouldn't exist
	err := TestProxyAvailable("socks5://127.0.0.1:59999")
	if err == nil {
		t.Error("TestProxyAvailable should fail when proxy not running")
	}
}

func TestDialer_IsAvailable_NoProxy(t *testing.T) {
	dialer := &Dialer{
		ProxyAddresses: []string{"socks5://127.0.0.1:59999"}, // Non-existent
	}

	if dialer.IsAvailable() {
		t.Error("IsAvailable should return false when no proxy running")
	}
}

// Test constants
func TestConstants(t *testing.T) {
	if DefaultConnectionTimeout == 0 {
		t.Error("DefaultConnectionTimeout should not be zero")
	}
	if DefaultKeepAlive == 0 {
		t.Error("DefaultKeepAlive should not be zero")
	}
	if ProxyTestTimeout == 0 {
		t.Error("ProxyTestTimeout should not be zero")
	}
}

// Benchmark validation
func BenchmarkValidateOnionAddress_Valid(b *testing.B) {
	addr := "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:8080"
	for i := 0; i < b.N; i++ {
		ValidateOnionAddress(addr)
	}
}

func BenchmarkValidateOnionAddress_Invalid(b *testing.B) {
	addr := "example.com"
	for i := 0; i < b.N; i++ {
		ValidateOnionAddress(addr)
	}
}

func BenchmarkOnionRegex_Match(b *testing.B) {
	addr := "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:8080"
	for i := 0; i < b.N; i++ {
		OnionRegex.MatchString(addr)
	}
}
