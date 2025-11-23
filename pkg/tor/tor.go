// Package tor provides Tor SOCKS5 proxy connection utilities for NoshiTalk.
package tor

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

const (
	// DefaultConnectionTimeout is the timeout for establishing connections
	DefaultConnectionTimeout = 90 * time.Second

	// DefaultKeepAlive is the keep-alive interval for connections
	DefaultKeepAlive = 30 * time.Second

	// ProxyTestTimeout is the timeout for testing proxy availability
	ProxyTestTimeout = 2 * time.Second
)

var (
	// DefaultProxyAddresses are the default Tor SOCKS5 proxy addresses to try
	DefaultProxyAddresses = []string{
		"socks5://127.0.0.1:9050",  // Standard Tor daemon
		"socks5://localhost:9050",  // Alternative
		"socks5://127.0.0.1:9150",  // Tor Browser
	}

	// OnionRegex validates v3 .onion addresses
	OnionRegex = regexp.MustCompile(`^[a-z2-7]{56}\.onion(:[0-9]{1,5})?$`)
)

// ValidateOnionAddress validates that an address is a proper v3 .onion address.
func ValidateOnionAddress(addr string) error {
	if addr == "" {
		return fmt.Errorf("address cannot be empty")
	}

	if !strings.Contains(addr, ".onion") {
		return fmt.Errorf("only Tor .onion addresses allowed - no clearnet connections")
	}

	if !OnionRegex.MatchString(addr) {
		return fmt.Errorf("invalid .onion address format (must be v3: 56 chars + .onion:port)")
	}

	return nil
}

// TestProxyAvailable tests if a Tor proxy is available at the given address.
func TestProxyAvailable(proxyAddr string) error {
	// Extract host:port from proxy URL
	u, err := url.Parse(proxyAddr)
	if err != nil {
		return fmt.Errorf("invalid proxy URL: %w", err)
	}

	host := u.Host
	if host == "" {
		host = "127.0.0.1:9050"
	}

	conn, err := net.DialTimeout("tcp", host, ProxyTestTimeout)
	if err != nil {
		return fmt.Errorf("proxy not responding: %w", err)
	}
	conn.Close()

	return nil
}

// Connect establishes a connection to a .onion address through Tor.
// It tries multiple proxy addresses and returns the first successful connection.
func Connect(serverAddr string, proxyAddresses []string) (net.Conn, error) {
	if err := ValidateOnionAddress(serverAddr); err != nil {
		return nil, err
	}

	if len(proxyAddresses) == 0 {
		proxyAddresses = DefaultProxyAddresses
	}

	var conn net.Conn
	var lastErr error

	for _, proxyURL := range proxyAddresses {
		torProxyUrl, err := url.Parse(proxyURL)
		if err != nil {
			lastErr = err
			continue
		}

		baseDialer := &net.Dialer{
			Timeout:   DefaultConnectionTimeout,
			KeepAlive: DefaultKeepAlive,
		}

		dialer, err := proxy.FromURL(torProxyUrl, baseDialer)
		if err != nil {
			lastErr = err
			continue
		}

		conn, err = dialer.Dial("tcp", serverAddr)
		if err != nil {
			lastErr = fmt.Errorf("connection via %s failed: %w", proxyURL, err)
			continue
		}

		// Success
		return conn, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all Tor proxy attempts failed: %w", lastErr)
	}

	return nil, fmt.Errorf("no proxy addresses configured")
}

// ConnectWithCallback establishes a connection with progress callbacks.
func ConnectWithCallback(serverAddr string, proxyAddresses []string, onProgress func(string)) (net.Conn, error) {
	if err := ValidateOnionAddress(serverAddr); err != nil {
		return nil, err
	}

	if len(proxyAddresses) == 0 {
		proxyAddresses = DefaultProxyAddresses
	}

	var conn net.Conn
	var lastErr error

	for _, proxyURL := range proxyAddresses {
		if onProgress != nil {
			onProgress(fmt.Sprintf("Trying proxy %s...", proxyURL))
		}

		torProxyUrl, err := url.Parse(proxyURL)
		if err != nil {
			lastErr = err
			continue
		}

		baseDialer := &net.Dialer{
			Timeout:   DefaultConnectionTimeout,
			KeepAlive: DefaultKeepAlive,
		}

		dialer, err := proxy.FromURL(torProxyUrl, baseDialer)
		if err != nil {
			lastErr = err
			continue
		}

		if onProgress != nil {
			onProgress(fmt.Sprintf("Connecting to %s...", serverAddr))
		}

		conn, err = dialer.Dial("tcp", serverAddr)
		if err != nil {
			lastErr = fmt.Errorf("connection via %s failed: %w", proxyURL, err)
			if onProgress != nil {
				onProgress(fmt.Sprintf("Failed: %v", err))
			}
			continue
		}

		if onProgress != nil {
			onProgress(fmt.Sprintf("Connected via %s", proxyURL))
		}
		return conn, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all Tor proxy attempts failed: %w", lastErr)
	}

	return nil, fmt.Errorf("no proxy addresses configured")
}

// Dialer wraps a Tor SOCKS5 dialer with additional configuration.
type Dialer struct {
	ProxyAddresses []string
	Timeout        time.Duration
	KeepAlive      time.Duration
}

// NewDialer creates a new Tor dialer with default settings.
func NewDialer() *Dialer {
	return &Dialer{
		ProxyAddresses: DefaultProxyAddresses,
		Timeout:        DefaultConnectionTimeout,
		KeepAlive:      DefaultKeepAlive,
	}
}

// Dial connects to a .onion address through Tor.
func (d *Dialer) Dial(serverAddr string) (net.Conn, error) {
	return Connect(serverAddr, d.ProxyAddresses)
}

// DialWithCallback connects with progress callbacks.
func (d *Dialer) DialWithCallback(serverAddr string, onProgress func(string)) (net.Conn, error) {
	return ConnectWithCallback(serverAddr, d.ProxyAddresses, onProgress)
}

// IsAvailable checks if at least one Tor proxy is available.
func (d *Dialer) IsAvailable() bool {
	for _, addr := range d.ProxyAddresses {
		if err := TestProxyAvailable(addr); err == nil {
			return true
		}
	}
	return false
}
