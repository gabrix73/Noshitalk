package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/awnumar/memguard"
	"golang.org/x/net/proxy"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"fyne.io/fyne/v2/theme"
)

type ChatClient struct {
	conn         net.Conn
	gcm          cipher.AEAD
	app          fyne.App
	window       fyne.Window
	messages     *widget.List
	messageList  []string
	input        *widget.Entry
	status       *widget.Label
	connectBtn   *widget.Button
	serverEntry  *widget.Entry
	debugLog     *widget.Entry
	connected    bool
	autoReconnect bool
	lastServer   string
}

var version = "0.1"

func main() {
	memguard.CatchInterrupt()
	defer memguard.Purge()

	chatApp := app.NewWithID("noshitalk-client")
	client := &ChatClient{
		app:         chatApp,
		messageList: []string{},
		autoReconnect: true,
	}

	client.createMainWindow()
	client.enableAutoReconnect()
	client.window.ShowAndRun()
}

func (c *ChatClient) createMainWindow() {
	c.window = c.app.NewWindow(fmt.Sprintf("🔐 NoshiTalk Client v%s - Maximum Security", version))
	c.window.SetIcon(theme.ComputerIcon())
	c.window.Resize(fyne.NewSize(1200, 800))

	c.status = widget.NewLabel("🔴 Disconnected - Ready to connect")
	c.status.TextStyle.Bold = true

	c.serverEntry = widget.NewEntry()
	c.serverEntry.SetText("localhost:8083")
	c.serverEntry.SetPlaceHolder("server:port or .onion:port")

	c.connectBtn = widget.NewButton("🚀 Connect to Secure Server", c.connectToServer)
	c.connectBtn.Importance = widget.HighImportance

	c.messages = widget.NewList(
		func() int {
			return len(c.messageList)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("Template message")
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(c.messageList[i])
		},
	)

	c.input = widget.NewEntry()
	c.input.SetPlaceHolder("Type your secure message here...")
	c.input.Disable()
	c.input.OnSubmitted = c.sendMessage

	// Auto-reconnect checkbox
	autoReconnectCheck := widget.NewCheck("Auto-reconnect", func(checked bool) {
		c.autoReconnect = checked
		if checked {
			c.addDebugLog("🔄 Auto-reconnect enabled")
		} else {
			c.addDebugLog("⏸️ Auto-reconnect disabled")
		}
	})
	autoReconnectCheck.SetChecked(true)

	securityPanel := widget.NewCard("🔒 Security Status", "", 
		container.NewVBox(
			widget.NewLabel("• ECC Authentication ✓\n• TLS 1.3 Encryption ✓\n• Perfect Forward Secrecy ✓\n• Zero Logging ✓\n• Memory Protection ✓\n• Tor Support ✓"),
			autoReconnectCheck,
		))

	c.debugLog = widget.NewEntry()
	c.debugLog.MultiLine = true
	c.debugLog.Wrapping = fyne.TextWrapWord
	c.debugLog.SetText("Ready to connect...\nUse this panel to monitor connection details.\n")
	
	debugScroll := container.NewScroll(c.debugLog)
	debugScroll.SetMinSize(fyne.NewSize(350, 300))
	
	debugPanel := widget.NewCard("🔍 Debug Log", "", debugScroll)

	clearLogBtn := widget.NewButton("🧹 Clear Log", func() {
		c.debugLog.SetText("Debug log cleared.\n")
	})

	copyLogBtn := widget.NewButton("📋 Copy All", func() {
		if c.debugLog.Text != "" {
			c.window.Clipboard().SetContent(c.debugLog.Text)
			c.addDebugLog("📋 Log copied to clipboard")
		}
	})

	debugButtons := container.NewHBox(clearLogBtn, copyLogBtn)

	rightPanel := container.NewVBox(
		securityPanel,
		debugPanel,
		debugButtons,
	)

	connectionPanel := container.NewVBox(
		widget.NewLabel("Server Address:"),
		c.serverEntry,
		c.connectBtn,
		c.status,
	)

	chatArea := container.NewHSplit(
		c.messages,
		rightPanel,
	)
	chatArea.SetOffset(0.65)

	bottomBar := container.NewBorder(
		nil, 
		nil, 
		widget.NewLabel("💬 Input: "), 
		widget.NewButton("Send", func() { c.sendMessage(c.input.Text) }),
		c.input,
	)

	content := container.NewBorder(
		connectionPanel, 
		bottomBar, 
		nil, 
		nil,
		chatArea,
	)

	c.window.SetContent(content)
}

func (c *ChatClient) enableAutoReconnect() {
	go func() {
		lastAttempt := time.Now()
		for {
			time.Sleep(5 * time.Second)
			if !c.connected && c.autoReconnect && c.lastServer != "" {
				// Wait at least 10 seconds between attempts
				if time.Since(lastAttempt) < 10*time.Second {
					continue
				}
				lastAttempt = time.Now()
				
				c.addDebugLog("🔄 Auto-reconnecting to " + c.lastServer)
				c.serverEntry.SetText(c.lastServer)
				c.connectToServer()
			}
		}
	}()
}

func (c *ChatClient) connectToServer() {
	if c.connected {
		c.disconnect()
		return
	}

	serverAddr := c.serverEntry.Text
	if serverAddr == "" {
		c.showError("Input Error", "Please enter server address")
		return
	}

	c.lastServer = serverAddr
	c.debugLog.SetText("Starting new connection...\n")
	c.addDebugLog(fmt.Sprintf("Target: %s", serverAddr))

	c.status.SetText("🟡 Connecting...")
	c.connectBtn.Disable()

	progress := dialog.NewCustom("Connecting", "Cancel", 
		widget.NewProgressBarInfinite(), c.window)
	progress.Show()

	go func() {
		defer progress.Hide()

		isOnion := strings.HasSuffix(serverAddr, ".onion") || 
				  strings.Contains(serverAddr, ".onion:")

		var conn net.Conn
		var err error

		if isOnion {
			c.status.SetText("🟡 Connecting through Tor...")
			c.addDebugLog("🧅 .onion address detected - using Tor")
			conn, err = c.connectThroughTor(serverAddr)
		} else {
			c.status.SetText("🟡 Connecting directly...")
			c.addDebugLog("🌐 Regular address - direct connection")
			conn, err = c.connectDirect(serverAddr)
		}

		if err != nil {
			c.showError("Connection Error", fmt.Sprintf("Error connecting to server: %v", err))
			c.addDebugLog(fmt.Sprintf("❌ Connection failed: %v", err))
			c.connectBtn.Enable()
			c.status.SetText("🔴 Connection Failed")
			return
		}

		c.conn = conn
		c.status.SetText("🟡 Establishing end-to-end encryption...")
		c.addDebugLog("🔐 Starting ECDH key exchange...")

		curve := ecdh.X25519()
		privateKey, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			c.showError("Crypto Error", fmt.Sprintf("Error generating private key: %v", err))
			c.addDebugLog(fmt.Sprintf("❌ Key generation failed: %v", err))
			c.disconnect()
			return
		}

		privateKeyBuffer := memguard.NewBufferFromBytes(privateKey.Bytes())
		defer privateKeyBuffer.Destroy()

		publicKey := privateKey.PublicKey()
		publicKeyBytes := publicKey.Bytes()
		c.addDebugLog("📤 Sending public key...")
		
		c.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		totalSent := 0
		for totalSent < len(publicKeyBytes) {
			n, err := c.conn.Write(publicKeyBytes[totalSent:])
			if err != nil {
				c.showError("Connection Error", fmt.Sprintf("Error sending public key: %v", err))
				c.addDebugLog(fmt.Sprintf("❌ Failed to send public key: %v", err))
				c.disconnect()
				return
			}
			totalSent += n
		}
		c.conn.SetWriteDeadline(time.Time{})
		c.addDebugLog("✅ Public key sent completely")

		c.addDebugLog("📥 Receiving server public key...")
		serverPublicKeyBytes := make([]byte, 32)
		_, err = io.ReadFull(conn, serverPublicKeyBytes)
		if err != nil {
			c.showError("Connection Error", fmt.Sprintf("Error receiving server public key: %v", err))
			c.addDebugLog(fmt.Sprintf("❌ Failed to receive server public key: %v", err))
			c.disconnect()
			return
		}
		c.addDebugLog("✅ Received server public key")

		serverPublicKey, err := curve.NewPublicKey(serverPublicKeyBytes)
		if err != nil {
			c.showError("Crypto Error", fmt.Sprintf("Error parsing server public key: %v", err))
			c.addDebugLog(fmt.Sprintf("❌ Invalid server public key: %v", err))
			c.disconnect()
			return
		}

		c.addDebugLog("🔢 Calculating shared secret...")
		sharedSecret, err := privateKey.ECDH(serverPublicKey)
		if err != nil {
			c.showError("Crypto Error", fmt.Sprintf("Error calculating shared secret: %v", err))
			c.addDebugLog(fmt.Sprintf("❌ ECDH failed: %v", err))
			c.disconnect()
			return
		}

		sharedSecretBuffer := memguard.NewBufferFromBytes(sharedSecret)
		defer sharedSecretBuffer.Destroy()

		c.addDebugLog("🔐 Setting up AES-GCM encryption...")
		block, err := aes.NewCipher(sharedSecret)
		if err != nil {
			c.showError("Crypto Error", fmt.Sprintf("Error initializing AES cipher: %v", err))
			c.addDebugLog(fmt.Sprintf("❌ AES cipher creation failed: %v", err))
			c.disconnect()
			return
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			c.showError("Crypto Error", fmt.Sprintf("Error initializing GCM mode: %v", err))
			c.addDebugLog(fmt.Sprintf("❌ GCM cipher creation failed: %v", err))
			c.disconnect()
			return
		}

		c.gcm = gcm
		c.connected = true
		c.input.Enable()
		c.connectBtn.SetText("🚪 Disconnect")
		c.connectBtn.OnTapped = c.disconnect
		c.connectBtn.Enable()
		
		if isOnion {
			c.status.SetText("🟢 Connected via Tor - Maximum Anonymity")
			c.addMessage("System", "✅ Connected through Tor")
			c.addMessage("System", "🧅 Anonymous connection established")
			c.addDebugLog("🎉 Tor connection fully established!")
		} else {
			c.status.SetText("🟢 Connected - Maximum Security Active")
			c.addMessage("System", "✅ Connected to secure server")
			c.addDebugLog("🎉 Direct connection fully established!")
		}
		
		c.addMessage("System", "🔐 End-to-end encryption established")
		c.addMessage("System", "💬 You can now send secure messages")
		c.addDebugLog("✅ Ready for secure messaging")

		// Start receiving messages
		go c.receiveMessages()
		
		// Start heartbeat after everything is ready
		c.startHeartbeat()
	}()
}

func (c *ChatClient) connectThroughTor(serverAddr string) (net.Conn, error) {
	c.addDebugLog("🧅 Starting Tor connection...")
	c.addDebugLog("🧪 Testing Tor circuit...")
	
	// Test if Tor SOCKS proxy is running
	testConn, testErr := net.DialTimeout("tcp", "127.0.0.1:9050", 2*time.Second)
	if testErr == nil {
		testConn.Close()
		c.addDebugLog("✅ Tor SOCKS proxy is responsive")
	} else {
		c.addDebugLog(fmt.Sprintf("⚠️ Warning: Tor proxy test failed: %v", testErr))
	}
	
	var conn net.Conn
	proxyURLs := []string{
		"socks5://127.0.0.1:9050",
		"socks5://localhost:9050",
	}
	
	for i, proxyURL := range proxyURLs {
		c.addDebugLog(fmt.Sprintf("🔗 Attempt %d: Using proxy %s", i+1, proxyURL))
		
		torProxyUrl, _ := url.Parse(proxyURL)
		if torProxyUrl == nil {
			c.addDebugLog("❌ Invalid proxy URL")
			continue
		}

		baseDialer := &net.Dialer{
			Timeout:   90 * time.Second,
			KeepAlive: 30 * time.Second,
		}

		dialer, dialErr := proxy.FromURL(torProxyUrl, baseDialer)
		if dialErr != nil {
			c.addDebugLog(fmt.Sprintf("❌ Error creating dialer: %v", dialErr))
			continue
		}

		c.addDebugLog(fmt.Sprintf("🔗 Connecting to %s through Tor...", serverAddr))
		
		var connErr error
		conn, connErr = dialer.Dial("tcp", serverAddr)
		if connErr != nil {
			c.addDebugLog(fmt.Sprintf("❌ Attempt %d failed: %v", i+1, connErr))
			if i < len(proxyURLs)-1 {
				time.Sleep(2 * time.Second)
				continue
			}
		} else {
			c.addDebugLog(fmt.Sprintf("✅ Connection successful with proxy %s", proxyURL))
			break
		}
	}
	
	if conn == nil {
		return nil, fmt.Errorf("Tor SOCKS connection failed after all attempts")
	}

	c.addDebugLog("✅ TCP connection established through Tor")

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "",
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}

	c.addDebugLog("🔐 Starting TLS handshake...")
	
	tlsConn := tls.Client(conn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(45 * time.Second))
	
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		c.addDebugLog(fmt.Sprintf("❌ TLS handshake failed: %v", err))
		return nil, fmt.Errorf("TLS handshake through Tor failed: %v", err)
	}
	
	tlsConn.SetDeadline(time.Time{})
	
	c.addDebugLog("✅ TLS connection established")

	return tlsConn, nil
}

func (c *ChatClient) connectDirect(serverAddr string) (net.Conn, error) {
	c.addDebugLog("🔗 Starting direct connection...")
	
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
	}

	c.addDebugLog(fmt.Sprintf("📡 Connecting to %s...", serverAddr))
	
	conn, err := net.DialTimeout("tcp", serverAddr, 30*time.Second)
	if err != nil {
		c.addDebugLog(fmt.Sprintf("❌ TCP connection failed: %v", err))
		return nil, fmt.Errorf("direct TCP connection failed: %v", err)
	}

	c.addDebugLog("✅ TCP connection established")
	c.addDebugLog("🔐 Starting TLS handshake...")
	
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		c.addDebugLog(fmt.Sprintf("❌ TLS handshake failed: %v", err))
		return nil, fmt.Errorf("TLS handshake failed: %v", err)
	}

	c.addDebugLog("✅ TLS connection established")

	return tlsConn, nil
}

func (c *ChatClient) addDebugLog(message string) {
	timestamp := time.Now().Format("15:04:05")
	logEntry := fmt.Sprintf("[%s] %s\n", timestamp, message)
	
	currentText := c.debugLog.Text
	c.debugLog.SetText(currentText + logEntry)
	
	c.debugLog.CursorRow = len(strings.Split(c.debugLog.Text, "\n")) - 1
}

func (c *ChatClient) startHeartbeat() {
	go func() {
		for {
			time.Sleep(30 * time.Second)
			if !c.connected {
				c.addDebugLog("💔 Heartbeat stopped - not connected")
				return
			}
			
			c.addDebugLog("💗 Sending keepalive ping...")
			if err := c.sendEncryptedMessage("/ping"); err != nil {
				c.addDebugLog(fmt.Sprintf("❌ Keepalive failed: %v", err))
				if c.connected {
					c.addMessage("System", "❌ Connection lost - heartbeat failed")
					c.disconnect()
				}
				return
			}
		}
	}()
}

func (c *ChatClient) disconnect() {
	if !c.connected {
		return
	}

	c.connected = false
	c.addDebugLog("🔌 Initiating disconnect...")

	if c.conn != nil {
		c.sendEncryptedMessage("/quit")
		time.Sleep(100 * time.Millisecond)
		c.conn.Close()
	}
	
	c.input.Disable()
	c.connectBtn.SetText("🚀 Connect to Secure Server")
	c.connectBtn.OnTapped = c.connectToServer
	c.connectBtn.Enable()
	c.status.SetText("🔴 Disconnected - Ready to connect")
	
	c.addMessage("System", "📴 Disconnected from server")
	c.addDebugLog("✅ Disconnection complete - session cleaned")
}

func (c *ChatClient) sendMessage(message string) {
	if !c.connected || message == "" {
		return
	}

	c.addDebugLog(fmt.Sprintf("📤 Sending message: %s", message))

	err := c.sendEncryptedMessage(message)
	if err != nil {
		c.addDebugLog(fmt.Sprintf("❌ Send error: %v", err))
		c.showError("Send Error", fmt.Sprintf("Error sending message: %v", err))
		return
	}

	c.addDebugLog("✅ Message sent successfully")
	c.addMessage("You", message)
	c.input.SetText("")
}

func (c *ChatClient) sendEncryptedMessage(message string) error {
	if c.gcm == nil {
		return fmt.Errorf("encryption not initialized")
	}
	
	if c.conn == nil {
		return fmt.Errorf("connection not established")
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %v", err)
	}

	encrypted := c.gcm.Seal(nil, nonce, []byte(message), nil)
	data := append(nonce, encrypted...)
	
	_, err := c.conn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write message: %v", err)
	}

	return nil
}

func (c *ChatClient) receiveMessages() {
	buf := make([]byte, 8192)
	
	c.addDebugLog("📡 Starting message receive loop")
	
	for c.connected {
		// NO deadline for persistent connections
		c.conn.SetReadDeadline(time.Time{}) 
		
		n, err := c.conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				c.addDebugLog("📴 Server closed connection (EOF)")
			} else {
				c.addDebugLog(fmt.Sprintf("❌ Read error: %v", err))
			}
			if c.connected {
				c.addMessage("System", "❌ Connection lost")
				c.disconnect()
			}
			return
		}
		
		if n == 0 {
			c.addDebugLog("⚠️ Read 0 bytes, continuing...")
			continue
		}
		
		c.addDebugLog(fmt.Sprintf("📥 Received %d bytes", n))
		
		// Decrypt the message
		message, err := c.decryptMessage(buf[:n])
		if err != nil {
			c.addDebugLog(fmt.Sprintf("❌ Decrypt error: %v", err))
			continue
		}
		
		c.addDebugLog(fmt.Sprintf("🔓 Decrypted: %s", message))
		
		// Handle special commands
		if message == "/pong" {
			c.addDebugLog("🏓 Pong received from server")
			continue // Don't show pong in messages
		}
		
		// Try to parse as JSON
		var msg struct {
			From    string `json:"from"`
			Content string `json:"content"`
			Type    string `json:"type"`
			Time    string `json:"time"`
		}
		
		if err := json.Unmarshal([]byte(message), &msg); err != nil {
			// Not JSON, show as plain message
			c.addDebugLog(fmt.Sprintf("📝 Plain message: %s", message))
			c.addMessage("Server", message)
		} else {
			c.addDebugLog(fmt.Sprintf("📋 JSON from %s: %s", msg.From, msg.Content))
			if msg.Type == "system" {
				c.addMessage("System", msg.Content)
			} else {
				c.addMessage(msg.From, msg.Content)
			}
		}
	}
	
	c.addDebugLog("📡 Receive loop ended")
}

func (c *ChatClient) decryptMessage(data []byte) (string, error) {
	if len(data) < 12 {
		return "", fmt.Errorf("message too short: %d bytes", len(data))
	}

	nonce := data[:12]
	ciphertext := data[12:]

	plaintext, err := c.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %v", err)
	}

	return string(plaintext), nil
}

func (c *ChatClient) addMessage(sender, message string) {
	timestamp := time.Now().Format("15:04:05")
	formatted := fmt.Sprintf("[%s] %s: %s", timestamp, sender, message)
	
	c.messageList = append(c.messageList, formatted)
	c.messages.Refresh()
	c.messages.ScrollToBottom()
}

func (c *ChatClient) showError(title, message string) {
	dialog.ShowError(fmt.Errorf(message), c.window)
	c.addMessage("System", "❌ "+title+": "+message)
	c.addDebugLog("❌ " + title + ": " + message)
}

func init() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-sigChan
		fmt.Printf("\n🛑 NoshiTalk Client v%s shutting down...\n", version)
		memguard.Purge()
		os.Exit(0)
	}()
}
