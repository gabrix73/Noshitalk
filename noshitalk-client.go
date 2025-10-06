package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
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
	conn          net.Conn
	gcm           cipher.AEAD
	sharedSecret  *memguard.Enclave
	app           fyne.App
	window        fyne.Window
	messages      *widget.List
	messageList   []string
	input         *widget.Entry
	status        *widget.Label
	connectBtn    *widget.Button
	serverEntry   *widget.Entry
	debugLog      *widget.Entry
	connected     bool
	autoReconnect bool
	lastServer    string
	userList      *widget.List
	onlineUsers   []string
	username      string
	fingerprint   string
	signKey       *ecdh.PrivateKey
	encryptKey    *ecdh.PrivateKey
}

type Message struct {
	From    string `json:"from"`
	To      string `json:"to,omitempty"`
	Content string `json:"content"`
	Time    string `json:"time"`
	Type    string `json:"type"`
}

type UserListMessage struct {
	Type  string   `json:"type"`
	Users []string `json:"users"`
	Time  string   `json:"time"`
}

type IdentityFile struct {
	Version        string  `json:"version"`
	Username       string  `json:"username"`
	Fingerprint    string  `json:"fingerprint"`
	SignKeyPair    KeyPair `json:"signKeyPair"`
	EncryptKeyPair KeyPair `json:"encryptKeyPair"`
}

type KeyPair struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

var (
	version    = "1.0"
	onionRegex = regexp.MustCompile(`^[a-z2-7]{56}\.onion(:[0-9]{1,5})?$`)
)

const (
	messageBlockSize = 256
	minRandomDelay   = 50
	maxRandomDelay   = 200
)

func main() {
	memguard.CatchInterrupt()
	defer memguard.Purge()

	chatApp := app.NewWithID("noshitalk-gui")
	client := &ChatClient{
		app:           chatApp,
		messageList:   []string{},
		autoReconnect: true,
		onlineUsers:   []string{},
	}

	if err := client.initializeIdentity(); err != nil {
		fmt.Printf("Identity initialization failed: %v\n", err)
		fmt.Printf("Continuing with temporary identity\n\n")
	}

	client.createMainWindow()
	client.enableAutoReconnect()
	client.window.ShowAndRun()
}

func (c *ChatClient) initializeIdentity() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	keyPath := filepath.Join(homeDir, ".noshitalk", "gui-identity.noshikey")

	if _, err := os.Stat(keyPath); err == nil {
		return c.loadIdentity(keyPath)
	}

	return c.generateNewIdentity(keyPath)
}

func (c *ChatClient) generateNewIdentity(keyPath string) error {
	fmt.Printf("Generating new identity\n")

	curve := ecdh.X25519()

	signKey, err := curve.GenerateKey(cryptorand.Reader)
	if err != nil {
		return err
	}

	encryptKey, err := curve.GenerateKey(cryptorand.Reader)
	if err != nil {
		return err
	}

	signPubKey := signKey.PublicKey().Bytes()
	hash := sha256.Sum256(signPubKey)
	fingerprint := hex.EncodeToString(hash[:16])

	username := fmt.Sprintf("gui_%s", fingerprint[:8])

	c.signKey = signKey
	c.encryptKey = encryptKey
	c.fingerprint = fingerprint
	c.username = username

	fmt.Printf("Identity: %s\n", fingerprint)
	fmt.Printf("Username: %s\n", username)

	return c.saveIdentity(keyPath)
}

func (c *ChatClient) loadIdentity(keyPath string) error {
	fmt.Printf("Loading identity from %s\n", keyPath)

	data, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}

	var identity IdentityFile
	if err := json.Unmarshal(data, &identity); err != nil {
		return err
	}

	curve := ecdh.X25519()

	signPrivBytes, err := hex.DecodeString(identity.SignKeyPair.PrivateKey)
	if err != nil {
		return err
	}

	encryptPrivBytes, err := hex.DecodeString(identity.EncryptKeyPair.PrivateKey)
	if err != nil {
		return err
	}

	signKey, err := curve.NewPrivateKey(signPrivBytes)
	if err != nil {
		return err
	}

	encryptKey, err := curve.NewPrivateKey(encryptPrivBytes)
	if err != nil {
		return err
	}

	c.signKey = signKey
	c.encryptKey = encryptKey
	c.fingerprint = identity.Fingerprint
	c.username = identity.Username

	fmt.Printf("Identity loaded: %s\n", identity.Fingerprint)
	fmt.Printf("Username: %s\n\n", identity.Username)

	return nil
}

func (c *ChatClient) saveIdentity(keyPath string) error {
	dir := filepath.Dir(keyPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	identity := IdentityFile{
		Version:     "1.0",
		Username:    c.username,
		Fingerprint: c.fingerprint,
		SignKeyPair: KeyPair{
			PrivateKey: hex.EncodeToString(c.signKey.Bytes()),
			PublicKey:  hex.EncodeToString(c.signKey.PublicKey().Bytes()),
		},
		EncryptKeyPair: KeyPair{
			PrivateKey: hex.EncodeToString(c.encryptKey.Bytes()),
			PublicKey:  hex.EncodeToString(c.encryptKey.PublicKey().Bytes()),
		},
	}

	data, err := json.MarshalIndent(identity, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(keyPath, data, 0600); err != nil {
		return err
	}

	fmt.Printf("Identity saved to %s\n\n", keyPath)
	return nil
}

func (c *ChatClient) createMainWindow() {
	c.window = c.app.NewWindow(fmt.Sprintf("NoshiTalk GUI v%s", version))
	c.window.SetIcon(theme.ComputerIcon())
	c.window.Resize(fyne.NewSize(1200, 800))

	c.status = widget.NewLabel("Disconnected")
	c.status.TextStyle.Bold = true

	c.serverEntry = widget.NewEntry()
	c.serverEntry.SetText("")
	c.serverEntry.SetPlaceHolder("abc...xyz.onion:8080")

	c.connectBtn = widget.NewButton("Connect", c.connectToServer)
	c.connectBtn.Importance = widget.HighImportance

	c.messages = widget.NewList(
		func() int {
			return len(c.messageList)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("Template")
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(c.messageList[i])
		},
	)

	c.userList = widget.NewList(
		func() int {
			return len(c.onlineUsers)
		},
		func() fyne.CanvasObject {
			return widget.NewButton("", nil)
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			if i < len(c.onlineUsers) {
				btn := o.(*widget.Button)
				username := c.onlineUsers[i]
				btn.SetText(username)
				btn.OnTapped = func() {
					c.onUserClick(username)
				}
			}
		},
	)

	c.input = widget.NewEntry()
	c.input.SetPlaceHolder("Message...")
	c.input.Disable()
	c.input.OnSubmitted = c.sendMessage

	autoReconnectCheck := widget.NewCheck("Auto-reconnect", func(checked bool) {
		c.autoReconnect = checked
	})

	panicBtn := widget.NewButton("PANIC", c.panic)
	panicBtn.Importance = widget.DangerImportance

	identityInfo := widget.NewLabel("Identity: Loading...")
	if c.fingerprint != "" {
		identityInfo.SetText(fmt.Sprintf("ID: %s", c.fingerprint[:16]))
	}

	securityPanel := widget.NewCard("Security", "",
		container.NewVBox(
			widget.NewLabel("Tor only\nE2E encrypted\nEphemeral messages\nmemguard protected"),
			autoReconnectCheck,
			identityInfo,
			panicBtn,
		))

	c.debugLog = widget.NewEntry()
	c.debugLog.MultiLine = true
	c.debugLog.Wrapping = fyne.TextWrapWord
	c.debugLog.SetText("Ready\n")

	autoReconnectCheck.SetChecked(true)

	debugScroll := container.NewScroll(c.debugLog)
	debugScroll.SetMinSize(fyne.NewSize(350, 300))

	debugPanel := widget.NewCard("Debug", "", debugScroll)

	clearLogBtn := widget.NewButton("Clear", func() {
		c.debugLog.SetText("Log cleared\n")
	})

	rightPanel := container.NewVBox(
		securityPanel,
		debugPanel,
		clearLogBtn,
	)

	connectionPanel := container.NewVBox(
		widget.NewLabel("Server:"),
		c.serverEntry,
		c.connectBtn,
		c.status,
	)

	userListScroll := container.NewScroll(c.userList)
	userListScroll.SetMinSize(fyne.NewSize(200, 0))

	userListPanel := container.NewBorder(
		widget.NewCard("Online", "", widget.NewLabel("")),
		nil, nil, nil,
		userListScroll,
	)

	leftSplit := container.NewHSplit(userListPanel, c.messages)
	leftSplit.SetOffset(0.20)

	chatArea := container.NewHSplit(leftSplit, rightPanel)
	chatArea.SetOffset(0.70)

	bottomBar := container.NewBorder(
		nil, nil,
		widget.NewLabel("Input: "),
		widget.NewButton("Send", func() { c.sendMessage(c.input.Text) }),
		c.input,
	)

	content := container.NewBorder(
		connectionPanel,
		bottomBar,
		nil, nil,
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
				if time.Since(lastAttempt) < 10*time.Second {
					continue
				}
				lastAttempt = time.Now()

				c.addDebugLog("Auto-reconnecting to " + c.lastServer)
				fyne.Do(func() {
					c.serverEntry.SetText(c.lastServer)
					c.connectToServer()
				})
			}
		}
	}()
}

func validateOnionAddress(addr string) error {
	if addr == "" {
		return fmt.Errorf("empty address")
	}

	if !strings.Contains(addr, ".onion") {
		return fmt.Errorf("only .onion addresses allowed")
	}

	if !onionRegex.MatchString(addr) {
		return fmt.Errorf("invalid .onion format")
	}

	return nil
}

func (c *ChatClient) connectToServer() {
	if c.connected {
		c.disconnect()
		return
	}

	serverAddr := c.serverEntry.Text
	if serverAddr == "" {
		c.showError("Error", "Enter .onion address")
		return
	}

	if err := validateOnionAddress(serverAddr); err != nil {
		c.showError("Invalid Address", err.Error())
		return
	}

	c.lastServer = serverAddr
	fyne.Do(func() {
		c.debugLog.SetText("Connecting\n")
	})
	c.addDebugLog("Target: " + serverAddr)

	fyne.Do(func() {
		c.status.SetText("Connecting...")
		c.connectBtn.Disable()
	})

	progress := dialog.NewCustom("Connecting", "Cancel",
		widget.NewProgressBarInfinite(), c.window)
	progress.Show()

	go func() {
		defer fyne.Do(func() { progress.Hide() })

		conn, err := c.connectThroughTor(serverAddr)
		if err != nil {
			c.showError("Connection Error", err.Error())
			c.addDebugLog(fmt.Sprintf("Connection failed: %v", err))
			fyne.Do(func() {
				c.connectBtn.Enable()
				c.status.SetText("Connection failed")
			})
			return
		}

		c.conn = conn
		fyne.Do(func() {
			c.status.SetText("Encrypting...")
		})
		c.addDebugLog("Starting ECDH")

		curve := ecdh.X25519()

		var encryptKey *ecdh.PrivateKey
		if c.encryptKey != nil {
			encryptKey = c.encryptKey
			c.addDebugLog("Using persistent identity: " + c.fingerprint)
		} else {
			var err error
			encryptKey, err = curve.GenerateKey(cryptorand.Reader)
			if err != nil {
				c.showError("Crypto Error", err.Error())
				c.disconnect()
				return
			}
			c.addDebugLog("Using temporary identity")
		}

		encryptKeyBuffer := memguard.NewBufferFromBytes(encryptKey.Bytes())
		defer encryptKeyBuffer.Destroy()

		publicKey := encryptKey.PublicKey()
		publicKeyBytes := publicKey.Bytes()
		c.addDebugLog("Sending public key")

		c.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := c.conn.Write(publicKeyBytes); err != nil {
			c.showError("Connection Error", err.Error())
			c.disconnect()
			return
		}
		c.conn.SetWriteDeadline(time.Time{})

		c.addDebugLog("Receiving server key")
		serverPublicKeyBytes := make([]byte, 32)
		if _, err := io.ReadFull(conn, serverPublicKeyBytes); err != nil {
			c.showError("Connection Error", err.Error())
			c.disconnect()
			return
		}

		serverPublicKey, err := curve.NewPublicKey(serverPublicKeyBytes)
		if err != nil {
			c.showError("Crypto Error", err.Error())
			c.disconnect()
			return
		}

		c.addDebugLog("Calculating shared secret")

		sharedSecret, err := encryptKey.ECDH(serverPublicKey)
		if err != nil {
			c.showError("Crypto Error", err.Error())
			c.disconnect()
			return
		}

		c.addDebugLog("Starting HMAC auth")
		if err := c.performMutualAuth(sharedSecret); err != nil {
			c.showError("Auth Error", err.Error())
			c.disconnect()
			return
		}
		c.addDebugLog("Auth successful")

		c.addDebugLog("Setting up AES-GCM")
		block, err := aes.NewCipher(sharedSecret[:32])
		if err != nil {
			c.showError("Crypto Error", err.Error())
			c.disconnect()
			return
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			c.showError("Crypto Error", err.Error())
			c.disconnect()
			return
		}

		sharedSecretBuffer := memguard.NewBufferFromBytes(sharedSecret)
		c.sharedSecret = sharedSecretBuffer.Seal()
		sharedSecretBuffer.Destroy()

		c.gcm = gcm
		c.connected = true

		fyne.Do(func() {
			c.input.Enable()
			c.connectBtn.SetText("Disconnect")
			c.connectBtn.OnTapped = c.disconnect
			c.connectBtn.Enable()
			c.status.SetText("Connected (E2E)")
		})

		c.addMessage("System", "Connected via Tor")
		c.addMessage("System", "E2E encryption active")
		c.addDebugLog("Session established")

		go c.receiveMessages()
	}()
}

func (c *ChatClient) connectThroughTor(serverAddr string) (net.Conn, error) {
	c.addDebugLog("Starting Tor connection")

	var conn net.Conn
	proxyURLs := []string{
		"socks5://127.0.0.1:9050",
		"socks5://localhost:9050",
	}

	for _, proxyURL := range proxyURLs {
		torProxyUrl, _ := url.Parse(proxyURL)
		if torProxyUrl == nil {
			continue
		}

		baseDialer := &net.Dialer{
			Timeout:   90 * time.Second,
			KeepAlive: 30 * time.Second,
		}

		dialer, dialErr := proxy.FromURL(torProxyUrl, baseDialer)
		if dialErr != nil {
			continue
		}

		c.addDebugLog("Connecting via " + proxyURL)

		var connErr error
		conn, connErr = dialer.Dial("tcp", serverAddr)
		if connErr != nil {
			c.addDebugLog("Failed: " + connErr.Error())
			continue
		} else {
			c.addDebugLog("Connected via " + proxyURL)
			break
		}
	}

	if conn == nil {
		return nil, fmt.Errorf("Tor connection failed")
	}

	c.addDebugLog("TCP established")
	return conn, nil
}

func (c *ChatClient) performMutualAuth(sharedSecret []byte) error {
	c.conn.SetDeadline(time.Now().Add(30 * time.Second))
	defer c.conn.SetDeadline(time.Time{})

	serverChallenge := make([]byte, 32)
	if _, err := io.ReadFull(c.conn, serverChallenge); err != nil {
		return fmt.Errorf("receive challenge failed: %v", err)
	}

	h := hmac.New(sha256.New, sharedSecret)
	h.Write(serverChallenge)
	clientResponse := h.Sum(nil)

	clientChallenge := make([]byte, 32)
	if _, err := cryptorand.Read(clientChallenge); err != nil {
		return fmt.Errorf("challenge generation failed: %v", err)
	}

	if _, err := c.conn.Write(clientResponse); err != nil {
		return fmt.Errorf("send response failed: %v", err)
	}
	if _, err := c.conn.Write(clientChallenge); err != nil {
		return fmt.Errorf("send challenge failed: %v", err)
	}

	serverResponse := make([]byte, 32)
	if _, err := io.ReadFull(c.conn, serverResponse); err != nil {
		return fmt.Errorf("receive response failed: %v", err)
	}

	h.Reset()
	h.Write(clientChallenge)
	expectedServerMAC := h.Sum(nil)

	if !hmac.Equal(serverResponse, expectedServerMAC) {
		return fmt.Errorf("server authentication failed")
	}

	return nil
}

func (c *ChatClient) addDebugLog(message string) {
	timestamp := time.Now().Format("15:04:05")
	logEntry := fmt.Sprintf("[%s] %s\n", timestamp, message)

	fyne.Do(func() {
		c.debugLog.SetText(c.debugLog.Text + logEntry)
		c.debugLog.CursorRow = len(strings.Split(c.debugLog.Text, "\n")) - 1
	})
}

func (c *ChatClient) disconnect() {
	if !c.connected {
		return
	}

	c.connected = false
	c.addDebugLog("Disconnecting")

	if c.conn != nil {
		c.sendEncryptedMessage("/quit")
		time.Sleep(100 * time.Millisecond)
		c.conn.Close()
		c.conn = nil
	}

	if c.sharedSecret != nil {
		buf, _ := c.sharedSecret.Open()
		if buf != nil {
			buf.Destroy()
		}
		c.sharedSecret = nil
	}
	c.gcm = nil

	fyne.Do(func() {
		c.input.Disable()
		c.connectBtn.SetText("Connect")
		c.connectBtn.OnTapped = c.connectToServer
		c.connectBtn.Enable()
		c.status.SetText("Disconnected")
	})

	c.addMessage("System", "Disconnected")
	c.addDebugLog("Keys wiped")
}

func (c *ChatClient) panic() {
	c.addDebugLog("PANIC MODE")

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	if c.sharedSecret != nil {
		buf, _ := c.sharedSecret.Open()
		if buf != nil {
			buf.Destroy()
		}
		c.sharedSecret = nil
	}

	if c.signKey != nil {
		c.signKey = nil
	}

	if c.encryptKey != nil {
		c.encryptKey = nil
	}

	c.gcm = nil
	c.connected = false
	c.fingerprint = ""
	c.username = ""

	fyne.Do(func() {
		c.input.Disable()
		c.connectBtn.SetText("Connect")
		c.connectBtn.OnTapped = c.connectToServer
		c.connectBtn.Enable()
		c.status.SetText("PANIC - All keys destroyed")
	})

	c.addMessage("System", "PANIC: Keys destroyed")
	c.addDebugLog("Memory wiped")

	memguard.Purge()
}

func (c *ChatClient) sendMessage(message string) {
	if !c.connected || message == "" {
		return
	}

	c.addDebugLog("Sending: " + message)

	err := c.sendEncryptedMessage(message)
	if err != nil {
		c.addDebugLog("Send error: " + err.Error())
		c.showError("Send Error", err.Error())
		return
	}

	c.addMessage("You", message)
	fyne.Do(func() {
		c.input.SetText("")
	})
}

func padMessage(plaintext []byte) []byte {
	currentLen := len(plaintext)
	paddedLen := ((currentLen / messageBlockSize) + 1) * messageBlockSize
	padLen := paddedLen - currentLen

	result := make([]byte, 2+paddedLen)
	binary.BigEndian.PutUint16(result[0:2], uint16(currentLen))
	copy(result[2:], plaintext)

	if padLen > 0 {
		padding := make([]byte, padLen)
		cryptorand.Read(padding)
		copy(result[2+currentLen:], padding)
	}

	return result
}

func unpadMessage(paddedData []byte) ([]byte, error) {
	if len(paddedData) < 2 {
		return nil, fmt.Errorf("data too short")
	}

	originalLen := binary.BigEndian.Uint16(paddedData[0:2])

	if int(originalLen) > len(paddedData)-2 {
		return nil, fmt.Errorf("invalid padding")
	}

	return paddedData[2 : 2+originalLen], nil
}

func randomDelay() {
	delay := minRandomDelay + rand.Intn(maxRandomDelay-minRandomDelay)
	time.Sleep(time.Duration(delay) * time.Millisecond)
}

func (c *ChatClient) sendEncryptedMessage(message string) error {
	if c.gcm == nil || c.conn == nil {
		return fmt.Errorf("not connected")
	}

	randomDelay()

	paddedMessage := padMessage([]byte(message))

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(cryptorand.Reader, nonce); err != nil {
		return fmt.Errorf("nonce generation failed: %v", err)
	}

	encrypted := c.gcm.Seal(nil, nonce, paddedMessage, nil)
	data := append(nonce, encrypted...)

	_, err := c.conn.Write(data)
	return err
}

func (c *ChatClient) receiveMessages() {
	buf := make([]byte, 8192)

	c.addDebugLog("Starting receive loop")

	for c.connected {
		c.conn.SetReadDeadline(time.Time{})

		n, err := c.conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				c.addDebugLog("Server closed connection")
			} else {
				c.addDebugLog("Read error: " + err.Error())
			}
			if c.connected {
				c.addMessage("System", "Connection lost")
				c.disconnect()
			}
			return
		}

		if n == 0 {
			continue
		}

		c.addDebugLog(fmt.Sprintf("Received %d bytes", n))

		message, err := c.decryptMessage(buf[:n])
		if err != nil {
			c.addDebugLog("Decrypt error: " + err.Error())
			continue
		}

		var userListMsg UserListMessage
		if err := json.Unmarshal([]byte(message), &userListMsg); err == nil && userListMsg.Type == "user_list" {
			c.onlineUsers = userListMsg.Users
			fyne.Do(func() {
				c.userList.Refresh()
			})
			c.addMessage("System", fmt.Sprintf("Online: %d users", len(userListMsg.Users)))
			continue
		}

		var msg Message
		if err := json.Unmarshal([]byte(message), &msg); err != nil {
			c.addMessage("Server", message)
		} else {
			switch msg.Type {
			case "system":
				c.addMessage("System", msg.Content)
			case "private":
				c.addMessage("PM-"+msg.From, msg.Content)
			case "error":
				c.addMessage("System", "Error: "+msg.Content)
			default:
				c.addMessage(msg.From, msg.Content)
			}
		}
	}

	c.addDebugLog("Receive loop ended")
}

func (c *ChatClient) decryptMessage(data []byte) (string, error) {
	if len(data) < 12 {
		return "", fmt.Errorf("message too short")
	}

	nonce := data[:12]
	ciphertext := data[12:]

	paddedPlaintext, err := c.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %v", err)
	}

	plaintext, err := unpadMessage(paddedPlaintext)
	if err != nil {
		return "", fmt.Errorf("unpad failed: %v", err)
	}

	return string(plaintext), nil
}

func (c *ChatClient) onUserClick(username string) {
	fyne.Do(func() {
		c.input.SetText("/pm " + username + " ")
		c.input.CursorColumn = len(c.input.Text)
		c.window.Canvas().Focus(c.input)
	})
	c.addDebugLog("Ready to PM " + username)
}

func (c *ChatClient) addMessage(sender, message string) {
	timestamp := time.Now().Format("15:04:05")
	formatted := fmt.Sprintf("[%s] %s: %s", timestamp, sender, message)

	c.messageList = append(c.messageList, formatted)
	fyne.Do(func() {
		c.messages.Refresh()
		c.messages.ScrollToBottom()
	})
}

func (c *ChatClient) showError(title, message string) {
	fyne.Do(func() {
		dialog.ShowError(fmt.Errorf(message), c.window)
	})
	c.addMessage("System", title+": "+message)
	c.addDebugLog(title + ": " + message)
}

func init() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Printf("\nShutting down\n")
		memguard.Purge()
		os.Exit(0)
	}()
}
