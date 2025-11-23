package main

import (
	"crypto/cipher"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/awnumar/memguard"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"noshitalk/pkg/crypto"
	"noshitalk/pkg/identity"
	"noshitalk/pkg/protocol"
	"noshitalk/pkg/tor"
)

// ChatClient represents the GUI chat client.
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
	identity      *identity.Identity
}

var version = "2.0-refactored"

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

	// Initialize persistent identity
	keyPath, err := identity.GetDefaultKeyPath("gui-identity.noshikey")
	if err == nil {
		client.identity, err = identity.LoadOrCreate(keyPath, "gui")
		if err != nil {
			fmt.Printf("Identity initialization failed: %v\n", err)
			fmt.Printf("Continuing with temporary identity\n\n")
		}
	}

	client.createMainWindow()
	client.enableAutoReconnect()
	client.window.ShowAndRun()
}

func (c *ChatClient) createMainWindow() {
	c.window = c.app.NewWindow(fmt.Sprintf("NoshiTalk GUI v%s", version))
	c.window.SetIcon(theme.ComputerIcon())
	c.window.Resize(fyne.NewSize(1200, 800))

	c.status = widget.NewLabel("Disconnected")
	c.status.TextStyle.Bold = true

	c.serverEntry = widget.NewEntry()
	c.serverEntry.SetPlaceHolder("abc...xyz.onion:8080")

	c.connectBtn = widget.NewButton("Connect", c.connectToServer)
	c.connectBtn.Importance = widget.HighImportance

	c.messages = widget.NewList(
		func() int { return len(c.messageList) },
		func() fyne.CanvasObject { return widget.NewLabel("Template") },
		func(i widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(c.messageList[i])
		},
	)

	c.userList = widget.NewList(
		func() int { return len(c.onlineUsers) },
		func() fyne.CanvasObject { return widget.NewButton("", nil) },
		func(i widget.ListItemID, o fyne.CanvasObject) {
			if i < len(c.onlineUsers) {
				btn := o.(*widget.Button)
				username := c.onlineUsers[i]
				btn.SetText(username)
				btn.OnTapped = func() { c.onUserClick(username) }
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
	autoReconnectCheck.SetChecked(true)

	panicBtn := widget.NewButton("PANIC", c.panic)
	panicBtn.Importance = widget.DangerImportance

	identityInfo := widget.NewLabel("Identity: Loading...")
	if c.identity != nil {
		identityInfo.SetText(fmt.Sprintf("ID: %s", c.identity.Fingerprint[:16]))
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

	debugScroll := container.NewScroll(c.debugLog)
	debugScroll.SetMinSize(fyne.NewSize(350, 300))

	debugPanel := widget.NewCard("Debug", "", debugScroll)

	clearLogBtn := widget.NewButton("Clear", func() {
		c.debugLog.SetText("Log cleared\n")
	})

	rightPanel := container.NewVBox(securityPanel, debugPanel, clearLogBtn)

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

	content := container.NewBorder(connectionPanel, bottomBar, nil, nil, chatArea)
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

	if err := tor.ValidateOnionAddress(serverAddr); err != nil {
		c.showError("Invalid Address", err.Error())
		return
	}

	c.lastServer = serverAddr
	fyne.Do(func() { c.debugLog.SetText("Connecting\n") })
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

		torDialer := tor.NewDialer()
		conn, err := torDialer.DialWithCallback(serverAddr, func(msg string) {
			c.addDebugLog(msg)
		})
		if err != nil {
			c.showError("Connection Error", err.Error())
			fyne.Do(func() {
				c.connectBtn.Enable()
				c.status.SetText("Connection failed")
			})
			return
		}

		c.conn = conn
		fyne.Do(func() { c.status.SetText("Encrypting...") })
		c.addDebugLog("Starting ECDH")

		// Use persistent identity or generate temporary
		var privateKey = c.identity.PrivateKey
		if c.identity != nil && c.identity.PrivateKey != nil {
			c.addDebugLog("Using persistent identity: " + c.identity.Fingerprint)
		} else {
			privateKey, err = crypto.GenerateX25519KeyPair()
			if err != nil {
				c.showError("Crypto Error", err.Error())
				c.disconnect()
				return
			}
			c.addDebugLog("Using temporary identity")
		}

		// Send public key
		publicKeyBytes := privateKey.PublicKey().Bytes()
		c.addDebugLog("Sending public key")

		c.conn.SetWriteDeadline(time.Now().Add(crypto.HandshakeTimeout))
		if _, err := c.conn.Write(publicKeyBytes); err != nil {
			c.showError("Connection Error", err.Error())
			c.disconnect()
			return
		}
		c.conn.SetWriteDeadline(time.Time{})

		// Receive server public key
		c.addDebugLog("Receiving server key")
		serverPubKeyBytes := make([]byte, 32)
		if _, err := io.ReadFull(conn, serverPubKeyBytes); err != nil {
			c.showError("Connection Error", err.Error())
			c.disconnect()
			return
		}

		// Calculate shared secret
		c.addDebugLog("Calculating shared secret")
		sharedSecret, err := crypto.PerformECDH(privateKey, serverPubKeyBytes)
		if err != nil {
			c.showError("Crypto Error", err.Error())
			c.disconnect()
			return
		}

		// Mutual authentication
		c.addDebugLog("Starting HMAC auth")
		if err := crypto.PerformClientAuth(c.conn, sharedSecret); err != nil {
			c.showError("Auth Error", err.Error())
			c.disconnect()
			return
		}
		c.addDebugLog("Auth successful")

		// Setup AES-GCM
		c.addDebugLog("Setting up AES-GCM")
		gcm, err := crypto.SetupAESGCM(sharedSecret)
		if err != nil {
			c.showError("Crypto Error", err.Error())
			c.disconnect()
			return
		}

		c.sharedSecret = crypto.SecureBuffer(sharedSecret)
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

func (c *ChatClient) disconnect() {
	if !c.connected {
		return
	}

	c.connected = false
	c.addDebugLog("Disconnecting")

	if c.conn != nil {
		c.sendEncrypted("/quit")
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

	c.identity = nil
	c.gcm = nil
	c.connected = false

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

	if err := c.sendEncrypted(message); err != nil {
		c.addDebugLog("Send error: " + err.Error())
		c.showError("Send Error", err.Error())
		return
	}

	c.addMessage("You", message)
	fyne.Do(func() { c.input.SetText("") })
}

func (c *ChatClient) sendEncrypted(message string) error {
	if c.gcm == nil || c.conn == nil {
		return fmt.Errorf("not connected")
	}

	data, err := crypto.EncryptMessage(c.gcm, message)
	if err != nil {
		return err
	}

	_, err = c.conn.Write(data)
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

		message, err := crypto.DecryptMessage(c.gcm, buf[:n])
		if err != nil {
			c.addDebugLog("Decrypt error: " + err.Error())
			continue
		}

		// Try to parse as UserListMessage
		if userList, err := protocol.ParseAsUserList([]byte(message)); err == nil && userList.Type == protocol.TypeUserList {
			c.onlineUsers = userList.Users
			fyne.Do(func() { c.userList.Refresh() })
			c.addMessage("System", fmt.Sprintf("Online: %d users", len(userList.Users)))
			continue
		}

		// Try to parse as Message
		if msg, err := protocol.ParseAsMessage([]byte(message)); err == nil {
			switch msg.Type {
			case protocol.TypeSystem:
				c.addMessage("System", msg.Content)
			case protocol.TypePrivate:
				c.addMessage("PM-"+msg.From, msg.Content)
			case protocol.TypeError:
				c.addMessage("System", "Error: "+msg.Content)
			default:
				c.addMessage(msg.From, msg.Content)
			}
		} else {
			c.addMessage("Server", message)
		}
	}

	c.addDebugLog("Receive loop ended")
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

func (c *ChatClient) addDebugLog(message string) {
	timestamp := time.Now().Format("15:04:05")
	logEntry := fmt.Sprintf("[%s] %s\n", timestamp, message)

	fyne.Do(func() {
		c.debugLog.SetText(c.debugLog.Text + logEntry)
		c.debugLog.CursorRow = len(strings.Split(c.debugLog.Text, "\n")) - 1
	})
}

func (c *ChatClient) showError(title, message string) {
	fyne.Do(func() {
		dialog.ShowError(fmt.Errorf(message), c.window)
	})
	c.addMessage("System", title+": "+message)
	c.addDebugLog(title + ": " + message)
}
