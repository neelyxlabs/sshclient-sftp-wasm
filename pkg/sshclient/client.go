package sshclient

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// HostKeyPin identifies a server host key the caller is willing to trust.
// The SHA256 field is the primary binding and must match OpenSSH's
// `ssh.FingerprintSHA256` format ("SHA256:<base64-no-padding>"). The
// Algorithm field is informational (e.g. "ssh-ed25519"); pin matching
// checks the SHA256 only, since a single server publishes multiple keys
// and the SHA256 alone identifies the specific one.
type HostKeyPin struct {
	Algorithm string
	SHA256    string
}

// ConnectErrorCode classifies connect-time failures for stable consumer
// dispatch. The JS bindings surface these codes to TypeScript, which maps
// them to typed error classes.
type ConnectErrorCode string

const (
	CodeHostKeyPinRequired ConnectErrorCode = "host-key-pin-required"
	CodeHostKeyMismatch    ConnectErrorCode = "host-key-mismatch"
	CodePPKNotSupported    ConnectErrorCode = "ppk-not-supported"
	CodeInvalidPrivateKey  ConnectErrorCode = "invalid-private-key"
	CodeAuthFailed         ConnectErrorCode = "auth-failed"
	CodeTransportError     ConnectErrorCode = "transport-error"
	CodeInternal           ConnectErrorCode = "internal"
)

// ConnectError carries a machine-readable Code alongside a human-readable
// Message. Consumers on the JS side distinguish on Code.
type ConnectError struct {
	Code    ConnectErrorCode
	Message string
	// Fingerprint is populated on CodeHostKeyMismatch so the caller can surface
	// both the expected and the actually-seen keys.
	Expected *HostKeyPin
	Got      *HostKeyPin
}

func (e *ConnectError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return string(e.Code)
}

func newConnectError(code ConnectErrorCode, format string, a ...interface{}) *ConnectError {
	return &ConnectError{Code: code, Message: fmt.Sprintf(format, a...)}
}

// ConnectionOptions carries everything needed to open an SSH connection.
// HostKeyPin is REQUIRED — connections without a pin fail with
// CodeHostKeyPinRequired before any network I/O against the target server.
// Use GetServerFingerprint for a one-shot key capture that deliberately
// does not auth.
type ConnectionOptions struct {
	Host        string
	Port        int
	User        string
	Password    string
	PrivateKey  string
	Timeout     int
	HostKeyPin  *HostKeyPin
}

type PacketCallback func(data []byte, metadata map[string]interface{})
type StateCallback func(state string)

type Client struct {
	options         ConnectionOptions
	conn            *ssh.Client
	session         *ssh.Session
	sessionID       string
	mu              sync.RWMutex
	onPacketReceive PacketCallback
	onPacketSend    PacketCallback
	onStateChange   StateCallback
	transport       Transport
	stdin           chan []byte
	stdout          chan []byte
	shellStarted    bool
}

var (
	sessions   = make(map[string]*Client)
	sessionsMu sync.RWMutex
)

func New(options ConnectionOptions) *Client {
	return &Client{
		options:   options,
		sessionID: generateSessionID(),
		stdin:     make(chan []byte, 100),
		stdout:    make(chan []byte, 100),
	}
}

// SetTransport sets the transport for the client
func (c *Client) SetTransport(transport Transport) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.transport = transport
}

func (c *Client) OnPacketReceive(callback PacketCallback) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onPacketReceive = callback
}

func (c *Client) OnPacketSend(callback PacketCallback) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onPacketSend = callback
}

func (c *Client) OnStateChange(callback StateCallback) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onStateChange = callback
}

func (c *Client) Connect() (string, error) {
	c.notifyStateChange("connecting")

	if c.options.HostKeyPin == nil {
		c.notifyStateChange("error")
		return "", newConnectError(CodeHostKeyPinRequired,
			"host key pin is required; supply options.HostKeyPin before Connect")
	}

	config := &ssh.ClientConfig{
		User:            c.options.User,
		HostKeyCallback: makePinnedHostKeyCallback(c.options.HostKeyPin),
		Timeout:         time.Duration(c.options.Timeout) * time.Second,
	}

	if c.options.Password != "" {
		config.Auth = append(config.Auth, ssh.Password(c.options.Password))
	}

	if c.options.PrivateKey != "" {
		if looksLikePPK([]byte(c.options.PrivateKey)) {
			c.notifyStateChange("error")
			return "", newConnectError(CodePPKNotSupported,
				"PuTTY (.ppk) private keys are not supported; convert with `puttygen -O private-openssh yourkey.ppk`")
		}
		signer, err := ssh.ParsePrivateKey([]byte(c.options.PrivateKey))
		if err != nil {
			c.notifyStateChange("error")
			return "", newConnectError(CodeInvalidPrivateKey,
				"failed to parse private key: %v", err)
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}

	// The transport should already be set before calling Connect
	if c.transport == nil {
		c.notifyStateChange("error")
		return "", newConnectError(CodeTransportError, "no transport configured")
	}

	// Create SSH connection over the transport
	addr := fmt.Sprintf("%s:%d", c.options.Host, c.options.Port)

	// Wrap transport with packet interceptor
	wrappedTransport := NewInterceptedTransport(c.transport, c.onPacketSend, c.onPacketReceive)

	// Create SSH client connection using the transport
	sshConn, chans, reqs, err := ssh.NewClientConn(wrappedTransport, addr, config)
	if err != nil {
		c.notifyStateChange("error")
		return "", classifyConnectError(err)
	}

	c.conn = ssh.NewClient(sshConn, chans, reqs)

	sessionsMu.Lock()
	sessions[c.sessionID] = c
	sessionsMu.Unlock()

	c.notifyStateChange("connected")

	return c.sessionID, nil
}

// GetServerFingerprint performs a minimal SSH handshake against options.Host
// using the supplied transport, captures the server's host key fingerprint,
// and aborts the connection before any authentication exchange. Intended
// for first-run / TOFU flows where a caller needs to display the server's
// key to a user for approval before pinning.
//
// options.HostKeyPin is ignored (and not required) on this path.
func GetServerFingerprint(options ConnectionOptions, transport Transport) (*HostKeyPin, error) {
	if transport == nil {
		return nil, newConnectError(CodeTransportError, "no transport configured")
	}

	var captured *HostKeyPin
	captureSentinel := errors.New("fingerprint-captured")

	config := &ssh.ClientConfig{
		User: options.User,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			captured = &HostKeyPin{
				Algorithm: key.Type(),
				SHA256:    ssh.FingerprintSHA256(key),
			}
			return captureSentinel
		},
		// No Auth methods — we abort before auth via the sentinel error.
		Timeout: time.Duration(options.Timeout) * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", options.Host, options.Port)
	_, _, _, err := ssh.NewClientConn(transport, addr, config)
	if captured != nil {
		// Expected: NewClientConn returned our captureSentinel (or a wrapping error).
		// Either way, we got the fingerprint before auth.
		return captured, nil
	}
	return nil, newConnectError(CodeTransportError,
		"failed to capture host key before handshake error: %v", err)
}

// makePinnedHostKeyCallback returns an ssh.HostKeyCallback that matches the
// server's presented key against pin.SHA256.
func makePinnedHostKeyCallback(pin *HostKeyPin) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		got := &HostKeyPin{
			Algorithm: key.Type(),
			SHA256:    ssh.FingerprintSHA256(key),
		}
		if got.SHA256 == pin.SHA256 {
			return nil
		}
		return &ConnectError{
			Code:     CodeHostKeyMismatch,
			Message:  fmt.Sprintf("host key mismatch: expected %s, got %s (%s)", pin.SHA256, got.SHA256, got.Algorithm),
			Expected: pin,
			Got:      got,
		}
	}
}

// classifyConnectError converts lower-level SSH errors from ssh.NewClientConn
// into ConnectError with a stable code. Host-key and PPK errors are already
// typed at their source.
func classifyConnectError(err error) error {
	if err == nil {
		return nil
	}
	// If our host-key callback already produced a typed ConnectError, unwrap it.
	var ce *ConnectError
	if errors.As(err, &ce) {
		return ce
	}
	msg := err.Error()
	if containsAny(msg, "unable to authenticate", "ssh: handshake failed: ssh: unable to authenticate",
		"no supported methods remain", "permission denied") {
		return newConnectError(CodeAuthFailed, "%v", err)
	}
	return newConnectError(CodeTransportError, "%v", err)
}

func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if bytes.Contains([]byte(haystack), []byte(n)) {
			return true
		}
	}
	return false
}

// looksLikePPK returns true if data looks like a PuTTY .ppk private key.
// Detected early so we return a helpful CodePPKNotSupported error before
// ssh.ParsePrivateKey produces a less-friendly message.
func looksLikePPK(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte("PuTTY-User-Key-File"))
}

func (c *Client) StartShell() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.shellStarted {
		return nil // Shell already started
	}

	if c.conn == nil {
		return fmt.Errorf("not connected")
	}

	// Create a new session
	session, err := c.conn.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	c.session = session

	// Set up stdin pipe
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %v", err)
	}

	// Set up stdout pipe
	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	// Set up stderr pipe (combine with stdout)
	stderr, err := session.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %v", err)
	}

	// Request pseudo terminal
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,     // enable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	if err := session.RequestPty("xterm-256color", 24, 80, modes); err != nil {
		return fmt.Errorf("request for pseudo terminal failed: %v", err)
	}

	// Start the remote shell
	if err := session.Shell(); err != nil {
		return fmt.Errorf("failed to start shell: %v", err)
	}

	c.shellStarted = true

	// Start goroutine to handle stdin
	go func() {
		for data := range c.stdin {
			stdin.Write(data)
		}
	}()

	// Start goroutine to handle stdout
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stdout.Read(buf)
			if err != nil {
				break
			}
			if n > 0 && c.onPacketReceive != nil {
				data := make([]byte, n)
				copy(data, buf[:n])
				metadata := map[string]interface{}{
					"timestamp": time.Now().Unix(),
					"type":      "data",
					"direction": "receive",
					"size":      n,
				}
				c.onPacketReceive(data, metadata)
			}
		}
	}()

	// Start goroutine to handle stderr
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stderr.Read(buf)
			if err != nil {
				break
			}
			if n > 0 && c.onPacketReceive != nil {
				data := make([]byte, n)
				copy(data, buf[:n])
				metadata := map[string]interface{}{
					"timestamp": time.Now().Unix(),
					"type":      "data",
					"direction": "receive",
					"size":      n,
				}
				c.onPacketReceive(data, metadata)
			}
		}
	}()

	return nil
}

func (c *Client) Send(data []byte) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.shellStarted {
		// Start shell on first send
		c.mu.RUnlock()
		err := c.StartShell()
		c.mu.RLock()
		if err != nil {
			return err
		}
	}

	// Send data to stdin channel
	select {
	case c.stdin <- data:
		if c.onPacketSend != nil {
			metadata := map[string]interface{}{
				"timestamp": time.Now().Unix(),
				"type":      "data",
				"direction": "send",
				"size":      len(data),
			}
			c.onPacketSend(data, metadata)
		}
		return nil
	default:
		return fmt.Errorf("stdin buffer full")
	}
}

func (c *Client) ResizeTerminal(cols, rows int) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.session == nil {
		return fmt.Errorf("no active session")
	}

	return c.session.WindowChange(rows, cols)
}

func (c *Client) Disconnect() error {
	c.notifyStateChange("disconnecting")

	c.mu.Lock()
	defer c.mu.Unlock()

	// Close stdin channel to stop goroutine
	if c.stdin != nil {
		close(c.stdin)
		c.stdin = nil
	}

	if c.session != nil {
		c.session.Close()
		c.session = nil
	}

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	c.shellStarted = false

	sessionsMu.Lock()
	delete(sessions, c.sessionID)
	sessionsMu.Unlock()

	c.notifyStateChange("disconnected")

	return nil
}

func (c *Client) notifyStateChange(state string) {
	if c.onStateChange != nil {
		c.onStateChange(state)
	}
}

// GetClient retrieves an SSH client by its session ID. Used by SFTP bindings
// that need to open the SFTP subsystem on an already-connected session.
func GetClient(sessionID string) (*Client, bool) {
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	client, ok := sessions[sessionID]
	return client, ok
}

func DisconnectSession(sessionID string) error {
	sessionsMu.RLock()
	client, exists := sessions[sessionID]
	sessionsMu.RUnlock()

	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	return client.Disconnect()
}

func SendToSession(sessionID string, data []byte) error {
	sessionsMu.RLock()
	client, exists := sessions[sessionID]
	sessionsMu.RUnlock()

	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	return client.Send(data)
}

func generateSessionID() string {
	suffix, _ := randomHex(8)
	return "ssh-" + suffix
}
