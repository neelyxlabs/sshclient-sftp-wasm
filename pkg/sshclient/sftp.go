package sshclient

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// SFTPSession wraps a pkg/sftp Client that runs over an already-established
// ssh.Client. Lifetime: bounded by the parent ssh.Client; closing the SFTPSession
// tears down the SFTP subsystem only, not the SSH connection.
type SFTPSession struct {
	sessionID string
	client    *sftp.Client
	sshClient *ssh.Client
}

var (
	sftpSessions   = make(map[string]*SFTPSession)
	sftpSessionsMu sync.RWMutex
)

// NewSFTPSession opens the SFTP subsystem on an existing SSH client connection.
func (c *Client) NewSFTPSession() (*SFTPSession, error) {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		return nil, fmt.Errorf("ssh not connected")
	}

	client, err := sftp.NewClient(conn)
	if err != nil {
		return nil, fmt.Errorf("open sftp subsystem: %w", err)
	}

	s := &SFTPSession{
		sessionID: generateSFTPSessionID(),
		client:    client,
		sshClient: conn,
	}

	sftpSessionsMu.Lock()
	sftpSessions[s.sessionID] = s
	sftpSessionsMu.Unlock()

	return s, nil
}

// SessionID returns a stable identifier for this SFTP session, used by the
// JS bindings to look up the session across FFI calls.
func (s *SFTPSession) SessionID() string {
	return s.sessionID
}

// PutFile uploads data to remotePath using a temp-file + atomic rename. The
// rename is attempted via the OpenSSH posix-rename@openssh.com extension
// first; servers that don't advertise the extension fall back to standard
// SFTP Rename. This protects against consumers (e.g. ELR pick-up scanners)
// observing a partially-written file.
func (s *SFTPSession) PutFile(remotePath string, data []byte) error {
	suffix, err := randomHex(8)
	if err != nil {
		return fmt.Errorf("generate temp suffix: %w", err)
	}
	tmpPath := remotePath + ".tmp-" + suffix

	f, err := s.client.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmpPath, err)
	}

	n, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		_ = s.client.Remove(tmpPath)
		return fmt.Errorf("write %s: %w", tmpPath, writeErr)
	}
	if n != len(data) {
		_ = s.client.Remove(tmpPath)
		return fmt.Errorf("short write to %s: %d of %d bytes", tmpPath, n, len(data))
	}
	if closeErr != nil {
		_ = s.client.Remove(tmpPath)
		return fmt.Errorf("close %s: %w", tmpPath, closeErr)
	}

	if err := s.client.PosixRename(tmpPath, remotePath); err != nil {
		if rerr := s.client.Rename(tmpPath, remotePath); rerr != nil {
			_ = s.client.Remove(tmpPath)
			return fmt.Errorf("rename %s -> %s: %w (posix attempt: %v)", tmpPath, remotePath, rerr, err)
		}
	}

	return nil
}

// MkdirAll recursively creates remotePath. Already-existing directories are
// not an error.
func (s *SFTPSession) MkdirAll(remotePath string) error {
	if err := s.client.MkdirAll(remotePath); err != nil {
		return fmt.Errorf("mkdir -p %s: %w", remotePath, err)
	}
	return nil
}

// Close tears down the SFTP subsystem. The parent SSH connection remains
// open and must be disconnected separately via the Client.
func (s *SFTPSession) Close() error {
	sftpSessionsMu.Lock()
	delete(sftpSessions, s.sessionID)
	sftpSessionsMu.Unlock()
	return s.client.Close()
}

// GetSFTPSession retrieves a previously-opened SFTP session by ID.
func GetSFTPSession(sessionID string) (*SFTPSession, bool) {
	sftpSessionsMu.RLock()
	defer sftpSessionsMu.RUnlock()
	s, ok := sftpSessions[sessionID]
	return s, ok
}

// randomHex returns a hex-encoded string of 2n characters, sourced from
// crypto/rand. Under GOOS=js/wasm this uses the browser's Web Crypto API.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func generateSFTPSessionID() string {
	suffix, _ := randomHex(6)
	return "sftp-" + suffix
}
