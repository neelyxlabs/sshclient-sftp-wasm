package sshclient

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

// newTestSFTPPair wires an in-memory sftp.Server to an sftp.Client over
// net.Pipe(), constructs an SFTPSession around the client, and returns a
// cleanup function. No SSH involved — these tests exercise only the
// SFTP-subsystem-level operations.
func newTestSFTPPair(t *testing.T) (*SFTPSession, func()) {
	t.Helper()

	clientConn, serverConn := net.Pipe()

	// Serve in a goroutine; pkg/sftp's Server blocks in Serve() until the
	// underlying conn closes.
	go func() {
		server, err := sftp.NewServer(serverConn)
		if err != nil {
			// t.Errorf would race with cleanup; prefer silent exit — test
			// failures surface via the client side anyway.
			return
		}
		server.Serve()
		server.Close()
	}()

	client, err := sftp.NewClientPipe(clientConn, clientConn)
	if err != nil {
		clientConn.Close()
		serverConn.Close()
		t.Fatalf("sftp.NewClientPipe: %v", err)
	}

	sess := &SFTPSession{
		sessionID: generateSFTPSessionID(),
		client:    client,
	}
	sftpSessionsMu.Lock()
	sftpSessions[sess.sessionID] = sess
	sftpSessionsMu.Unlock()

	cleanup := func() {
		_ = sess.Close()
		_ = clientConn.Close()
		_ = serverConn.Close()
	}
	return sess, cleanup
}

func TestSFTPSession_PutFile_HappyPath(t *testing.T) {
	sess, cleanup := newTestSFTPPair(t)
	defer cleanup()

	dir := t.TempDir()
	target := filepath.Join(dir, "hello.txt")
	want := []byte("hello world\n")

	if err := sess.PutFile(target, want); err != nil {
		t.Fatalf("PutFile: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", target, err)
	}
	if string(got) != string(want) {
		t.Errorf("PutFile content: got %q, want %q", got, want)
	}
}

func TestSFTPSession_PutFile_AtomicRename_NoTempLeftover(t *testing.T) {
	sess, cleanup := newTestSFTPPair(t)
	defer cleanup()

	dir := t.TempDir()
	target := filepath.Join(dir, "report.csv")
	payload := []byte("id,name,value\n1,alpha,100\n2,beta,200\n")

	if err := sess.PutFile(target, payload); err != nil {
		t.Fatalf("PutFile: %v", err)
	}

	// Verify target exists...
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("target not at final path: %v", err)
	}
	// ... and no .tmp-* leftover.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestSFTPSession_MkdirAll_Recursive(t *testing.T) {
	sess, cleanup := newTestSFTPPair(t)
	defer cleanup()

	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b", "c")

	if err := sess.MkdirAll(nested); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if info, err := os.Stat(nested); err != nil || !info.IsDir() {
		t.Errorf("expected directory at %s: err=%v", nested, err)
	}
}

func TestSFTPSession_MkdirAll_Idempotent(t *testing.T) {
	sess, cleanup := newTestSFTPPair(t)
	defer cleanup()

	dir := t.TempDir()
	target := filepath.Join(dir, "reports")

	if err := sess.MkdirAll(target); err != nil {
		t.Fatalf("first MkdirAll: %v", err)
	}
	if err := sess.MkdirAll(target); err != nil {
		t.Errorf("second MkdirAll should be a no-op: %v", err)
	}
}

func TestSFTPSession_Close_RemovesFromRegistry(t *testing.T) {
	sess, cleanup := newTestSFTPPair(t)
	defer cleanup()

	id := sess.SessionID()
	if _, ok := GetSFTPSession(id); !ok {
		t.Fatalf("session %s should be registered before Close", id)
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, ok := GetSFTPSession(id); ok {
		t.Errorf("session %s should be unregistered after Close", id)
	}
}

// Sanity check: randomHex returns the requested number of bytes (hex-encoded)
// and doesn't collide across rapid calls.
func TestRandomHex_Distinct(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 100; i++ {
		s, err := randomHex(8)
		if err != nil {
			t.Fatalf("randomHex: %v", err)
		}
		if len(s) != 16 {
			t.Errorf("want 16 hex chars, got %d: %q", len(s), s)
		}
		if _, dup := seen[s]; dup {
			t.Errorf("randomHex collision: %s", s)
		}
		seen[s] = struct{}{}
	}
	// Paranoia: wall-clock check — randomHex should finish fast.
	start := time.Now()
	_, _ = randomHex(8)
	if time.Since(start) > 100*time.Millisecond {
		t.Errorf("randomHex too slow: %s", time.Since(start))
	}
}
