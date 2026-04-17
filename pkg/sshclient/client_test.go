package sshclient

import (
	"crypto/ed25519"
	"errors"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestLooksLikePPK(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"ppk v2", "PuTTY-User-Key-File-2: ssh-rsa\n...", true},
		{"ppk v3", "PuTTY-User-Key-File-3: ssh-ed25519\n...", true},
		{"ppk with leading whitespace", "  \r\nPuTTY-User-Key-File-2: ssh-rsa", true},
		{"openssh pem", "-----BEGIN OPENSSH PRIVATE KEY-----\n...", false},
		{"rsa pem", "-----BEGIN RSA PRIVATE KEY-----\n...", false},
		{"empty", "", false},
		{"ppk-like but not ppk", "PuTTY-File", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := looksLikePPK([]byte(c.in))
			if got != c.want {
				t.Errorf("looksLikePPK(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func makeTestPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_ = priv
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return sshPub
}

func TestMakePinnedHostKeyCallback_Match(t *testing.T) {
	key := makeTestPublicKey(t)
	pin := &HostKeyPin{
		Algorithm: key.Type(),
		SHA256:    ssh.FingerprintSHA256(key),
	}
	cb := makePinnedHostKeyCallback(pin)
	if err := cb("example.com", &net.TCPAddr{}, key); err != nil {
		t.Errorf("matching pin should succeed, got: %v", err)
	}
}

func TestMakePinnedHostKeyCallback_Mismatch(t *testing.T) {
	actualKey := makeTestPublicKey(t)
	otherKey := makeTestPublicKey(t)
	if ssh.FingerprintSHA256(actualKey) == ssh.FingerprintSHA256(otherKey) {
		t.Fatalf("expected distinct fingerprints — unlucky RNG?")
	}

	pin := &HostKeyPin{
		Algorithm: otherKey.Type(),
		SHA256:    ssh.FingerprintSHA256(otherKey),
	}
	cb := makePinnedHostKeyCallback(pin)
	err := cb("example.com", &net.TCPAddr{}, actualKey)
	if err == nil {
		t.Fatal("mismatched pin should fail")
	}

	var ce *ConnectError
	if !errors.As(err, &ce) {
		t.Fatalf("want *ConnectError, got %T: %v", err, err)
	}
	if ce.Code != CodeHostKeyMismatch {
		t.Errorf("code = %s, want %s", ce.Code, CodeHostKeyMismatch)
	}
	if ce.Expected == nil || ce.Expected.SHA256 != pin.SHA256 {
		t.Errorf("expected pin not echoed: %+v", ce.Expected)
	}
	if ce.Got == nil || ce.Got.SHA256 != ssh.FingerprintSHA256(actualKey) {
		t.Errorf("got pin not populated: %+v", ce.Got)
	}
}

func TestClassifyConnectError_Auth(t *testing.T) {
	raw := errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain")
	err := classifyConnectError(raw)
	var ce *ConnectError
	if !errors.As(err, &ce) {
		t.Fatalf("want *ConnectError, got %T: %v", err, err)
	}
	if ce.Code != CodeAuthFailed {
		t.Errorf("code = %s, want %s", ce.Code, CodeAuthFailed)
	}
}

func TestClassifyConnectError_Transport(t *testing.T) {
	raw := errors.New("dial tcp: connection refused")
	err := classifyConnectError(raw)
	var ce *ConnectError
	if !errors.As(err, &ce) {
		t.Fatalf("want *ConnectError, got %T: %v", err, err)
	}
	if ce.Code != CodeTransportError {
		t.Errorf("code = %s, want %s", ce.Code, CodeTransportError)
	}
}

func TestClassifyConnectError_PreservesTypedConnectError(t *testing.T) {
	original := &ConnectError{Code: CodeHostKeyMismatch, Message: "oops"}
	err := classifyConnectError(original)
	var ce *ConnectError
	if !errors.As(err, &ce) {
		t.Fatalf("want *ConnectError, got %T: %v", err, err)
	}
	if ce.Code != CodeHostKeyMismatch {
		t.Errorf("typed error was re-classified: %s", ce.Code)
	}
}

func TestConnect_WithoutPin_FailsEarly(t *testing.T) {
	client := New(ConnectionOptions{
		Host: "example.com",
		Port: 22,
		User: "test",
		// deliberately no HostKeyPin
	})
	_, err := client.Connect()
	if err == nil {
		t.Fatal("Connect without pin should fail")
	}
	var ce *ConnectError
	if !errors.As(err, &ce) {
		t.Fatalf("want *ConnectError, got %T: %v", err, err)
	}
	if ce.Code != CodeHostKeyPinRequired {
		t.Errorf("code = %s, want %s", ce.Code, CodeHostKeyPinRequired)
	}
}

func TestConnect_WithPPKKey_FailsEarly(t *testing.T) {
	client := New(ConnectionOptions{
		Host:       "example.com",
		Port:       22,
		User:       "test",
		PrivateKey: "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n",
		HostKeyPin: &HostKeyPin{Algorithm: "ssh-ed25519", SHA256: "SHA256:abc"},
	})
	_, err := client.Connect()
	if err == nil {
		t.Fatal("Connect with PPK key should fail")
	}
	var ce *ConnectError
	if !errors.As(err, &ce) {
		t.Fatalf("want *ConnectError, got %T: %v", err, err)
	}
	if ce.Code != CodePPKNotSupported {
		t.Errorf("code = %s, want %s", ce.Code, CodePPKNotSupported)
	}
	// Message should point the user at the conversion command so they can
	// self-serve instead of filing a support ticket.
	if !strings.Contains(ce.Message, "puttygen") {
		t.Errorf("PPK error message missing `puttygen` guidance: %q", ce.Message)
	}
}
