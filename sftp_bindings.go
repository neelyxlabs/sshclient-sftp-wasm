//go:build js && wasm

package main

import (
	"encoding/base64"
	"syscall/js"

	"github.com/neelyxlabs/sshclient-sftp-wasm/pkg/sshclient"
)

// asyncPromise runs work() on a goroutine and returns a JS Promise that
// resolves with its result or rejects with a ConnectError-serialized object
// (for typed errors) or a bare string (for everything else).
func asyncPromise(work func() (interface{}, error)) js.Value {
	promiseConstructor := js.Global().Get("Promise")
	var handler js.Func
	handler = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		defer handler.Release()
		resolve := args[0]
		reject := args[1]
		go func() {
			result, err := work()
			if err != nil {
				reject.Invoke(errorToJS(err))
				return
			}
			resolve.Invoke(js.ValueOf(result))
		}()
		return nil
	})
	return promiseConstructor.New(handler)
}

// errorToJS serializes a Go error into the most informative JS value
// available. For *sshclient.ConnectError, the shape is
// { code, message, expected?, got? } — consumer TS maps this to typed
// error classes. For any other error, a bare string is returned.
func errorToJS(err error) js.Value {
	if ce, ok := err.(*sshclient.ConnectError); ok {
		m := map[string]interface{}{
			"code":    string(ce.Code),
			"message": ce.Message,
		}
		if ce.Expected != nil {
			m["expected"] = map[string]interface{}{
				"algorithm": ce.Expected.Algorithm,
				"sha256":    ce.Expected.SHA256,
			}
		}
		if ce.Got != nil {
			m["got"] = map[string]interface{}{
				"algorithm": ce.Got.Algorithm,
				"sha256":    ce.Got.SHA256,
			}
		}
		return js.ValueOf(m)
	}
	return js.ValueOf(err.Error())
}

// parseHostKeyPin reads a { algorithm, sha256 } object from JS. Returns nil
// if the object is missing or has no sha256 field — callers treat nil as
// "no pin supplied".
func parseHostKeyPin(v js.Value) *sshclient.HostKeyPin {
	if v.Type() != js.TypeObject {
		return nil
	}
	sha := v.Get("sha256")
	if sha.Type() != js.TypeString || sha.String() == "" {
		return nil
	}
	algo := ""
	if a := v.Get("algorithm"); a.Type() == js.TypeString {
		algo = a.String()
	}
	return &sshclient.HostKeyPin{
		Algorithm: algo,
		SHA256:    sha.String(),
	}
}

// sftpOpen opens the SFTP subsystem on an existing SSH session. Returns
// { sftpSessionId } on success.
//
// JS signature: sftpOpen(sshSessionId: string): Promise<{sftpSessionId: string}>
func sftpOpen(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return promiseReject("missing ssh session ID")
	}
	sshSessionID := args[0].String()
	return asyncPromise(func() (interface{}, error) {
		client, ok := sshclient.GetClient(sshSessionID)
		if !ok {
			return nil, &sshclient.ConnectError{Code: sshclient.CodeInternal, Message: "ssh session not found: " + sshSessionID}
		}
		sess, err := client.NewSFTPSession()
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"sftpSessionId": sess.SessionID(),
		}, nil
	})
}

// sftpPut uploads data to remotePath using temp-file + atomic rename.
// Data is accepted as a base64-encoded string to avoid the Uint8Array
// marshalling cost for small payloads; callers with large blobs should
// encode in chunks (though typical HL7 ELR payloads are < 100 KB).
//
// JS signature: sftpPut(sftpSessionId: string, remotePath: string, base64Data: string): Promise<void>
func sftpPut(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return promiseReject("missing sftp session ID, remote path, or data")
	}
	sftpSessionID := args[0].String()
	remotePath := args[1].String()
	b64 := args[2].String()
	return asyncPromise(func() (interface{}, error) {
		data, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, &sshclient.ConnectError{Code: sshclient.CodeInternal, Message: "invalid base64 payload: " + err.Error()}
		}
		sess, ok := sshclient.GetSFTPSession(sftpSessionID)
		if !ok {
			return nil, &sshclient.ConnectError{Code: sshclient.CodeInternal, Message: "sftp session not found: " + sftpSessionID}
		}
		if err := sess.PutFile(remotePath, data); err != nil {
			return nil, &sshclient.ConnectError{Code: sshclient.CodeInternal, Message: err.Error()}
		}
		return nil, nil
	})
}

// sftpMkdir creates a directory (recursively). No-op if it already exists.
//
// JS signature: sftpMkdir(sftpSessionId: string, path: string): Promise<void>
func sftpMkdir(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return promiseReject("missing sftp session ID or path")
	}
	sftpSessionID := args[0].String()
	path := args[1].String()
	return asyncPromise(func() (interface{}, error) {
		sess, ok := sshclient.GetSFTPSession(sftpSessionID)
		if !ok {
			return nil, &sshclient.ConnectError{Code: sshclient.CodeInternal, Message: "sftp session not found: " + sftpSessionID}
		}
		if err := sess.MkdirAll(path); err != nil {
			return nil, &sshclient.ConnectError{Code: sshclient.CodeInternal, Message: err.Error()}
		}
		return nil, nil
	})
}

// sftpClose tears down the SFTP subsystem. The parent SSH session stays open.
//
// JS signature: sftpClose(sftpSessionId: string): Promise<void>
func sftpClose(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return promiseReject("missing sftp session ID")
	}
	sftpSessionID := args[0].String()
	return asyncPromise(func() (interface{}, error) {
		sess, ok := sshclient.GetSFTPSession(sftpSessionID)
		if !ok {
			// Closing an unknown session is not an error; make it idempotent.
			return nil, nil
		}
		if err := sess.Close(); err != nil {
			return nil, &sshclient.ConnectError{Code: sshclient.CodeInternal, Message: err.Error()}
		}
		return nil, nil
	})
}

// getServerFingerprint does a one-shot fingerprint capture: minimal handshake,
// no auth, returns { algorithm, sha256 }. For TOFU / first-run flows where a
// user needs to approve a server's key before pinning.
//
// JS signature: getServerFingerprint(options, transportId): Promise<{algorithm, sha256}>
func getServerFingerprint(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return promiseReject("missing connection options or transport ID")
	}
	options := parseConnectionOptions(args[0])
	transportID := args[1].String()
	return asyncPromise(func() (interface{}, error) {
		transport, ok := sshclient.GetTransport(transportID)
		if !ok {
			return nil, &sshclient.ConnectError{Code: sshclient.CodeTransportError, Message: "transport not found: " + transportID}
		}
		pin, err := sshclient.GetServerFingerprint(options, transport)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"algorithm": pin.Algorithm,
			"sha256":    pin.SHA256,
		}, nil
	})
}
