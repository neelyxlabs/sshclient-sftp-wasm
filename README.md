# sshclient-sftp-wasm

Browser SSH + SFTP via WebAssembly. Forked from [VerdigrisTech/sshclient-wasm](https://github.com/VerdigrisTech/sshclient-wasm) and extended with SFTP support, mandatory host-key pinning, and typed errors.

Built on Go's [`golang.org/x/crypto/ssh`](https://pkg.go.dev/golang.org/x/crypto/ssh) and [`github.com/pkg/sftp`](https://github.com/pkg/sftp), compiled to WebAssembly.

## What's different from upstream

- **SFTP** — `sftpOpen()` returns a handle with `put()`, `mkdir()`, `close()`. File uploads use temp-file + atomic rename to prevent partial-upload observation.
- **Mandatory host-key pinning** — `InsecureIgnoreHostKey` is removed. Every `connect()` requires a `hostKeyPin` with the server's SHA256 fingerprint. Use `getServerFingerprint()` for first-run TOFU flows.
- **Typed errors** — `HostKeyMismatchError`, `PPKFormatError`, `AuthFailedError`, `TransportError`, etc. Each has a stable `.code` string for dispatch without `instanceof`.
- **PuTTY key detection** — `.ppk` private keys are caught before any network I/O with a `PPKFormatError` that includes conversion instructions.

See [`UPSTREAM.md`](./UPSTREAM.md) for the fork SHA and divergence details.

## Browsers can't do raw TCP

This library runs SSH/SFTP entirely in the browser, but browsers cannot open TCP sockets. You need a WebSocket-to-TCP bridge between the browser and the SSH server. The library's `WebSocketTransport` points at a bridge URL.

We maintain a companion bridge: **[neelyxlabs/ws-tcp-bridge-worker](https://github.com/neelyxlabs/ws-tcp-bridge-worker)** — a Cloudflare Worker that pipes WebSocket bytes to any TCP destination. But any WS-to-TCP proxy works (chisel, a custom Node proxy, AWS IoT Secure Tunneling).

```
Browser (WASM SSH/SFTP) ──WebSocket──> Bridge ──TCP──> SFTP server
```

The bridge sees only SSH ciphertext. Credentials stay in the browser.

## Installation

```bash
npm install github:neelyxlabs/sshclient-sftp-wasm
```

Copy the WASM binary and Go runtime to your `public/` directory:

```bash
cp node_modules/@neelyxlabs/sshclient-sftp-wasm/dist/sshclient.wasm public/
cp node_modules/@neelyxlabs/sshclient-sftp-wasm/dist/wasm_exec.js public/
```

## SFTP upload example

```typescript
import { SSHClient, WebSocketTransport } from "@neelyxlabs/sshclient-sftp-wasm";

// Load the WASM binary (once per page load)
await SSHClient.initialize();

// Point at your WS-TCP bridge
const transport = new WebSocketTransport("t1", "wss://your-bridge.example.com/?dest=sftp.example.com:22&token=...");

// Connect with a pinned host key (required)
const session = await SSHClient.connect(
  {
    host: "sftp.example.com",
    port: 22,
    user: "elr-upload",
    password: "secret",
    hostKeyPin: {
      algorithm: "ssh-ed25519",
      sha256: "SHA256:abcdef1234567890...",
    },
  },
  transport
);

// Upload a file via SFTP
const sftp = await session.sftpOpen();
await sftp.mkdir("/inbound/elr");
await sftp.put("/inbound/elr/message.hl7", new TextEncoder().encode("MSH|^~\\&|..."));
await sftp.close();

await session.disconnect();
```

## Host-key pinning

Every `connect()` call requires a `hostKeyPin`. If the server's key doesn't match, the library throws `HostKeyMismatchError` before any credentials are sent.

For first-run setup, capture the server's fingerprint without authenticating:

```typescript
const transport = new WebSocketTransport("fp", "wss://bridge/?dest=sftp.example.com:22&token=...");
const pin = await SSHClient.getServerFingerprint(
  { host: "sftp.example.com", port: 22, user: "anyone" },
  transport
);
// pin = { algorithm: "ssh-ed25519", sha256: "SHA256:abc..." }

// Verify this matches `ssh-keyscan -t ed25519 sftp.example.com` output,
// then store it (database, config file, FHIR extension, localStorage — your choice).
```

On subsequent connections, pass the stored pin:

```typescript
const session = await SSHClient.connect(
  { host, port, user, password, hostKeyPin: storedPin },
  transport
);
```

## Error handling

All errors thrown by `connect()`, `getServerFingerprint()`, and SFTP methods have a `.code` string for reliable dispatch:

```typescript
import {
  HostKeyMismatchError,
  HostKeyPinRequiredError,
  PPKFormatError,
  AuthFailedError,
  TransportError,
} from "@neelyxlabs/sshclient-sftp-wasm";

try {
  const session = await SSHClient.connect(opts, transport);
  const sftp = await session.sftpOpen();
  await sftp.put(path, data);
  await sftp.close();
  await session.disconnect();
} catch (e) {
  switch ((e as any).code) {
    case "host-key-pin-required":
      // Forgot to pass hostKeyPin
      break;
    case "host-key-mismatch":
      // Server key changed — possible MITM or legitimate rotation.
      // e.expected and e.got contain the pins for display.
      break;
    case "ppk-not-supported":
      // User pasted a PuTTY .ppk key. Message includes conversion instructions.
      break;
    case "auth-failed":
      // Wrong password or key
      break;
    case "transport-error":
      // Bridge unreachable, WebSocket failed, TCP connection refused
      break;
  }
}
```

## Interactive SSH (non-SFTP)

The upstream interactive-shell API still works:

```typescript
const session = await SSHClient.connect(
  { host, port, user, password, hostKeyPin: pin },
  transport,
  {
    onPacketReceive: (data, metadata) => {
      terminal.write(new TextDecoder().decode(data));
    },
    onStateChange: (state) => console.log("SSH state:", state),
  }
);

await session.send(new TextEncoder().encode("ls -la\n"));
await session.disconnect();
```

## API surface

```typescript
// Initialization
SSHClient.initialize(options?: InitializationOptions): Promise<void>

// Connection (hostKeyPin is REQUIRED)
SSHClient.connect(options: ConnectionOptions, transport: Transport, callbacks?: SSHClientCallbacks): Promise<SSHSession>

// Fingerprint capture (no auth, for TOFU)
SSHClient.getServerFingerprint(options: ConnectionOptions, transport: Transport): Promise<HostKeyPin>

// Session
SSHSession.send(data: Uint8Array): Promise<void>
SSHSession.disconnect(): Promise<void>
SSHSession.resizeTerminal(cols: number, rows: number): Promise<void>
SSHSession.sftpOpen(): Promise<SFTPHandle>

// SFTP
SFTPHandle.put(remotePath: string, bytes: Uint8Array): Promise<void>
SFTPHandle.mkdir(path: string): Promise<void>
SFTPHandle.close(): Promise<void>

// Transports
WebSocketTransport(id: string, url: string, protocols?: string[])
CustomTransport(id: string, connectImpl?, disconnectImpl?, sendImpl?)
SecureTunnelTransport(id: string, config: SecureTunnelConfig)  // AWS IoT

// Types
interface HostKeyPin { algorithm: string; sha256: string }
interface ConnectionOptions {
  host: string; port: number; user: string;
  password?: string; privateKey?: string;
  timeout?: number; hostKeyPin?: HostKeyPin;  // required for connect()
}

// Errors (all have .code: string)
HostKeyPinRequiredError   // code: "host-key-pin-required"
HostKeyMismatchError      // code: "host-key-mismatch", .expected, .got
PPKFormatError            // code: "ppk-not-supported"
InvalidPrivateKeyError    // code: "invalid-private-key"
AuthFailedError           // code: "auth-failed"
TransportError            // code: "transport-error"
InternalSSHError          // code: "internal"
```

## Building from source

Prerequisites: Go 1.24+, Node 22+, pnpm 10+.

```bash
git clone https://github.com/neelyxlabs/sshclient-sftp-wasm.git
cd sshclient-sftp-wasm

go mod download
pnpm install

# Run Go unit tests
make test-go

# Build the WASM binary (outputs to dist/ and public/)
make wasm

# Build the TypeScript wrapper (outputs to dist/)
pnpm run build:ts

# Compile-check WASM target without building
make wasm-check
```

The WASM binary is ~6.8 MB uncompressed (~1.9 MB gzipped).

## COEP/COOP headers

**Not required.** Go's `js/wasm` target is single-threaded and does not use `SharedArrayBuffer`. Do not add `Cross-Origin-Embedder-Policy` or `Cross-Origin-Opener-Policy` headers — they will break cross-origin resources from services like Medplum, Google Sign-In, and Sentry.

## License

BSD-3-Clause. See [LICENSE.md](./LICENSE.md).
