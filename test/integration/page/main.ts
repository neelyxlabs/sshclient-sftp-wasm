import {
  SSHClient,
  WebSocketTransport,
  HostKeyPin,
  HostKeyMismatchError,
  PPKFormatError,
  HostKeyPinRequiredError,
} from "@neelyxlabs/sshclient-sftp-wasm";

declare global {
  interface Window {
    __runTest: (cfg: TestConfig) => Promise<TestResult>;
    __testResult: TestResult | null;
  }
}

interface TestConfig {
  scenario:
    | "happy-path"
    | "host-key-mismatch"
    | "capture-fingerprint"
    | "ppk-early-reject";
  bridgeUrl: string; // e.g. "ws://localhost:8787/?dest=localhost:2222&exp=...&sig=..."
  host: string;
  port: number;
  user: string;
  password: string;
  // For host-key-mismatch: override with a wrong pin. For happy-path: use the real pin.
  hostKeyPin?: HostKeyPin;
  privateKey?: string; // for ppk-early-reject
  remotePath?: string;
  payloadSize?: number;
}

interface TestResult {
  ok: boolean;
  scenario: string;
  errorName?: string;
  errorCode?: string;
  fingerprint?: HostKeyPin;
  bytesSent?: number;
  remotePath?: string;
  durationMs?: number;
  message?: string;
}

const logEl = document.getElementById("log")!;
function log(msg: string): void {
  logEl.textContent += "\n" + msg;
}

async function ensureInit(): Promise<void> {
  // WASM binary is served from publicDir → /sshclient.wasm
  await SSHClient.initialize({ autoDetect: true, cacheBusting: false });
}

function generatePayload(bytes: number): Uint8Array {
  const buf = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i++) buf[i] = i & 0xff;
  return buf;
}

window.__testResult = null;

window.__runTest = async (cfg: TestConfig): Promise<TestResult> => {
  const start = performance.now();
  const result: TestResult = { ok: false, scenario: cfg.scenario };
  try {
    log(`→ scenario: ${cfg.scenario}`);
    await ensureInit();

    if (cfg.scenario === "ppk-early-reject") {
      // Should fail client-side before any transport work.
      const transport = new WebSocketTransport("t-ppk", cfg.bridgeUrl);
      try {
        await SSHClient.connect(
          {
            host: cfg.host,
            port: cfg.port,
            user: cfg.user,
            privateKey: cfg.privateKey ?? "PuTTY-User-Key-File-3: ssh-ed25519\n...",
            hostKeyPin: cfg.hostKeyPin,
          },
          transport
        );
        result.message = "expected PPKFormatError, got success";
      } catch (e) {
        const err = e as Error & { code?: string };
        result.errorName = err.name;
        result.errorCode = err.code;
        result.ok = err instanceof PPKFormatError;
      }
      return finalize(result, start);
    }

    if (cfg.scenario === "capture-fingerprint") {
      const transport = new WebSocketTransport("t-fp", cfg.bridgeUrl);
      const pin = await SSHClient.getServerFingerprint(
        { host: cfg.host, port: cfg.port, user: cfg.user },
        transport
      );
      result.fingerprint = pin;
      result.ok = !!pin.sha256 && pin.sha256.startsWith("SHA256:");
      return finalize(result, start);
    }

    if (cfg.scenario === "host-key-mismatch") {
      const transport = new WebSocketTransport("t-bad", cfg.bridgeUrl);
      try {
        await SSHClient.connect(
          {
            host: cfg.host,
            port: cfg.port,
            user: cfg.user,
            password: cfg.password,
            hostKeyPin:
              cfg.hostKeyPin ?? {
                algorithm: "ssh-ed25519",
                sha256: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
              },
          },
          transport
        );
        result.message = "expected HostKeyMismatchError, got success";
      } catch (e) {
        const err = e as Error & { code?: string };
        result.errorName = err.name;
        result.errorCode = err.code;
        result.ok = err instanceof HostKeyMismatchError;
      }
      return finalize(result, start);
    }

    // happy-path
    if (!cfg.hostKeyPin) {
      throw new Error("happy-path requires hostKeyPin");
    }
    const transport = new WebSocketTransport("t-happy", cfg.bridgeUrl);
    const session = await SSHClient.connect(
      {
        host: cfg.host,
        port: cfg.port,
        user: cfg.user,
        password: cfg.password,
        hostKeyPin: cfg.hostKeyPin,
      },
      transport
    );
    const sftp = await session.sftpOpen();

    const payload = generatePayload(cfg.payloadSize ?? 50_000);
    const remotePath = cfg.remotePath ?? "/home/testuser/uploads/test.bin";
    await sftp.put(remotePath, payload);
    await sftp.close();
    await session.disconnect();

    result.bytesSent = payload.length;
    result.remotePath = remotePath;
    result.ok = true;
    return finalize(result, start);
  } catch (e) {
    const err = e as Error & { code?: string };
    result.errorName = err.name;
    result.errorCode = err.code;
    result.message = err.message;
    return finalize(result, start);
  }
};

function finalize(r: TestResult, start: number): TestResult {
  r.durationMs = Math.round(performance.now() - start);
  window.__testResult = r;
  log(`← ${JSON.stringify(r)}`);
  return r;
}

// Silence the "HostKeyPinRequiredError not referenced" warning — it's part of
// the imported API surface and we want the import to verify the name is wired.
void HostKeyPinRequiredError;
