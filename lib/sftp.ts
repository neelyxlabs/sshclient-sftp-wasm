import { wrapSSHError } from "./errors";

/**
 * SFTPHandle wraps a server-side SFTP subsystem opened over an existing
 * SSH session. Obtain one via `SSHSession.sftpOpen()`.
 *
 * Lifetime: closing the handle tears down only the SFTP subsystem; the
 * underlying SSH session remains open until `SSHSession.disconnect()`.
 *
 * All methods reject with a typed error (see `./errors`) on failure.
 */
export class SFTPHandle {
  public readonly sftpSessionId: string;
  private readonly wasmInstance: any;
  private closed = false;

  constructor(wasmInstance: any, sftpSessionId: string) {
    this.wasmInstance = wasmInstance;
    this.sftpSessionId = sftpSessionId;
  }

  /**
   * Upload `bytes` to `remotePath` on the server. Uses a temp-file plus
   * atomic rename, so partial uploads are never observable under the
   * target filename.
   */
  async put(remotePath: string, bytes: Uint8Array): Promise<void> {
    this.ensureOpen();
    const b64 = toBase64(bytes);
    try {
      await this.wasmInstance.sftpPut(this.sftpSessionId, remotePath, b64);
    } catch (e) {
      throw wrapSSHError(e);
    }
  }

  /**
   * Create `path` (recursively). No-op if it already exists.
   */
  async mkdir(path: string): Promise<void> {
    this.ensureOpen();
    try {
      await this.wasmInstance.sftpMkdir(this.sftpSessionId, path);
    } catch (e) {
      throw wrapSSHError(e);
    }
  }

  /**
   * Close the SFTP subsystem. Idempotent.
   */
  async close(): Promise<void> {
    if (this.closed) return;
    try {
      await this.wasmInstance.sftpClose(this.sftpSessionId);
    } catch (e) {
      throw wrapSSHError(e);
    } finally {
      this.closed = true;
    }
  }

  private ensureOpen(): void {
    if (this.closed) {
      throw new Error(
        `SFTPHandle ${this.sftpSessionId} has been closed`
      );
    }
  }
}

// Base64-encode a Uint8Array. Chunked at 32 KB to avoid
// "Maximum call stack exceeded" on `String.fromCharCode(...bytes)`
// for large payloads.
function toBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const end = Math.min(i + chunkSize, bytes.length);
    binary += String.fromCharCode.apply(
      null,
      Array.from(bytes.subarray(i, end))
    );
  }
  return btoa(binary);
}
