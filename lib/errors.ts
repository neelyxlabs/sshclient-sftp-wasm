/**
 * Typed errors surfaced by SSHClient.connect(), getServerFingerprint(),
 * and the SFTP* methods. Each class has a stable `name` and `code` so
 * callers can discriminate without `instanceof` (which breaks across
 * module-boundary duplication):
 *
 *   try { ... } catch (e) {
 *     if ((e as any)?.code === 'host-key-mismatch') { ... }
 *   }
 */

export interface HostKeyPin {
  algorithm: string;
  sha256: string;
}

export type SSHErrorCode =
  | "host-key-pin-required"
  | "host-key-mismatch"
  | "ppk-not-supported"
  | "invalid-private-key"
  | "auth-failed"
  | "transport-error"
  | "internal";

abstract class SSHError extends Error {
  abstract readonly code: SSHErrorCode;
}

export class HostKeyPinRequiredError extends SSHError {
  readonly name = "HostKeyPinRequiredError";
  readonly code = "host-key-pin-required" as const;
}

export class HostKeyMismatchError extends SSHError {
  readonly name = "HostKeyMismatchError";
  readonly code = "host-key-mismatch" as const;
  /** The pin the caller supplied. */
  readonly expected?: HostKeyPin;
  /** The key the server actually presented. Surface this to an operator so
   * they can inspect whether a legitimate rotation happened. */
  readonly got?: HostKeyPin;

  constructor(
    message: string,
    opts?: { expected?: HostKeyPin; got?: HostKeyPin }
  ) {
    super(message);
    this.expected = opts?.expected;
    this.got = opts?.got;
  }
}

export class PPKFormatError extends SSHError {
  readonly name = "PPKFormatError";
  readonly code = "ppk-not-supported" as const;
}

export class InvalidPrivateKeyError extends SSHError {
  readonly name = "InvalidPrivateKeyError";
  readonly code = "invalid-private-key" as const;
}

export class AuthFailedError extends SSHError {
  readonly name = "AuthFailedError";
  readonly code = "auth-failed" as const;
}

export class TransportError extends SSHError {
  readonly name = "TransportError";
  readonly code = "transport-error" as const;
}

export class InternalSSHError extends SSHError {
  readonly name = "InternalSSHError";
  readonly code = "internal" as const;
}

/**
 * Convert an unknown rejection value from the WASM bridge into the
 * appropriate typed error. The WASM side sends either:
 *   - a bare string (legacy / unclassified errors)
 *   - { code, message, expected?, got? }  (ConnectError serialization)
 */
export function wrapSSHError(raw: unknown): Error {
  if (raw instanceof Error) return raw;

  if (typeof raw === "string") {
    return new InternalSSHError(raw);
  }

  if (raw && typeof raw === "object") {
    const r = raw as {
      code?: string;
      message?: string;
      expected?: HostKeyPin;
      got?: HostKeyPin;
    };
    const msg = r.message ?? String(r.code ?? "unknown");
    switch (r.code) {
      case "host-key-pin-required":
        return new HostKeyPinRequiredError(msg);
      case "host-key-mismatch":
        return new HostKeyMismatchError(msg, {
          expected: r.expected,
          got: r.got,
        });
      case "ppk-not-supported":
        return new PPKFormatError(msg);
      case "invalid-private-key":
        return new InvalidPrivateKeyError(msg);
      case "auth-failed":
        return new AuthFailedError(msg);
      case "transport-error":
        return new TransportError(msg);
      default:
        return new InternalSSHError(msg);
    }
  }

  return new InternalSSHError(String(raw));
}
