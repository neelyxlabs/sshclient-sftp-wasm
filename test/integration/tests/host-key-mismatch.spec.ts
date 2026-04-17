import { test, expect } from "@playwright/test";

const BRIDGE_SECRET = process.env.BRIDGE_HMAC_SECRET ?? "test-hmac-secret";
const BRIDGE_BASE = process.env.BRIDGE_URL ?? "ws://localhost:8787";
const DEST = "localhost:2222";

async function signedUrl(dest: string, ttlSeconds = 300): Promise<string> {
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(BRIDGE_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${dest}|${exp}`)
  );
  const hex = Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `${BRIDGE_BASE}/?dest=${encodeURIComponent(dest)}&exp=${exp}&sig=${hex}`;
}

test("wrong pin → HostKeyMismatchError, no auth attempted", async ({
  page,
}) => {
  page.on("console", (msg) => console.log(`[page] ${msg.text()}`));

  const url = await signedUrl(DEST);
  await page.goto("/");

  const result = await page.evaluate(
    async (cfg) => window.__runTest(cfg),
    {
      scenario: "host-key-mismatch",
      bridgeUrl: url,
      host: "localhost",
      port: 2222,
      user: "testuser",
      password: "testpass",
      // Intentional wrong pin.
      hostKeyPin: {
        algorithm: "ssh-ed25519",
        sha256:
          "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      },
    }
  );

  expect(result.ok).toBe(true);
  expect(result.errorName).toBe("HostKeyMismatchError");
  expect(result.errorCode).toBe("host-key-mismatch");
});

test("PPK key → PPKFormatError before network", async ({ page }) => {
  const url = await signedUrl(DEST);
  await page.goto("/");

  const result = await page.evaluate(
    async (cfg) => window.__runTest(cfg),
    {
      scenario: "ppk-early-reject",
      bridgeUrl: url,
      host: "localhost",
      port: 2222,
      user: "testuser",
      password: "",
      privateKey:
        "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n...",
      hostKeyPin: {
        algorithm: "ssh-ed25519",
        sha256: "SHA256:placeholder",
      },
    }
  );

  expect(result.ok).toBe(true);
  expect(result.errorName).toBe("PPKFormatError");
  expect(result.errorCode).toBe("ppk-not-supported");
});
