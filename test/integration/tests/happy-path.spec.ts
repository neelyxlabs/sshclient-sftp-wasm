import { test, expect } from "@playwright/test";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";

const BRIDGE_SECRET = process.env.BRIDGE_HMAC_SECRET ?? "test-hmac-secret";
const BRIDGE_BASE = process.env.BRIDGE_URL ?? "ws://localhost:8787";
const DEST = "localhost:2222";
const UPLOADS_DIR = resolve(__dirname, "..", "uploads");
const HOST_KEY_PUB = resolve(__dirname, "..", "ssh-keys", "ssh_host_ed25519_key.pub");

function getHostKeyFingerprint(): string {
  const out = spawnSync("ssh-keygen", ["-lf", HOST_KEY_PUB, "-E", "sha256"], {
    encoding: "utf8",
  });
  if (out.status !== 0) {
    throw new Error(`ssh-keygen failed: ${out.stderr}`);
  }
  // Output: "256 SHA256:abc... sshclient-sftp-wasm integration test host key (ED25519)"
  const m = /SHA256:\S+/.exec(out.stdout);
  if (!m) throw new Error(`fingerprint not found in: ${out.stdout}`);
  return m[0];
}

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

test("happy path — SFTP PUT completes, file appears, no temp leftover", async ({
  page,
}) => {
  page.on("console", (msg) => console.log(`[page] ${msg.text()}`));

  const fingerprint = getHostKeyFingerprint();
  const url = await signedUrl(DEST);

  await page.goto("/");

  const result = await page.evaluate(
    async (cfg) => {
      return await window.__runTest(cfg);
    },
    {
      scenario: "happy-path",
      bridgeUrl: url,
      host: "localhost",
      port: 2222,
      user: "testuser",
      password: "testpass",
      hostKeyPin: { algorithm: "ssh-ed25519", sha256: fingerprint },
      remotePath: "/home/testuser/uploads/happy.bin",
      payloadSize: 50_000,
    }
  );

  expect(result.ok, `scenario failed: ${JSON.stringify(result)}`).toBe(true);
  expect(result.bytesSent).toBe(50_000);

  // Verify file appeared in the mounted Docker volume.
  const target = resolve(UPLOADS_DIR, "happy.bin");
  expect(existsSync(target), `expected file at ${target}`).toBe(true);
  const bytes = readFileSync(target);
  expect(bytes.length).toBe(50_000);
  expect(bytes[0]).toBe(0);
  expect(bytes[255]).toBe(255);

  // Verify no .tmp-* leftover.
  const leftovers = readdirSync(UPLOADS_DIR).filter((f) =>
    f.includes(".tmp-")
  );
  expect(leftovers).toEqual([]);
});

test("capture-fingerprint returns the known host key", async ({ page }) => {
  const url = await signedUrl(DEST);
  const expected = getHostKeyFingerprint();

  await page.goto("/");
  const result = await page.evaluate(
    async (cfg) => window.__runTest(cfg),
    {
      scenario: "capture-fingerprint",
      bridgeUrl: url,
      host: "localhost",
      port: 2222,
      user: "testuser",
      password: "",
    }
  );

  expect(result.ok).toBe(true);
  expect(result.fingerprint?.sha256).toBe(expected);
  expect(result.fingerprint?.algorithm).toBe("ssh-ed25519");
});
