# Integration test harness

End-to-end test for the library + bridge pipeline:

```
Playwright → Vite-served page → @neelyxlabs/sshclient-sftp-wasm
                                        ↓ (WebSocket)
                              ws-tcp-bridge-worker (wrangler dev)
                                        ↓ (raw TCP)
                                openssh-server (docker)
```

## Prerequisites

- **Docker** (for OpenSSH server)
- **Go 1.24+** (to build the WASM binary)
- **Node 22+** + **pnpm**
- **wrangler** (`npm i -g wrangler` or use `npx`)
- The `ws-tcp-bridge-worker` repo checked out as a sibling (e.g. `../ws-tcp-bridge-worker`), OR pointed at via `BRIDGE_WORKER_DIR` env var.

## Layout

```
test/integration/
├── README.md                  (this file)
├── docker-compose.yml         (openssh-server)
├── ssh-keys/                  (pre-generated host + user keys; gitignored except README)
├── package.json               (playwright + vite)
├── vite.config.ts
├── playwright.config.ts
├── page/
│   ├── index.html             (UI for driving the library)
│   └── main.ts                (calls library, emits test signals)
└── tests/
    ├── happy-path.spec.ts
    └── host-key-mismatch.spec.ts
```

## Running locally

From the repo root:

```bash
# 1. Build the WASM binary (picked up by the Vite page via public/).
make wasm

# 2. Generate host + user keys (one-time).
./test/integration/ssh-keys/generate.sh

# 3. Start OpenSSH server in Docker.
docker compose -f test/integration/docker-compose.yml up -d

# 4. Start the bridge Worker in a separate terminal.
cd ../ws-tcp-bridge-worker        # sibling repo
echo "HMAC_SECRET=test-hmac-secret" > .dev.vars
echo "ALLOWED_DESTS=localhost:2222" >> .dev.vars
npm install
npx wrangler dev

# 5. Run Playwright tests.
cd ../sshclient-sftp-wasm/test/integration
pnpm install
pnpm exec playwright install chromium --with-deps
pnpm test
```

## What each test asserts

### `happy-path.spec.ts`
- Loads the WASM.
- Captures the fingerprint via `SSHClient.getServerFingerprint()`.
- Re-connects with the captured pin.
- Opens SFTP, `put`s a 50 KB payload to `/home/testuser/uploads/test.bin`.
- Closes.
- Asserts the file appears in the mounted Docker volume.
- Asserts NO `.tmp-` leftover files in the destination directory.

### `host-key-mismatch.spec.ts`
- Connects with a deliberately-wrong host-key pin.
- Asserts `HostKeyMismatchError` is raised BEFORE any auth attempt.
- Asserts the OpenSSH server logs contain no auth attempt for the test user
  within the test window (via `docker compose logs`).

## CI

The GitHub Action `.github/workflows/ci.yml` runs this harness on every PR to `main`. CI provisions Docker, Go, and Node; the bridge Worker is started in the same job via `wrangler dev --local`. Tests fail fast on WASM build errors so the rest of the pipeline doesn't run.

## Debugging

- Page-side console logs stream to Playwright's stdout via `page.on('console', ...)` in the test fixtures.
- Bridge logs are visible in the `wrangler dev` terminal.
- OpenSSH logs: `docker compose logs sftp`.
- Inspect the uploads directory directly: `ls -la test/integration/uploads/`.
