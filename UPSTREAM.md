# Upstream tracking

This repository is a fork of [VerdigrisTech/sshclient-wasm](https://github.com/VerdigrisTech/sshclient-wasm) extended with SFTP support (`github.com/pkg/sftp`), mandatory host-key verification, and PPK-format detection.

## Fork point

- Upstream: https://github.com/VerdigrisTech/sshclient-wasm
- SHA at fork: `de14504f37e74aa0562b7dddf9e28a8bbf1c5c0a`
- Date: 2026-04-16

## Rebase checklist (run every ~6 months or when `x/crypto` ships a CVE)

1. `git fetch upstream`
2. `git log upstream/main --oneline --since="last rebase"` — skim for security-relevant changes.
3. `git checkout -b rebase-$(date +%Y%m%d)` and merge/rebase.
4. Resolve conflicts — primarily in `pkg/sshclient/client.go` (our host-key pinning changes) and `main.go` (our SFTP JS bindings).
5. Run `go test ./...` and the integration harness.
6. Update the "SHA at fork" above.
7. Open a PR, merge, tag a patch release.

## Security upstream watch

Subscribe to:
- https://pkg.go.dev/vuln — feed for `golang.org/x/crypto`
- https://github.com/pkg/sftp/security/advisories

## Divergence from upstream

- **SFTP support** (`pkg/sshclient/sftp.go`, SFTP bindings in `main.go`, `lib/sftp.ts`) — additive, candidate for upstream PR.
- **Mandatory host-key verification** (`ConnectWithPin`, `GetServerFingerprint`) — breaking change on the Go API. `InsecureIgnoreHostKey` is removed. Not a good fit for upstream without a backwards-compat shim.
- **PPK detection** (typed `ErrPPKNotSupported`) — additive, candidate for upstream PR.
- **Module path renamed** to `github.com/neelyxlabs/sshclient-sftp-wasm`.
- **npm package renamed** to `@neelyxlabs/sshclient-sftp-wasm`.
- **Companion bridge** — a separate repo [neelyxlabs/ws-tcp-bridge-worker](https://github.com/neelyxlabs/ws-tcp-bridge-worker) ships a Cloudflare Worker WS-TCP bridge. Not in this repo; no impact on upstream rebases.
