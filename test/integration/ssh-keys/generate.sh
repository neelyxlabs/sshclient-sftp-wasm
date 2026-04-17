#!/usr/bin/env bash
# Generates a fixed ed25519 host key for the Docker OpenSSH server.
# The key is committed so the fingerprint is stable across dev machines and CI
# — this is a TEST key only, used on a localhost-only container. Do not reuse.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

if [ -f ssh_host_ed25519_key ]; then
  echo "Host key already exists at $HERE/ssh_host_ed25519_key"
  ssh-keygen -lf ssh_host_ed25519_key.pub -E sha256
  exit 0
fi

ssh-keygen -t ed25519 -f ssh_host_ed25519_key -N "" -C "sshclient-sftp-wasm integration test host key"
chmod 600 ssh_host_ed25519_key
chmod 644 ssh_host_ed25519_key.pub

echo "Generated. Fingerprint:"
ssh-keygen -lf ssh_host_ed25519_key.pub -E sha256

echo
echo "Update tests/fixtures.ts with the fingerprint above if it changed."
