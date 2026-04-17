.PHONY: build clean test test-go test-ts wasm wasm-check dev release copy-wasm-support npm-publish

GOOS = js
GOARCH = wasm
GO_BUILD_FLAGS = -ldflags="-s -w"

# `make build` — default build target; compile the WASM binary.
build: wasm

# `make wasm` — compile the Go WASM binary. main.go + sftp_bindings.go are
# both `//go:build js && wasm`-tagged and compile into the WASM target.
wasm: copy-wasm-support
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(GO_BUILD_FLAGS) -o dist/sshclient.wasm main.go sftp_bindings.go
	mkdir -p public
	cp dist/sshclient.wasm public/
	cp dist/wasm_exec.js public/

copy-wasm-support:
	mkdir -p dist
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" dist/

clean:
	rm -rf dist/ public/sshclient.wasm public/wasm_exec.js

# `make test` — everything.
test: test-go test-ts

# `make test-go` — unit tests for the native (non-WASM) Go code. These
# are the definitive tests for SFTP operations and host-key pinning logic.
test-go:
	go test -race ./...

# `make test-ts` — vitest tests for the TypeScript lib wrappers.
test-ts:
	pnpm test:run

# `make wasm-check` — compile-check under js/wasm without running tests.
# Catches cases where main.go or sftp_bindings.go break the WASM build.
wasm-check:
	GOOS=js GOARCH=wasm go build -o /dev/null ./...

dev: build
	cd examples && pnpm install && pnpm run dev

release:
	goreleaser release --snapshot --clean

# Publish to npm — usually invoked via the release workflow after tests pass.
npm-publish: wasm
	pnpm run build:ts
	npm publish --access public
