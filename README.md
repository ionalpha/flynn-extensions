# flynn-extensions

Out-of-process capability extensions for [flynn](https://github.com/ionalpha/flynn).

Comprehensive capabilities (token operations, and more over time) ship here as **separate,
sandboxed binaries** rather than being compiled into flynn's core. A user runs only the main
`flynn` binary and enables an extension from it; flynn launches the extension as a
subprocess, speaks the Model Context Protocol (MCP) to it, and mounts its tools behind the
capability gate. Core stays lean and free of any one extension's dependencies, and each
extension is isolated, independently released, and independently reviewed.

## Why out-of-process

It is more secure than compiling capabilities into the agent, not less:

- **The extension never holds privileged secrets.** For signing capabilities (e.g. token),
  the extension builds an unsigned request and a vault/hardware-backed signer in trusted core
  signs it. A compromised extension cannot exfiltrate a key it never had.
- **Sandboxed + egress-locked.** An extension process runs in flynn's containment ladder with
  no ambient filesystem/vault access, and its network egress is allow-listed (intersected
  with the operator grant), not whatever the extension asks for.
- **Governed like any tool.** Each mounted tool crosses the same dispatch waist: capability
  gated (default-deny), budget/brake-bounded, and recorded on the signed, replayable spine.
- **Signed-only code.** Released extensions are cosign-verified against a pinned key; dev mode
  is unsigned, local, and opt-in only.

## Layout

| Path | Purpose |
|------|---------|
| `mcpserver/` | The shared harness: an MCP stdio server. An extension registers `Tool`s and calls `Serve`; the harness handles all protocol framing. |
| `cmd/example/` | A minimal extension (one echo tool) that shows the shape. Copy it to start a new extension. |

Each extension is its own `cmd/<name>/` binary. CI builds every command; releases publish
signed per-OS/arch binaries per extension.

## Writing an extension

```go
s := mcpserver.New("my-extension", version)
s.Register(mcpserver.Tool{
    Name:        "my_tool",
    Description: "What it does.",
    InputSchema: json.RawMessage(`{"type":"object","properties":{...}}`),
    Handler: func(ctx context.Context, args json.RawMessage) (string, error) { ... },
})
s.Serve(context.Background(), os.Stdin, os.Stdout)
```

Everything the extension writes to **stdout is protocol**; log to **stderr** only.

## Dev workflow

Build your extension binary and point a dev flynn at it (no release, no signing) to iterate
locally. flynn refuses to run an unsigned binary outside its explicit dev mode, so a dev link
is only ever honoured when dev mode is turned on.

## Releases

A tag (`v*`) publishes a GitHub release with one archive per extension for every supported
platform (Linux, macOS, and Windows on amd64 and arm64), a `checksums.txt` over them, a
detached cosign signature and certificate for that checksum file, an SBOM per archive, and a
build-provenance attestation. Signing is keyless (Sigstore/OIDC), so there is no long-lived
key to manage: a downloader verifies the checksums, and so every artifact they cover, against
the release workflow's identity.

Verify a download:

```
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github.com/ionalpha/flynn-extensions' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --check --ignore-missing checksums.txt
gh attestation verify <archive> --repo ionalpha/flynn-extensions
```

flynn does this verification for you when it installs a released extension; the commands
above are for verifying a manual download.

## Standards

CI runs via the shared [ionalpha/go-ci](https://github.com/ionalpha/go-ci) reusable
workflow (gofumpt/goimports, a strict golangci-lint set, race tests on Linux/macOS/Windows,
`govulncheck`, and a full-history secret scan). The same bar as flynn core, defined once.
Releases are built and signed by the pinned `release` workflow.

## Status

Bootstrapping. This drop is the MCP-server harness, the example extension, the CI wiring, and
the signed release pipeline. The token extension and the flynn-side mount, enable, and disable
machinery follow.
