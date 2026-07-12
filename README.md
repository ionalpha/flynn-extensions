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
- **The extension never holds the network either.** An extension that needs to reach a service
  does not get egress; it hands the request bytes to core, which sends them to the endpoint the
  OPERATOR configured and returns the response. The extension names no destination and cannot
  influence one, so there is nowhere for it to exfiltrate to and no internal service it can
  reach. The token extension works this way: it runs with egress fully denied, on every platform
  (including Windows, where per-host egress filtering does not exist, so an extension that
  needed egress could not be launched at all).
- **Sandboxed + egress-locked.** An extension process runs in flynn's containment ladder with
  no ambient filesystem/vault access, and its network egress is allow-listed (intersected
  with the operator grant), not whatever the extension asks for. Deny-by-default: an extension
  that requests nothing reaches nothing.
- **Governed like any tool.** Each mounted tool crosses the same dispatch waist: capability
  gated (default-deny), budget/brake-bounded, and recorded on the signed, replayable spine.
- **Signed-only code.** Released extensions are cosign-verified against a pinned key; dev mode
  is unsigned, local, and opt-in only.

## Layout

| Path | Purpose |
|------|---------|
| `mcpserver/` | The shared harness: an MCP stdio server. An extension registers `Tool`s and calls `Serve`; the harness handles all protocol framing. |
| `cmd/example/` | A minimal extension (one echo tool) that shows the shape. Copy it to start a new extension. |

Each extension is its own `cmd/<name>/` binary, declared in [`.release.yaml`](.release.yaml)
and released on its own timeline. CI builds every command and fails if one is not declared,
so an extension cannot ship unversioned or unsigned.

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

Each extension is released on its own timeline. The tag names it:

```
token/v0.1.0      releases the token extension, and nothing else
example/v0.2.0    releases the example extension, and nothing else
```

An extension that has not changed never gets a new version because a sibling did, and a host
that pinned one does not have to re-verify the others.

A tag publishes a GitHub release holding, for that one extension: an archive per platform
(Linux, macOS and Windows, on amd64 and arm64), an SBOM per archive, a `checksums.txt` over
all of them, a detached cosign signature and certificate for that checksum file, and a
build-provenance attestation.

Archives are reproducible: two builds of the same commit are byte-identical, so anyone can
rebuild a tag and confirm the digests the signature covers are the ones this source actually
produces. Signing is keyless (Sigstore/OIDC), so there is no long-lived key to manage.

Verify a download. Every release's notes carry this command with the exact identity that
signed it; the signing identity is the **reusable release workflow** in `ionalpha/go-ci`,
which is what Sigstore binds a reusable workflow's signature to:

```sh
cosign verify-blob checksums.txt \
  --signature checksums.txt.sig \
  --certificate checksums.txt.pem \
  --certificate-identity-regexp '^https://github\.com/ionalpha/go-ci/\.github/workflows/monorepo-release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

sha256sum --check --ignore-missing checksums.txt
gh attestation verify <archive> --repo ionalpha/flynn-extensions
```

flynn does this verification for you when it installs a released extension; the commands above
are for verifying a manual download.

## Standards

CI runs via the shared [ionalpha/go-ci](https://github.com/ionalpha/go-ci) reusable
workflow (gofumpt/goimports, a strict golangci-lint set, race tests on Linux/macOS/Windows,
`govulncheck`, and a full-history secret scan). The same bar as flynn core, defined once.
Releases are built and signed by the shared `monorepo-release` workflow in that same repo,
which reads `.release.yaml` and scopes each extension by its real import graph: a fix to a
shared package appears in the changelog of every extension that imports it, and no others.

Two tracked hooks (`.githooks/`) guard who a change is recorded as. `dev/authorcheck` refuses a
commit whose author is not the pinned identity, and `dev/pushcheck` refuses a push that would
not go through the pinned SSH host, because git identity and SSH identity are different things:
a correctly-authored commit pushed over the wrong key is still attributed to that key's account
by GitHub. Both are unset by default, so an outside contributor commits under their own name and
pushes to their own fork, as they should.

## Status

Bootstrapping. This drop is the MCP-server harness, the example extension, the CI wiring, and
the signed release pipeline. The token extension and the flynn-side mount, enable, and disable
machinery follow.
