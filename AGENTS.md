# Contributing guide for humans and agents

This file is the contract for every contribution to this repository, whether it comes from a
person or an AI agent. Automated triage evaluates pull requests and issues against it. Read
it before opening anything.

## Ground rules

1. **One PR, one topic.** Keep changes focused. Do not bundle unrelated fixes.
2. **Link an issue.** Non-trivial PRs must reference an open issue describing the problem.
   Discuss approach there first for anything large.
3. **No low-quality / unreviewed AI output.** AI assistance is fine; unread, untested, or
   speculative "slop" is not. You are responsible for every line you submit.
4. **It must pass CI.** Build, vet, race tests, lint, and vulnerability checks all green.
5. **Be respectful.** See `CODE_OF_CONDUCT.md`.

## Project shape

- Go module `github.com/ionalpha/flynn-extensions`. It holds out-of-process capability
  extensions for [flynn](https://github.com/ionalpha/flynn).
- `mcpserver/` is the shared harness: an MCP stdio tool-server. An extension registers
  `Tool`s and calls `Serve`; the harness handles the protocol.
- Each extension is its own `cmd/<name>/` binary. It exposes tools over MCP; flynn launches
  it as a sandboxed subprocess and mounts its tools behind a capability grant.

## Security model (non-negotiable)

Extensions are designed to be at least as safe as in-process code. An extension:

- **never holds a privileged secret.** For a signing capability it builds an unsigned
  request; a vault/hardware-backed signer in flynn core signs it.
- runs **sandboxed and egress-locked** (no ambient filesystem/vault access; network egress is
  allow-listed, intersected with the operator grant).
- has each tool **governed at flynn's dispatch waist**: capability-gated, budget/brake
  bounded, recorded on the signed replayable spine.
- everything written to **stdout is protocol**; log only to **stderr**.

## Local development

CI is the shared [ionalpha/go-ci](https://github.com/ionalpha/go-ci) reusable workflow,
so a green run there is the bar. To match it locally:

```sh
go build ./...
go vet ./...
go test -race ./...
# lint with the SHARED config (clone go-ci next to this repo, or point --config at it):
golangci-lint run --config=../go-ci/.golangci.yml
```

Internal tooling (any local `CLAUDE.md`, `.claude/`) is git-ignored and must never be
committed.

## Standards

- **Format:** `gofumpt` + `goimports` (local prefix `github.com/ionalpha`).
- **Lint:** `golangci-lint` must pass against go-ci's shared `.golangci.yml`.
- **Tests:** add tests with behavior changes; prefer table-driven and property-based tests.
  The race detector must stay clean.
- **Commits:** Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, ...). Sign off with
  DCO (`git commit -s`).
- **Security:** never commit secrets. Report vulnerabilities privately (see `SECURITY.md`).
