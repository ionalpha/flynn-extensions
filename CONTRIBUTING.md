# Contributing

Thanks for your interest in flynn-extensions. Please read [`AGENTS.md`](AGENTS.md) first; it
is the canonical contribution contract (and what automated triage checks against).

## Quick start

1. Open or find an issue describing the change.
2. Fork, branch, and make a focused change.
3. Make it green locally before opening a PR:
   ```sh
   go build ./... && go vet ./... && go test -race ./...
   golangci-lint run --config=../flynn-ci/.golangci.yml
   ```
   This mirrors the shared [ionalpha/flynn-ci](https://github.com/ionalpha/flynn-ci) workflow
   that CI runs.
4. Open a pull request that links the issue and follows Conventional Commits.
5. Sign your commits off with DCO: `git commit -s`.
6. Sign the Contributor License Agreement (one-time, handled by the CLA bot on your first PR;
   see [`CLA.md`](CLA.md)).

## What gets merged fast

- Focused, tested, lint-clean changes that reference an issue.
- Bug fixes with a regression test.
- Docs improvements.

## What gets closed

- Unfocused or bundled PRs, unreviewed AI output, or changes with no linked issue.
- Anything that fails CI and is not being actively fixed.

## Reporting bugs and requesting features

Use the issue templates. For security problems, do **not** open a public issue; see
[`SECURITY.md`](SECURITY.md).
