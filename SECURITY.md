# Security Policy

## Reporting a vulnerability

Please report security issues **privately**. Do not open a public issue or pull request.

- Use GitHub's [private vulnerability reporting](https://github.com/ionalpha/flynn-extensions/security/advisories/new)
  ("Report a vulnerability" under the Security tab), or
- email **contact@ionalpha.io**.

Include a description, reproduction steps, affected version, and impact. We aim to
acknowledge within a few business days and will coordinate a fix and disclosure timeline
with you.

## Scope

This repository holds out-of-process capability extensions for
[flynn](https://github.com/ionalpha/flynn). Extensions run as sandboxed subprocesses that
flynn mounts over the Model Context Protocol behind a capability grant. Of particular
interest is anything that lets an extension exceed the security model it runs under, for
example: obtaining a secret it should never hold (signing keys stay in flynn core; an
extension builds unsigned requests and core signs them), reaching a network host outside its
allow-listed egress, escaping its sandbox, a tool call not gated by the declared capability,
a mis-namespaced tool impersonating another, or running unsigned extension code outside a
development context.

Vulnerabilities in a connected commercial host that consumes these extensions belong to that
system, not here.

## Supported versions

Until a 1.0 release, only the latest release and `main` receive security fixes.
