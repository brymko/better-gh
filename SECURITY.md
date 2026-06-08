# Security Policy

`bgh-proxy` is a security boundary: it holds one powerful GitHub token and enforces per-repo/
per-org/per-resource access policy for every client. Vulnerability reports are very welcome.

## Reporting a vulnerability

**Please do not open a public issue for security problems.** Instead, use one of:

- **GitHub private vulnerability reporting** — the repository's *Security → Report a vulnerability*
  ("Private vulnerability reporting") tab. This is preferred.
- **Email** — security reports to the maintainer at the address in the repository owner's GitHub
  profile, with `[bgh-proxy security]` in the subject.

Please include: the affected version/commit, a description of the issue, and a proof-of-concept or
the exact request sequence that triggers it. If you have a suggested fix, include it.

We aim to acknowledge a report within a few days and to coordinate a fix and disclosure timeline
with you. Please give us a reasonable window to ship a fix before any public disclosure.

## What is in scope

The trust boundary is the proxy itself (`internal/` + `cmd/`). High-value classes:

- **Isolation bypass** — a policy-restricted client reading or writing a repo/org/resource the
  policy denies (REST or GraphQL), including data that escapes the response filters.
- **Custodian-token disclosure** — leaking the real upstream token, its scopes, or its reach
  (e.g. via response headers, error bodies, timing).
- **Ownership / token-minting bypass** — claiming a deployment or minting a proxy token without
  being the deployment owner.
- **Denial of service** — a low-cost request that exhausts CPU/memory before policy enforcement.

The bundled `cli/` directory is the upstream [`cli/cli`](https://github.com/cli/cli) submodule and
is **out of scope** — the proxy's guarantees do not depend on client behaviour. Report `gh` CLI
issues upstream.

## Known, documented residuals (not vulnerabilities)

These are accepted trade-offs of being a policy proxy over a broad token, documented in
[README.md](README.md) ("What is *not* a boundary") and [SPEC.md](SPEC.md):

- **GraphQL counts/aggregates** (`totalCount`, `search` `*Count`) reveal *how many* denied items
  match — an existence oracle on counts, not contents. A fine-grained PAT custodian closes this at
  the source.
- **GraphQL `errors`** may echo a repo *name* a query references. Contents are isolated; the
  existence/name of a referenced repo is not.
- **Host compromise** exposes the plaintext custodian token (encrypted-at-rest is a non-goal).
- **Socket mode authenticates the user, not the process** — the `0600` unix socket admits any process
  running as your UID, all under the single socket policy.
- **API only, not git** — a client that already holds a direct `github.com` credential bypasses the
  proxy entirely; the proxy governs API access (`/api/v3`, `/api/graphql`), not git transport.

## Supported versions

This is a young project under active security hardening. Only the latest `main` is supported;
fixes land there. Pin a commit and update deliberately.
