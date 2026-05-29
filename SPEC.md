# better-gh

A transparent GitHub API proxy that adds per-repo/per-org read/write access policies, audit logging, and token custody — so the real token never leaves the server. Works with the stock `gh` CLI and any GitHub API client.

## Problem

The `gh` CLI has fundamental security design flaws:

1. **Overly broad default permissions** — `gh auth login` requests `repo` (full read/write to all private repos), `read:org`, and `gist`. There is no read-only OAuth scope for private repository code. Users who only need to read PRs still get write access to every repo they can see.

2. **Long-lived token on client machines** — The OAuth token (`gho_*`) is stored in the system keychain or, on fallback, in plaintext at `~/.config/gh/hosts.yml`. This token never expires and grants full access. A compromised laptop means full repository access.

3. **No per-repo/per-org granularity** — The token is all-or-nothing. You cannot say "read-only for org X, read-write for repo Y, no access to org Z." Every `gh` invocation carries the same god-mode token.

4. **No audit trail** — There is no record of which CLI invocations hit which API endpoints.

## Architecture

The proxy impersonates the GitHub API. Clients (`gh`, `curl`, libraries) connect to it as if it were a GitHub Enterprise instance. The proxy evaluates policy, swaps in the real token, forwards to `api.github.com`, and returns the response.

```
┌──────────────┐  /api/v3/repos/o/r/pulls  ┌──────────────┐  real token  ┌──────────────┐
│  gh CLI      │ ─────────────────────────▶ │  bgh-proxy   │ ──────────▶ │  GitHub API  │
│  curl        │  Auth: Bearer <proxy-secret>│              │             │              │
│  any client  │ ◀───────────────────────── │  ┌────────┐  │ ◀────────── │              │
└──────────────┘    passthrough response    │  │ policy │  │  response   └──────────────┘
                                            │  │ engine │  │
  No real GitHub token                      │  ├────────┤  │
  ever reaches the client.                  │  │ audit  │  │
                                            │  │ log    │  │
                                            │  └────────┘  │
                                            └──────────────┘
```

### Client setup (stock `gh`)

```bash
# Point gh at the proxy as a "GitHub Enterprise" host
gh auth login --hostname bgh.local
# Enter the proxy-issued secret as the "token"
# All gh commands now go through the proxy:
gh pr list -R my-company/frontend   # proxied, policy-checked, audited
```

No custom CLI required. Every `gh` command, extension, and alias works.

## v1 Scope

v1 is a **single-user local proxy** with:

- One GitHub token (env var or plaintext config — encrypted storage is v2)
- Local-only auth (shared secret on localhost)
- REST request classification (URL path parsing)
- GraphQL: mutation vs query detection only (mutations = write, queries = read). Repo extraction from GraphQL is v2 — v1 applies org/repo policy based on what can be extracted, falls back to the global default for unclassifiable GraphQL queries.
- Per-org and per-repo `read` / `read-write` / `none` policy
- JSONL audit log
- No TLS required (localhost only)

### What v1 does NOT include

- mTLS / team mode
- Multi-token routing
- Fine-grained per-resource-type policy (pull_requests vs issues vs contents) — v1 treats the whole repo as one unit
- Encrypted token storage
- Policy hot-reload
- GraphQL repo extraction

## Components

### 1. Transparent Reverse Proxy

- Listens on `127.0.0.1:7843` (configurable).
- Catch-all handler for `/api/v3/*` and `/api/graphql`.
- Request pipeline:
  1. Validate client secret from `Authorization` header
  2. Classify request (extract owner/repo, determine read vs write)
  3. Evaluate policy
  4. If denied: return 403 with `{ "message": "bgh: policy denied — ..." }`
  5. If allowed: rewrite URL, swap auth header, forward to `https://api.github.com`
- Stream GitHub's response back verbatim (status, headers, body).
- Serve `GET /api/v3` root endpoint for `gh`'s GHE handshake.

### 2. Request Classifier

Extracts `(owner/repo, read|write)` from each request.

#### REST

URL path parsing — the GitHub REST API is regular:

```
/api/v3/repos/{owner}/{repo}/**  →  repo = "{owner}/{repo}"
/api/v3/orgs/{org}/**            →  org  = "{org}"
/api/v3/user/**                  →  (no repo, user-level)
/api/v3/search/**                →  (no repo, search)
```

Access level from HTTP method: `GET`/`HEAD` → `read`, everything else → `write`.

#### GraphQL (v1 — minimal)

Parse the JSON body, extract the `query` string, check if it starts with `mutation` (after stripping leading whitespace and operation names). Mutations → `write`, everything else → `read`.

v1 does **not** extract repo references from GraphQL. The policy decision uses:
- The global default for GraphQL queries where no repo can be determined.
- This is safe under deny-by-default: unclassifiable requests hit the default (deny).

### 3. Policy Engine

Simple two-level policy: org defaults, repo overrides.

```toml
[defaults]
mode = "deny"              # "deny" or "allow"

[[org]]
name = "my-company"
access = "read"            # default for all repos in this org

[[repo]]
name = "my-company/deploy-infra"
access = "none"            # block completely

[[repo]]
name = "my-company/frontend"
access = "read-write"      # allow writes

[[repo]]
name = "personal/dotfiles"
access = "read-write"      # non-org repo
```

**Access levels**:
- `none` — 403, request never reaches GitHub
- `read` — GET/HEAD/GraphQL queries allowed, writes rejected
- `write` — alias for `read-write`, all operations allowed

**Resolution order**: exact repo match → org default → global default.

No glob patterns in v1 — exact match only.

### 4. Audit Log

Every request logged as JSONL, appended to a configured file:

```json
{
  "ts": "2026-05-26T14:30:00Z",
  "method": "GET",
  "path": "/repos/my-company/frontend/pulls",
  "repo": "my-company/frontend",
  "access": "read",
  "policy_result": "allowed",
  "github_status": 200,
  "duration_ms": 142
}
```

Async writes via a channel + dedicated writer task. Denied requests logged with `github_status: null`.

### 5. Client Auth (local mode)

- On startup, generate random 256-bit secret, write to `~/.config/bgh/client-secret` (mode 0600).
- Print setup instructions to stderr on first run.
- Validate `Authorization: Bearer <secret>` or `Authorization: token <secret>` (both forms `gh` may send).
- Regenerated on each proxy restart.

### 6. Token Config

v1 uses a single GitHub token, configured via:
- Environment variable: `BGH_GITHUB_TOKEN`
- Config file field: `github_token` in `bgh-proxy.toml`

Priority: env var > config file.

No encrypted storage, no multi-token routing — single token, simple config.

### 7. gh Compatibility

The proxy must handle `gh`'s GHE expectations:

- `GET /api/v3` — return root endpoint JSON with URLs pointing back to the proxy.
- `GET /api/v3/user` — forward to GitHub (used by `gh auth status` / `gh auth login`).
- Pass through `Link` headers for pagination.
- Return 403 errors in a format `gh` displays cleanly.

## Configuration

Single config file `bgh-proxy.toml`:

```toml
bind = "127.0.0.1:7843"
github_token = "ghp_..."        # or use BGH_GITHUB_TOKEN env var
audit_log = "~/.config/bgh/audit.jsonl"
policy_file = "~/.config/bgh/policy.toml"
```

## Technology Choices

- **Language**: Rust
- **HTTP**: `axum` (proxy server), `reqwest` (GitHub API client)
- **Config**: `toml`
- **CLI**: `clap`
- **Serialization**: `serde` + `serde_json`
- **Async**: `tokio`

## v2 Roadmap

- **Per-resource-type policy**: separate `pull_requests`, `issues`, `contents`, `actions` permissions per repo instead of single `access` level
- **GraphQL repo extraction**: parse `repository(owner:, name:)` arguments to apply repo-level policy to GraphQL queries
- **Glob patterns**: `my-company/test-*` in policy rules
- **Multi-token routing**: multiple GitHub tokens, proxy selects narrowest-scoped per request
- **mTLS team mode**: CA management, per-user client certs, per-identity policies
- **Encrypted token storage**: master key + AES-256-GCM at rest
- **Policy hot-reload**: file watch + atomic swap
- **Audit query CLI**: `bgh-proxy audit query --repo X --since DATE`
