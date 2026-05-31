# bgh-proxy — design & architecture

A transparent GitHub API proxy that adds per-repo/per-org/per-resource read/write access policy, audit logging, and token custody — so the powerful GitHub token never leaves the proxy host. Works with the stock `gh` CLI and any GitHub API client.

This document describes how the proxy is built and the security properties it aims to provide. For configuration, the policy language, and operational guidance see [README.md](README.md).

## Problem

The `gh` CLI's token model is coarse: `gh auth login` mints a token with `repo` (full read/write to every private repo you can see), `read:org`, and `gist`; it never expires; and it lives on the client (keychain, or plaintext `~/.config/gh/hosts.yml`). There is no read-only scope for private code, no per-repo granularity, and no audit trail. A compromised laptop means full access to everything.

`bgh-proxy` keeps the real token on a server and gives each client a narrowly-scoped credential plus an audit log.

## Architecture

The proxy impersonates the GitHub API. Clients (`gh`, `curl`, libraries) connect to it as if it were GitHub Enterprise. The proxy classifies the request, evaluates policy, swaps in the real token, forwards to `api.github.com`, and streams the response back.

```
┌────────────┐  /api/v3/repos/o/r/pulls   ┌─────────── bgh-proxy ───────────┐   real token   ┌────────────┐
│ gh / curl  │ ─────────────────────────▶ │ auth → classify → policy → fwd  │ ─────────────▶ │ GitHub API │
│ any client │  Authorization: <proxy tok>│        │           │            │                │            │
└────────────┘ ◀───────────────────────── │      audit       node          │ ◀───────────── └────────────┘
                  passthrough response     │      log         resolver      │   response
                                           └─────────────────────────────────┘
```

The real GitHub token never reaches the client.

### Components (Go packages)

| Package | Responsibility |
|---|---|
| `internal/proxy` | Request pipeline, header rewriting, response streaming, node resolver |
| `internal/classifier` | Extract `(owner, repo, org, access, resource, …)` from REST paths and GraphQL bodies |
| `internal/policy` | Evaluate a classified request against a TOML policy |
| `internal/nodecache` | Verified node-ID → repository cache (populated only by the resolver) |
| `internal/store` | Proxy-token persistence (`tokens.json`), SHA-256 hashed, constant-time lookup |
| `internal/auth` | Client/admin secret extraction and generation |
| `internal/audit` | Async JSONL audit logger |
| `internal/config`, `internal/tlsgen`, `internal/web` | Config loading, self-signed TLS, admin UI/API |
| `internal/oauth` | GitHub OAuth device flow for `bgh-proxy login` |
| `cmd/bgh-proxy` | CLI: `init`, `login`, `serve`, `token …` |

## Request pipeline

`proxy.Handler.ServeHTTP` runs each request through:

1. **Authenticate.** GHE mode requires a proxy token in `Authorization`; it is looked up (constant-time) in the store. Socket mode ignores the client token and uses the single socket policy.
2. **GHE handshake shortcuts.** `GET /api/v3` returns a root document with `X-OAuth-Scopes`; `GET /api/v3/user` returns a synthetic identity. These let `gh auth login`/`status` complete without forwarding.
3. **Reject path traversal.** Any request whose path contains a `.`/`..` segment (after percent-decoding) is rejected `400`, so the path the classifier sees is the path GitHub would route.
4. **Classify** into one or more scopes (see below).
5. **Resolve mutation scopes.** For a GraphQL mutation, resolve referenced node IDs to repositories via GitHub (see below). Skipped if the policy can never write.
6. **Evaluate policy** for every scope; deny (`403`) if any scope is denied.
7. **Forward.** Build a fresh upstream request: copy the client's headers (minus `Authorization`, `Host`, length, and hop-by-hop), set `Authorization: token <real-token>` and `X-GitHub-Api-Version`, default `Accept`/`User-Agent`/`Content-Type` only if absent. Stream status, headers, and body back verbatim.
8. **Audit** the decision (allowed/denied + upstream status) as one JSONL line.

## Classification

`classifier.Classify(method, path, body)` returns a primary scope plus any `Additional` scopes and, for mutations, the referenced node IDs. Access level: REST `GET`/`HEAD` = read, else write; GraphQL `query` = read, any `mutation` = write (fail-closed: unparseable/over-complex bodies are treated as write).

### REST

GitHub's REST API is path-regular:

```
/repos/{owner}/{repo}/{seg}/…  → repo = owner/repo, resource from {seg}
/orgs/{org}/…                  → org
/users/{user}/…                → org = user
everything else                → unscoped category from the first segment
```

The `resource` maps the first sub-segment (`pulls`, `issues`, `actions`, …) to a permission key. An unrecognized sub-segment yields a distinct `ResourceUnknown` sentinel: for a **write** under a rule that defines per-resource permissions, the policy fails closed rather than inheriting the base grant (so an unmapped write endpoint can't escape a per-resource `none`).

### GraphQL — multi-scope

A GraphQL document can touch many repositories/orgs in one operation, and GitHub executes all root fields. The classifier therefore walks the AST and collects **every** scope:

- `repository(owner:, name:)` → a repo scope (with resource inferred from its sub-selection);
- `organization`/`repositoryOwner(login:)` → an org scope;
- `search(query:)` → one repo scope per `repo:` qualifier, else an unscoped `search`;
- `viewer` → unscoped `user`; `rateLimit` → unscoped `meta`.

Variables are resolved. `operationName` is honored — only the executed operation is classified. The policy must allow **all** collected scopes. The AST walk is depth-bounded and fails closed on cyclic fragments / excessive nesting (an unbounded recursive walk would otherwise crash the process — `parser.ParseQuery` validates neither).

### Node-ID requests — authoritative resolution

GraphQL requests can address objects by opaque node ID with no `repository()` scope — every mutation (`mergePullRequest(input:{pullRequestId:…})`) and `node(id:)`/`nodes(ids:)` reads. Guessing the repository from earlier reads is unsafe (a response for repo A can contain node IDs belonging to repo B via cross-references), so the proxy resolves authoritatively:

1. The classifier extracts repo-scoped node IDs from inline arguments and variables (id-typed keys, filtered by a repo-scoped node-ID prefix allowlist so user/org IDs are excluded).
2. `proxy.resolveNodeScopes` looks each up in the verified `nodecache`; on a miss it asks GitHub `query{ nodes(ids:){ … on RepositoryNode { repository { nameWithOwner } } … } }` and caches the verified mapping (30 min TTL).
3. Each resolved repository becomes a scope; the policy must allow the request's access level (read or write) on all of them.

Any node that cannot be resolved (unknown ID, upstream error, unrecognized type, or more than 100 IDs) makes the request fail closed. Resolution is gated on `AllowsAnyWrite`/`AllowsAnyRead` so a token that can never act at that level does not trigger upstream calls. The `nodecache` only ever stores mappings the resolver verified — it is never populated by sniffing responses. (Resolving reads also closes a `mode = "allow"` gap: a `node(id:)` read of a blocked repo would otherwise fall through to the permissive default.)

## Policy engine

`policy.Evaluate(repo, org, access, resource, unscopedCategory)` resolves in order:

1. exact `[[repo]]` match (case-insensitive) → per-resource permission if present, else base `access`; unknown-resource writes under a permissioned rule fail closed;
2. exact `[[org]]` match (case-insensitive) → same;
3. `[defaults.unscoped][category]` when there is no repo/org;
4. unscoped writes with no repo/org are denied unconditionally;
5. `[defaults].mode` (`deny`/`allow`).

`Access` levels: `none` (nothing), `read` (read only), `read-write` (everything). For multi-scope requests the proxy ANDs the per-scope decisions.

## Token & secret model

- **Proxy tokens** (GHE mode): random 256-bit secrets, stored as SHA-256 hashes in `tokens.json` (`0600`), each carrying an embedded policy. Looked up in constant time; revocation and hard-deletion both go through the running server so they take effect immediately. `tokens.json` is written atomically (temp + rename).
- **Admin secret**: gates the token-minting API/UI; generated once and reused across restarts; file `0600`.
- **Socket**: created with a restrictive umask so it is `0600` from the moment it exists; only the owning user can connect.
- **Real GitHub token**: the proxy's single upstream credential, resolved from `BGH_GITHUB_TOKEN`, then `github_token` in config, then the file written by `bgh-proxy login`. Held only on the proxy host, never sent to clients. `bgh-proxy login` runs GitHub's OAuth **device flow** (`internal/oauth`) — by default with the GitHub CLI's public OAuth app client id, so it works with no registration like `gh auth login` (override with `--client-id` for your own app) — and stores the resulting token at `~/.config/bgh/github-token` (`0600`). Storage is plaintext (encrypted-at-rest is a non-goal).

## Security properties & threat model

The adversary is a holder of a proxy token (GHE) or any local process running as the user (socket). The intended invariant: **a client cannot exceed its policy**, even though the upstream token can.

Enforced: deny-by-default; per-repo/org/resource read/write; multi-scope GraphQL (every touched repo checked); authoritative mutation scoping (no mis-attribution); case-insensitive name matching; path-traversal rejection; fail-closed on parse/resolve/complexity failures; no token leakage to clients; constant-time secret comparison; least-privilege file modes.

Explicitly **not** boundaries (see README → Security model): the `search` and `user` unscoped categories run against the powerful token and can expose data from otherwise-denied repos; the proxy filters whole requests, not response fields; socket mode authenticates the user, not the process; mutation extraction is bounded by a node-ID prefix allowlist (unknown types fail closed).

## Technology

- **Language**: Go (`net/http` server and client)
- **GraphQL parsing**: `github.com/vektah/gqlparser/v2`
- **Config/policy**: `github.com/BurntSushi/toml`
- **Crypto/TLS**: standard library (`crypto/*`, self-signed CA + leaf for GHE mode)

## Non-goals (not implemented)

mTLS team mode and per-identity client certs; multi-token upstream routing; encrypted token storage; glob patterns in rules; policy hot-reload; response-body filtering; HA/clustering; an audit-query CLI.
