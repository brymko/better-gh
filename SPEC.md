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
| `internal/gqlfilter` | Schema-aware GraphQL response filter (redacts denied-repo data) |
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

1. The classifier extracts **every** node-ID-shaped value from inline arguments and variables (id-typed keys; both modern `prefix_base64` and legacy base64 forms). It does **not** filter by type — there is no repo-scoped prefix allowlist to fall behind, so a repo-scoped object of any type is caught.
2. `proxy.resolveNodeScopes` looks each up in the verified `nodecache`; on a miss it asks GitHub a `nodes(ids:)` query **generated from the embedded schema** that requests `repository { nameWithOwner }` for every repo-scoped `Node` type (covering check runs, deployments, commits, … — not just the few that implement `RepositoryNode`), and caches the verified mapping (30 min TTL).
3. Each node that resolves to a **repository** becomes a scope the policy must allow at the request's access level. A node that resolves to a **non-repo** object (user, org) adds no constraint. A node that does **not** resolve (unknown/invalid, or not visible to the upstream token) also adds no constraint — the upstream token cannot mutate what it cannot resolve, so this cannot exceed policy; and a request whose *only* nodes are non-repo/unresolved carries no repo scope, which the policy denies as an unscoped write.

A node that resolves to a repo-scoped **type** but yields no repository (anomalous), an upstream error, or more than 100 IDs makes the request fail closed. Resolution is gated on `AllowsAnyWrite`/`AllowsAnyRead` so a token that can never act at that level does not trigger upstream calls. The `nodecache` only ever stores mappings the resolver verified — it is never populated by sniffing responses. (Resolving reads also closes a `mode = "allow"` gap: a `node(id:)` read of a blocked repo would otherwise fall through to the permissive default.)

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

GraphQL **read isolation** is enforced by schema-aware **response filtering** (`internal/gqlfilter`), not by the classifier's scope check alone. The classifier still gates the entry point and unscoped categories, but the filter is what makes cross-repo navigation safe: the proxy types the read against GitHub's embedded schema, injects a hidden `repository { nameWithOwner }` tag into every repo-scoped selection, forwards the rewritten query, and redacts from the JSON response every object whose repository the policy denies (`Policy.CanReadAnything`). Because every repo-scoped datum self-identifies its real repository, this is sound against multi-root, `owner.repositories`, `forks`, `node(id:)`, search results, and `viewer.repositories` alike. The **same filtering is applied to mutation response payloads** (a mutation's return selection is a read sub-graph), so a write grant on one repo cannot read a denied repo via what the mutation returns. A GraphQL request is **fully filtered or denied, never forwarded unfiltered**: if the filter is enabled but cannot type the request (a field newer than the embedded schema, an invalid query, or one that pre-declares the reserved marker alias), no response can be tagged/redacted, so the proxy **fails closed** (`respFilter == nil` → deny). It does not fall back to the classifier's `scanCrossRepoNav` denylist for typed-filter-eligible requests — that denylist is not complete enough to bound an untyped read, so relying on it could stream cross-repo data reached via an unlisted field. (`NavEscapes` is still used only when the filter is disabled entirely, e.g. in tests.)

For the filter to see plaintext, the proxy does **not** forward the client's `Accept-Encoding` upstream — Go's transport then negotiates compression itself and decompresses transparently, so every body can be typed and redacted (a gzipped body would otherwise be unparseable and forwarded unredacted). A GraphQL response the filter cannot parse is **denied**, not passed through (`filterGraphQLResponse` fails closed).

The REST enumeration/search endpoints that return repository-bearing entries from many repos (`/user/repos`, `/user/issues`, `/orgs/{org}/repos`, `/issues`, `/notifications`, `/search/{repositories,code,issues,commits}`, …) are filtered analogously by `internal/restfilter`: denied-repo entries are dropped from the array/`items` (keyed on `full_name` / `repository.full_name` / `repository_url`). Without this the `user`/`search`/`notifications` categories would let a client enumerate denied repos' metadata, read their code via `/search/code`, or read issue/PR titles via `/notifications`, over REST — bypassing the GraphQL filter. When a search drops matches, `total_count` is rewritten to the kept count (with `incomplete_results`) so it can't serve as a denied-repo existence oracle. REST filtering is defense-in-depth (an off-shape body passes through rather than failing closed). Separately, the proxy strips `X-OAuth-Scopes`/`X-Accepted-OAuth-Scopes`/`X-OAuth-Client-Id` from forwarded responses so the custodian token's scopes are not disclosed to clients.

Explicitly **not** boundaries (see README → Security model): the response filter is only as current as its embedded schema (newer fields → fail closed); redaction is repo-granular (per-resource limits aren't applied to navigated objects); a fine-grained upstream PAT remains the defense-in-depth floor; socket mode authenticates the user, not the process; node IDs are resolved against the embedded schema, so coverage of newly-added repo-scoped types tracks schema freshness.

## Technology

- **Language**: Go (`net/http` server and client)
- **GraphQL parsing**: `github.com/vektah/gqlparser/v2`
- **Config/policy**: `github.com/BurntSushi/toml`
- **Crypto/TLS**: standard library (`crypto/*`, self-signed CA + leaf for GHE mode)

## Non-goals (not implemented)

mTLS team mode and per-identity client certs; multi-token upstream routing; encrypted token storage; glob patterns in rules; policy hot-reload; HA/clustering; an audit-query CLI. (Response-body filtering IS implemented for GraphQL and for the known REST enumeration/search endpoints; arbitrary REST bodies are not otherwise filtered, so a fine-grained upstream PAT remains the floor.)
