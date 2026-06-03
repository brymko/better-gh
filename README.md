> [!WARNING]
> This project was built with Claude (Anthropic) assistance. Review the code before trusting it with your GitHub tokens.

# bgh-proxy

Transparent GitHub API proxy with per-repo/per-org access control and audit logging.

```
gh cli  ──unix socket──▶  bgh-proxy  ──HTTPS──▶  api.github.com
                              │
                              ├─ classify request (repo, read/write)
                              ├─ evaluate policy (allow/deny)
                              ├─ audit log (JSONL)
                              └─ forward with real GitHub token
```

## Quick start

```bash
# Build
go build -o bgh-proxy ./cmd/bgh-proxy/

# Initialize (generates TLS certs, example config/policy)
bgh-proxy init

# Give the proxy an upstream GitHub token — either:
export BGH_GITHUB_TOKEN=$(gh auth token)        # reuse an existing token, or
bgh-proxy login                                 # log in like gh (device flow), no setup

# Edit the policy
$EDITOR ~/.config/bgh/policy.toml

# Start the proxy
bgh-proxy serve

# Point gh at the proxy (socket mode)
gh config set http_unix_socket ~/.config/bgh/proxy.sock
```

> [!NOTE]
> This is **socket mode** — don't `gh auth login` here (socket mode doesn't serve the sign-in flow, and the local socket already trusts your user). In **GHE mode** (below), `gh auth login --hostname <proxy>` is the *supported* way a client gets a scoped token — the proxy serves that flow and holds the one real token.

## Upstream token

The proxy uses one real GitHub token to reach `api.github.com` (the **custodian**). You don't have to pre-provide it: the **first GitHub sign-in** (web `/ui` or `gh auth login`) captures that account's token as the custodian and claims the deployment (trust-on-first-use; recorded in `~/.config/bgh/owner.json`, `0600`). After that, only that same account can sign in, and each sign-in refreshes the captured token. This is the easiest path — just start the proxy and sign in.

If you'd rather **pre-seed** a custodian (so the proxy can forward before the first sign-in, e.g. for CI), provide one of these — they become the fallback custodian until a sign-in claims ownership:

1. **A fine-grained PAT** — *Settings → Developer settings → Fine-grained tokens*, scoped as narrowly as possible, set as `BGH_GITHUB_TOKEN` or `github_token`. **Narrowest; recommended for high-stakes setups.**
2. **Reuse an existing token** — `export BGH_GITHUB_TOKEN=$(gh auth token)`. Quickest, but as broad as your `gh` login.
3. **`bgh-proxy login` (device flow)** — writes a `gho_` token (gh's public app, no registration) to `~/.config/bgh/github-token`.

The captured/sign-in token carries gh's standard scopes (`repo read:org gist workflow`); a pre-seeded fine-grained PAT is narrower. Storage is plaintext (`0600`); encrypted-at-rest is a non-goal.

The token is stored in plaintext (`github-token`, mode `0600`), same as the env/config options — encrypted storage is not implemented. Whichever you choose, the proxy then narrows access per client via policy.

## Two modes

### Socket mode (local use with `gh`)

`gh` sends all requests through a unix socket. No TLS, no proxy tokens needed — the socket file is `0600` so only your user can access it.

Policy is loaded from `~/.config/bgh/policy.toml`:

```toml
[defaults]
mode = "deny"

[defaults.unscoped]
user = "read"       # let /user, viewer{} etc. through
search = "read"     # allow search endpoints

[[org]]
name = "octocat"
access = "read"

[[repo]]
name = "octocat/Hello-World"
access = "read-write"
```

`gh` sends its own GitHub token, but the proxy ignores it and uses `BGH_GITHUB_TOKEN` for upstream requests. The socket policy controls what gets through.

### GHE mode (remote clients, CI bots)

Listens on HTTPS. Each client gets a **proxy token** with its own scoped policy. Clients send the proxy token in the `Authorization` header.

**Sign in with GitHub — bootstrap + tokens, nothing to pre-configure.** Signing in with GitHub *is* the setup: the proxy captures your GitHub token as its custodian and hands you scoped tokens. The **first** sign-in claims the deployment (trust-on-first-use); after that, only that same GitHub account may sign in (web *and* CLI).

- **Web — the owner console.** Open `https://proxy.example.com/ui` and **Sign in with GitHub**; you get a small console (a session lasting ~30 min) to **list** your tokens, **revoke** them, **edit** (re-issue with new permissions), and **create** new ones — via the builder (repo/org fields autocompleted from your own account) or by pasting a full TOML policy. Copy the `bgh_` token it shows you.
- **CLI — `gh auth login`, nothing to copy.**
  ```bash
  gh auth login --hostname proxy.example.com   # pick "Login with a web browser"
  ```
  `gh` opens the proxy's authorize page; you sign in with GitHub and pick a policy, and the scoped token is handed straight to `gh`. Every `gh` command from then on is policy-checked and audited.

> The first GitHub sign-in claims the deployment and **captures that account's GitHub token as the proxy's custodian** — no `BGH_GITHUB_TOKEN` needed (it's an optional fallback). Sign in immediately after starting, before exposing the proxy, so you claim it first. The **browser** (and `gh`) must trust the proxy's cert — front it with a real cert (Tailscale Serve or Caddy + Let's Encrypt; see [docs/deployment.md](docs/deployment.md)) so remote clients need zero trust setup.

**Or pre-mint a token and paste it** (good for CI bots / headless, or when you don't want the browser step):

```bash
# On the proxy host: create a token scoped to one repo
bgh-proxy token create --name ci-bot --default deny --repo my-org/my-repo=read
# prints: bgh_xxxxxxxxxxxx

# On the client: trust the proxy's CA and authenticate
cp ca.pem /usr/local/share/ca-certificates/bgh.crt && update-ca-certificates  # or add to keychain on macOS
gh auth login --hostname proxy.example.com --with-token <<< "bgh_xxxxxxxxxxxx"

# All gh commands now go through the proxy, policy-checked and audited:
gh pr list -R my-org/my-repo
gh issue list -R my-org/my-repo
```

## Policy specification

Policy files use TOML. In socket mode, the policy is loaded from `~/.config/bgh/policy.toml`. In GHE mode, each proxy token carries its own embedded policy.

### Full example

```toml
[defaults]
mode = "deny"                    # "deny" or "allow"
public = "read"                  # read ANY public repo (verified against GitHub); private repos still need a rule below

[defaults.unscoped]
user = "read"                    # allow /user, viewer{} reads
search = "read"                  # allow search endpoints
gists = "read-write"             # allow gist reads and writes

[[org]]
name = "my-company"
access = "read"                  # default for all repos in this org

[org.permissions]
pulls = "read-write"             # allow PR writes across org

[[org]]
name = "personal"
access = "read-write"

[[repo]]
name = "my-company/frontend"
access = "read-write"            # overrides org default

[[repo]]
name = "my-company/deploy-infra"
access = "none"                  # block completely, even reads

[[repo]]
name = "my-company/backend"
access = "read"

[repo.permissions]
pulls = "read-write"             # allow PR writes on this repo
actions = "none"                 # block actions even for reads

[[repo]]
name = "personal/dotfiles"
access = "read-write"
```

### `[defaults]` section

| Field | Values | Description |
|---|---|---|
| `mode` | `"deny"` (default), `"allow"` | Fallback decision when no rule matches. |
| `public` | `"none"` (default), `"read"` | Baseline read access to **public** repos not covered by a `[[repo]]`/`[[org]]` rule. |

**`public` (public-repo baseline).** With `public = "read"`, a token may read any **public** repository, even one with no explicit rule — handy for letting CI read open-source dependencies without listing each. It is enforced against GitHub's **real** visibility (an authoritative lookup for direct repo reads; an injected visibility marker for GraphQL; each entry's `private` for REST listings), so it can **never** expose a private repo, and unknown visibility is treated as private. An explicit `[[repo]]`/`[[org]]` rule always wins (so `access = "none"` on a public repo still blocks it). The baseline is **read-only** — writing to a public repo still needs an explicit `[[repo]]` rule with write access.

### `[defaults.unscoped]` section

Controls access to endpoints with no identifiable repo or org, on a per-category basis. Each key is a category name and the value is an access level.

| Category | REST endpoints | GraphQL |
|---|---|---|
| `user` | `/user`, `/user/repos`, `/user/orgs`, ... | `viewer { ... }` |
| `search` | `/search/repositories`, `/search/issues`, ... | `search(query: ...) { ... }` (no `repo:` qualifier) |
| `gists` | `/gists`, `/gists/{id}` | — |
| `notifications` | `/notifications` | — |
| `events` | `/events` | — |
| `meta` | `/rate_limit`, `/feeds`, `/meta`, `/octocat`, `/zen`, `/emojis`, `/` | `rateLimit { ... }` |

Categories not listed in `[defaults.unscoped]` fall through to `[defaults].mode`.

This replaces the old `allow_unscoped_reads` boolean. To migrate: replace `allow_unscoped_reads = true` with a `[defaults.unscoped]` section listing the categories you want to allow.

### `[[org]]` rules

| Field | Values | Description |
|---|---|---|
| `name` | string | Org login, e.g. `"my-company"`. Matched case-insensitively (GitHub routes names case-insensitively), no globs. |
| `access` | `"none"`, `"read"`, `"read-write"` | Access granted to any repo in this org that doesn't have its own `[[repo]]` rule. |
| `[org.permissions]` | map of resource → access | Per-resource overrides. See [Resource types](#resource-types). |

Org matching uses the `owner` segment from REST paths (`/repos/{owner}/...`) or the `owner` argument from GraphQL `repository(owner:, name:)`. For org-scoped endpoints (`/orgs/{org}/...`), the org name is used directly.

### `[[repo]]` rules

| Field | Values | Description |
|---|---|---|
| `name` | string | Full `owner/repo` name, e.g. `"my-company/frontend"`. Matched case-insensitively, no globs. |
| `access` | `"none"`, `"read"`, `"read-write"` | Access granted to this specific repo. Takes priority over `[[org]]` rules. |
| `[repo.permissions]` | map of resource → access | Per-resource overrides. See [Resource types](#resource-types). |

### Resource types

When the classifier identifies a specific resource within a repo-scoped request, per-resource permissions are checked before the rule's base `access` level.

| Resource | REST segments | GraphQL fields |
|---|---|---|
| `pulls` | `pulls` | `pullRequest`, `pullRequests`, mutations containing `PullRequest` |
| `issues` | `issues` | `issue`, `issues`, `pinnedIssues`, mutations containing `Issue` |
| `contents` | `contents`, `readme`, `zipball`, `tarball` | `object`, `blob`, `tree` |
| `actions` | `actions` | — |
| `releases` | `releases` | `releases`, `release`, `latestRelease`, mutations containing `Release` |
| `git` | `git` | — |
| `commits` | `commits`, `compare` | `commit`, `commitComments` |
| `branches` | `branches` | `refs`, `ref`, `defaultBranchRef`, mutations containing `Ref`/`Branch` |
| `checks` | `check-runs`, `check-suites`, `statuses` | mutations containing `Check` |
| `comments` | `comments` | — |
| `hooks` | `hooks` | — |
| `deployments` | `deployments`, `environments` | `deployments`, mutations containing `Deployment` |
| `pages` | `pages` | — |
| `keys` | `keys`, `deploy-keys` | — |
| `metadata` | `stargazers`, `subscribers`, `topics`, `languages`, `tags`, `forks`, `contributors`, `collaborators`, `teams`, `license`, `community`, `traffic`, repo root | `name`, `owner`, `url`, `id`, `isPrivate`, `stargazers`, etc. |

If the resource cannot be determined, the rule's base `access` level is used — **except** that a **write** to an unrecognized REST sub-resource is **denied** when the matching rule defines `[…permissions]` (fail-closed). This stops a per-resource `none` from being dodged via an unmapped sibling endpoint (e.g. `POST /repos/o/r/dispatches`, which can trigger workflows, escaping `actions = "none"`). Reads, and rules without per-resource permissions, still fall back to the base `access`.

### Access levels

| Level | Permits | REST methods | GraphQL |
|---|---|---|---|
| `none` | Nothing | All blocked | All blocked |
| `read` | Read-only | `GET`, `HEAD` | Queries only |
| `read-write` | Everything | All methods | Queries and mutations |

Aliases: `"write"` and `"readwrite"` are accepted as synonyms for `"read-write"`.

### Evaluation order

For each request, the classifier extracts `(repo, org, access_level, resource, unscoped_category)`. The policy engine evaluates rules in this order:

```
1. Exact [[repo]] match on "owner/repo"
   → found + resource + permissions[resource] exists → check permissions[resource]
   → found → check rule access level → allow or deny
   → not found: continue

2. [[org]] match on org name
   → found + resource + permissions[resource] exists → check permissions[resource]
   → found → check rule access level → allow or deny
   → not found: continue

3. [defaults.unscoped] check
   → if repo="" AND org="" AND unscoped[category] exists → check category access
   → otherwise: continue

4. [defaults].mode
   → "allow" → allow
   → "deny"  → deny
```

When the result is **deny** for a repo **read** and `[defaults].public = "read"`, a final public-repo
baseline applies: if no `[[repo]]`/`[[org]]` rule matched and the repo is actually **public**
(verified against GitHub, never the client's claim), the read is allowed. This never overrides an
explicit rule and never grants writes — see [`[defaults]` → `public`](#defaults-section).

Evaluation stops at the first matching rule. A `[[repo]]` rule always takes priority over an `[[org]]` rule for the same org, and both take priority over the default. Within a rule, per-resource permissions take priority over the rule's base access level. Repo/org names match case-insensitively.

When a single request touches **multiple** scopes (a GraphQL query selecting several repositories, or a mutation resolving to several repositories), every scope is evaluated independently and the request is allowed only if **all** of them are allowed.

### Request classification

The proxy classifies every request to extract scope `(owner, repo, org)` and access level `(read, write)`.

Access level is determined by:
- **REST**: `GET`/`HEAD` = read, all other methods (`POST`, `PUT`, `PATCH`, `DELETE`) = write
- **GraphQL**: `query` operations = read, `mutation` operations = write

#### Repo-scoped requests

These requests are matched against `[[repo]]` rules, falling back to `[[org]]` rules using the owner as the org name.

**REST endpoints** — any path under `/repos/{owner}/{repo}/`:

| Path pattern | Example | `gh` command |
|---|---|---|
| `/repos/{owner}/{repo}` | `/repos/my-org/frontend` | `gh repo view my-org/frontend` |
| `/repos/{owner}/{repo}/pulls` | `/repos/my-org/frontend/pulls` | `gh pr list -R my-org/frontend` |
| `/repos/{owner}/{repo}/pulls/{n}` | `/repos/my-org/frontend/pulls/42` | `gh pr view 42` |
| `/repos/{owner}/{repo}/issues` | `/repos/my-org/frontend/issues` | `gh issue list -R my-org/frontend` |
| `/repos/{owner}/{repo}/issues/{n}` | `/repos/my-org/frontend/issues/7` | `gh issue view 7` |
| `/repos/{owner}/{repo}/git/refs` | `/repos/my-org/frontend/git/refs` | `gh api repos/my-org/frontend/git/refs` |
| `/repos/{owner}/{repo}/contents/{path}` | `/repos/my-org/frontend/contents/README.md` | `gh api repos/.../contents/README.md` |
| `/repos/{owner}/{repo}/actions/runs` | `/repos/my-org/frontend/actions/runs` | `gh run list` |
| `/repos/{owner}/{repo}/releases` | `/repos/my-org/frontend/releases` | `gh release list` |
| `/repos/{owner}/{repo}/comments` | `/repos/my-org/frontend/comments` | `gh api repos/.../comments` |
| `/repos/{owner}/{repo}/**` | any sub-path | any repo-scoped API call |

**GraphQL queries** — the classifier walks the AST and extracts **every** scope the query touches, not just the first:

| Pattern | Example | Scope |
|---|---|---|
| `repository(owner:, name:)` | `repository(owner: "my-org", name: "frontend")` | repo = `my-org/frontend` |
| `organization(login:)` / `repositoryOwner(login:)` | `organization(login: "my-org")` | org = `my-org` |
| `search(query: "repo:...")` | `search(query: "repo:my-org/frontend is:open")` | repo = `my-org/frontend` (one scope per `repo:` qualifier) |
| `viewer { … }` / `rateLimit { … }` | — | unscoped `user` / `meta` |

Variables are resolved (`repository(owner: $owner, name: $name)`). A single GraphQL document can reference several repositories/orgs at once and GitHub executes all of them, so **the request is allowed only if policy allows every scope it touches** — a query that reads an allowed repo and a denied repo in the same operation is denied. `operationName` is honored (only the executed operation is classified). Queries too deeply nested or with cyclic fragments are rejected (fail-closed).

**GraphQL mutations** are scoped by *authoritative node resolution*. A mutation references objects by opaque node ID (e.g. `mergePullRequest(input: {pullRequestId: "PR_kwDO..."})`) and carries no `repository()` scope. The proxy:

1. extracts every repo-scoped node ID from the mutation (inline arguments and variables);
2. resolves each ID to its **real** repository by asking GitHub (`nodes(ids:){ … repository { nameWithOwner } }`), caching the verified mapping (30 min TTL);
3. requires policy to allow a **write** to every resolved repository.

A mutation whose node IDs cannot all be resolved (unknown ID, upstream error) is **denied** as an unscoped write. The resolution call is skipped entirely for tokens whose policy can never write. This means `gh pr merge 123` works because the PR's node ID resolves to its repository, and a mutation cannot be misdirected to a repo the token can't write — the repository is confirmed by GitHub, never guessed from an earlier read.

The same resolution applies to **reads by node ID** — `node(id:)` / `nodes(ids:)` queries carry no `repository()` scope, so each referenced node is resolved to its repository and the read is checked against it (and denied if it can't be resolved). Without this, a `node(id:)` read could reach a repo a `[[repo]] none` rule was meant to block under `mode = "allow"`.

#### Org-scoped requests

These requests are matched against `[[org]]` rules only. No `[[repo]]` rule can match since there is no repo.

**REST endpoints:**

| Path pattern | Example | `gh` command |
|---|---|---|
| `/orgs/{org}` | `/orgs/my-org` | `gh api orgs/my-org` |
| `/orgs/{org}/repos` | `/orgs/my-org/repos` | `gh repo list my-org` |
| `/orgs/{org}/members` | `/orgs/my-org/members` | `gh api orgs/my-org/members` |
| `/orgs/{org}/**` | any sub-path | any org-scoped API call |
| `/users/{user}` | `/users/octocat` | `gh api users/octocat` |
| `/users/{user}/repos` | `/users/octocat/repos` | `gh repo list octocat` |
| `/users/{user}/**` | any sub-path | any user-scoped API call |

Note: `/users/{user}` endpoints use the username as the org for policy matching. This means an `[[org]]` rule for `"octocat"` covers both `/orgs/octocat/...` and `/users/octocat/...`.

**GraphQL:**

| Pattern | Example | Scope |
|---|---|---|
| `organization(login:)` | `organization(login: "my-org")` | org = `my-org` |
| `repositoryOwner(login:)` | `repositoryOwner(login: "my-org")` | org = `my-org` |

#### Unscoped requests

These requests have no identifiable repo or org. Under `mode = "deny"`, they are **denied by default** unless `[defaults.unscoped]` grants access for their category.

This matters because `gh` needs several of these endpoints to function — `gh auth status` calls `/user`, `gh repo list` (without an owner) calls `/user/repos`, and many commands start with a `{ viewer { login } }` GraphQL query.

**REST endpoints by category:**

| Category | Paths | `gh` commands |
|---|---|---|
| `user` | `/user`, `/user/repos`, `/user/orgs`, `/user/starred` | `gh auth status`, `gh repo list`, `gh org list` |
| `search` | `/search/repositories`, `/search/issues`, `/search/code` | `gh search repos`, `gh search issues`, `gh search code` |
| `gists` | `/gists`, `/gists/{id}` | `gh gist list`, `gh gist create` |
| `notifications` | `/notifications` | `gh api notifications` |
| `events` | `/events` | `gh api events` |
| `meta` | `/rate_limit`, `/feeds`, `/meta`, `/octocat`, `/zen`, `/emojis`, `/` | `gh api rate_limit`, GHE handshake |

**GraphQL by category:**

| Category | Pattern | `gh` commands |
|---|---|---|
| `user` | `viewer { ... }` | most `gh` commands |
| `search` | `search(query: ...) { ... }` (no `repo:` qualifier) | `gh search ...` |
| `meta` | `rateLimit { ... }` | — |

**Mutations** never fall through to the unscoped categories: a GraphQL mutation is always scoped by [authoritative node resolution](#repo-scoped-requests) (or denied if it has no resolvable repo-scoped node). `[defaults.unscoped]` with a `read-write` category (e.g. `gists = "read-write"`) only applies to genuinely unscoped *REST* writes such as `POST /gists`.

### Examples

**Deny-default, read one org, write PRs only:**
```toml
[defaults]
mode = "deny"

[defaults.unscoped]
user = "read"
search = "read"

[[org]]
name = "my-company"
access = "read"

[org.permissions]
pulls = "read-write"

[[repo]]
name = "my-company/frontend"
access = "read-write"
```

Result: `gh pr list -R my-company/backend` works (read, org rule). `gh pr merge -R my-company/backend` works (write, org pulls=read-write). `gh pr merge -R my-company/frontend` works (write, repo rule). `gh issue create -R my-company/backend` denied (write, no issues perm, org=read). `gh pr list -R other/repo` denied (default deny).

**Granular repo permissions:**
```toml
[defaults]
mode = "deny"

[defaults.unscoped]
user = "read"

[[repo]]
name = "my-company/frontend"
access = "read"

[repo.permissions]
pulls = "read-write"
actions = "none"
```

Result: can read most things in `my-company/frontend`. Can create/merge PRs (pulls=read-write). Cannot access actions at all (actions=none). Cannot write to issues, releases, etc. (falls back to access=read).

**Allow-default, block sensitive repos:**
```toml
[defaults]
mode = "allow"

[[repo]]
name = "my-company/secrets"
access = "none"

[[repo]]
name = "my-company/deploy-infra"
access = "read"
```

Result: everything allowed except `my-company/secrets` (fully blocked) and `my-company/deploy-infra` (read-only).

## Token management

### CLI

```bash
bgh-proxy token create --name <name> [--default deny|allow] \
  [--org <org>=<access>]... \
  [--repo <owner/repo>=<access>]... \
  [--org-perm <org>:<resource>=<access>]... \
  [--repo-perm <owner/repo>:<resource>=<access>]... \
  [--unscoped <category>=<access>]...
bgh-proxy token list
bgh-proxy token show <name-or-id>
bgh-proxy token revoke <name-or-id>
bgh-proxy token delete <name-or-id>
```

`token create` prints the secret to stdout (shown once, not retrievable again). The CLI talks to the admin API, so changes take effect immediately on the running server.

### Web UIs

Two separate UIs, different auth:

- **Owner console** — `/ui` on the **GHE HTTPS** listener, authenticated by **GitHub sign-in** (the deployment owner). List / revoke / edit (re-issue) / create tokens, via a builder (repo/org fields autocompleted from your own account) or a pasted TOML policy. This is the one remote clients reach — see **GHE mode** above.
- **Admin UI** — on `admin_bind` (default `127.0.0.1:7844`, plain HTTP, **loopback only**), authenticated by the pasted **admin secret**. A simpler form for local administration on the proxy host:
  - List all tokens with status, creation date, last used
  - Create tokens with org/repo rules via form
  - View token details and policy
  - Revoke tokens

### Admin API

```
GET    /api/tokens                 List all tokens
POST   /api/tokens                 Create token (JSON body)
GET    /api/tokens/{id}            Get token detail
DELETE /api/tokens/{id}            Revoke token (mark revoked)
DELETE /api/tokens/{id}?hard=true  Hard-delete token (remove entry)
```

All endpoints require `Authorization: token <admin-secret>`. Token changes go through the running server, so `revoke`/`delete` take effect immediately (do not edit `tokens.json` by hand while the server is running — it rewrites the file on every allowed request).

## Configuration

`~/.config/bgh/config.toml`:

```toml
bind = "127.0.0.1:7843"           # GHE HTTPS listener
admin_bind = "127.0.0.1:7844"     # Admin UI (plain HTTP, loopback)
socket = "~/.config/bgh/proxy.sock"
mode = "both"                     # "socket", "ghe", or "both"
# github_token = "ghp_..."        # optional fallback custodian (or BGH_GITHUB_TOKEN); the first sign-in captures one
# external_url = "https://proxy.example.com"  # public URL when behind a TLS-terminating front (Tailscale/Caddy) — used in the device-flow verification URL
# oauth_client_id = "..."         # OAuth app for sign-in / `bgh-proxy login` (default: gh's public app, no registration)
# oauth_scopes = "repo read:org gist workflow"  # scopes captured as the custodian on sign-in
# tls_dir = "~/.config/bgh"       # directory holding the self-signed CA + server cert/key
audit_log = "~/.config/bgh/audit.jsonl"
policy_file = "~/.config/bgh/policy.toml"
```

## Files

```
~/.config/bgh/
├── config.toml        # Server configuration
├── policy.toml        # Socket mode policy
├── tokens.json        # Proxy token store
├── owner.json         # Deployment owner login + captured custodian token (0600)
├── github-token       # Fallback upstream token from `bgh-proxy login` (0600)
├── admin-secret       # Admin API/UI secret
├── audit.jsonl        # Request audit log
├── proxy.sock         # Unix socket
├── ca.pem             # Self-signed CA cert
├── ca-key.pem         # CA private key
├── server.pem         # TLS server cert
└── server-key.pem     # TLS server key
```

## Audit log

Every request is logged to `~/.config/bgh/audit.jsonl`:

```json
{"ts":"2026-05-26T14:30:00Z","method":"GET","path":"/repos/octocat/Hello-World/pulls","repo":"octocat/Hello-World","resource":"pulls","access":"read","policy_result":"allowed","github_status":200,"duration_ms":142,"mode":"socket","token_name":"(socket)"}
{"ts":"2026-05-26T14:30:01Z","method":"POST","path":"/repos/unknown/repo/pulls","repo":"unknown/repo","resource":"pulls","access":"write","policy_result":"denied: default policy is deny","github_status":null,"duration_ms":5,"mode":"ghe","token_name":"ci-bot"}
{"ts":"2026-05-26T14:30:02Z","method":"GET","path":"/user","unscoped_category":"user","access":"read","policy_result":"allowed","github_status":200,"duration_ms":45,"mode":"socket","token_name":"(socket)"}
```

## Security model

The proxy holds one **powerful upstream GitHub token** and hands out **narrow access** to clients. The goal: a client must not be able to exceed the policy it was given, even though the upstream token can do far more.

**Trust boundaries**
- **Socket mode** trusts the local user. The socket is created `0600` (owner-only connect), so only your user reaches it; `gh`'s own token is ignored and the single `policy.toml` applies to everything on the socket. Any process running as you gets that policy.
- **GHE mode** trusts whoever holds a valid proxy token, plus whoever trusts the self-signed CA. Each proxy token carries its own embedded policy. Tokens are stored as SHA-256 hashes (`tokens.json`, `0600`) and compared in constant time.
- The **admin API/UI** (token minting) is guarded by a separate `admin-secret`. Anyone with it can create full-access tokens.

**What is enforced**
- Per-repo / per-org / per-resource read vs write, deny-by-default.
- GraphQL queries are scoped to **every** repository/org/search target they touch — a query touching a denied repo alongside an allowed one is denied. `operationName` is honored.
- GraphQL requests that address objects by node ID (mutations, and `node(id:)`/`nodes(ids:)` reads) are scoped by **authoritative resolution**: each node ID is resolved to its real repository by GitHub before the request is authorized, so it cannot be misdirected to a repo the token can't access.
- Names match case-insensitively (GitHub routes them that way), so a re-cased path can't dodge a rule.
- Requests with `.`/`..` path segments (including `%2F`-encoded) are rejected `400`.
- Unparseable, over-deep, or cyclic GraphQL fails closed (denied), and never crashes the proxy.
- **GraphQL read isolation is enforced by schema-aware response filtering.** The proxy types each read against GitHub's GraphQL schema, rewrites it to tag every repo-scoped object with its repository **and its type**, forwards it, and then **redacts from the response** every object the policy denies for that **(repository, resource)** — the resource derived from the tagged type (`PullRequest`→`pulls`, `Issue`→`issues`, …). This is sound no matter how the query reaches a repo — multi-root, `owner.repositories`, `owner.repository(name:)`, `forks`, `node(id:)`, search results, even `viewer { repositories }` — each repo-scoped datum is checked against its *real* repository, and a per-resource restriction like `pulls = "none"` is enforced even on objects reached by *navigation*, not just at the entry point. Denied data comes back as `null`; allowed data is untouched. (This also means enabling the `user`/`search` categories no longer leaks denied-repo *contents* via enumeration — those repos are redacted.) The **same filtering covers mutation response payloads** (a mutation's return selection is itself a read sub-graph), so a write grant on one repo cannot read a denied repo through the value a mutation returns.
- **The filter sees plaintext and fails closed.** The proxy does **not** forward the client's `Accept-Encoding`, so upstream responses arrive decompressed and every body can be typed and redacted; a GraphQL response that cannot be parsed is **denied**, never passed through. A query that pre-declares the proxy's reserved marker alias (which could otherwise suppress a repository tag) is rejected (fail closed).
- **REST enumeration/search responses are redacted too.** The REST endpoints that return repository-bearing entries from many repos — `/user/repos`, `/user/issues`, `/user/starred`, `/user/subscriptions`, `/orgs/{org}/repos`, `/orgs/{org}/issues`, `/users/{u}/repos`, `/repos/{owner}/{repo}/forks`, `/issues`, `/notifications`, and `/search/{repositories,code,issues,commits}` — have denied-repo entries dropped from the response (by `full_name` / `repository.full_name` / `repository_url`). Without this, the `user`/`search`/`notifications` categories would let a client enumerate denied repos' metadata via REST, read their code via `/search/code`, or read issue/PR titles via `/notifications`, sidestepping the GraphQL filter. A search response that drops matches has its `total_count` rewritten to the kept count (and `incomplete_results` set) so the count can't be used as a denied-repo existence oracle. (Defense-in-depth: an off-shape body passes through unchanged.)
- **The upstream token's reach is not advertised.** The `X-OAuth-Scopes`, `X-Accepted-OAuth-Scopes`, and `X-OAuth-Client-Id` response headers (which reveal the custodian token's scopes and OAuth client) are stripped from forwarded responses, so a proxy-token holder cannot learn how powerful the real token is.

**What is *not* a boundary** — read these before trusting it:
- **The response filter is only as current as its embedded schema.** It is sound for any query it can type. A query using a field newer than the proxy's schema snapshot can't be tagged, so it is **denied outright** — a GraphQL request is fully filtered or denied, never forwarded unfiltered. (Earlier builds fell back to the classifier's cross-repo-nav denylist for untyped reads, but that denylist isn't complete enough to bound them, so a scoped read navigating cross-repo via an unlisted field could leak under drift; the proxy now fails closed instead.) Keep the schema reasonably fresh (`internal/gqlfilter/schema.graphql`); a stale schema costs availability (newer-field queries are denied), not isolation.
- **Per-resource redaction is as complete as the type→resource map.** The filter tags each object with its GraphQL type and enforces per-resource policy (e.g. `pulls = "none"`) on it wherever it appears — entry point *and* navigation. The map covers the resource-bearing types (pulls / issues / commits / releases / branches / checks / contents / deployments, plus commit statuses and branch-protection rules). A repo-scoped type **not** in the map falls back to the rule's base access (repo-level), so a per-resource restriction is not enforced on it — but those types are wrappers/connections (whose contained objects carry their own resource tag), timeline events (gated by their marked parent issue/PR), or types with no per-resource key (e.g. discussions). Keep the embedded schema fresh so the mapping stays current.
- **Only response `data` is redacted, not GraphQL `errors`.** A denied/absent repo's *name* can still surface in an upstream error message (e.g. "Could not resolve to a Repository …"). This isolates repo *contents*, not the existence/names of repos a query already references.
- **Counts and aggregates leak; only contents are redacted.** The filter removes denied-repo *objects* from a GraphQL response, but a connection's `totalCount` / `search`'s `issueCount`/`repositoryCount`/`discussionCount` are scalars computed by GitHub over the full (pre-redaction) set, so they reveal *how many* denied items matched — and `totalCount − len(nodes)` discloses the hidden count regardless of how elements are dropped. In particular `search(query:"<text>", type:ISSUE){ issueCount }` is an existence oracle for issue/PR/discussion *text* in denied repos, and `viewer { repositories { totalCount } }` leaks the custodian token's repo breadth. This is not soundly closable in the response filter (count fields can be aliased, `totalCount` is a cross-page total, and stripping counts would break legitimate counts on *allowed* repos), so the **fine-grained upstream PAT is the bound** — scoped to only the proxy's repos, GitHub never searches/counts the denied ones. (The REST `/search` `total_count` is opportunistically rewritten to the kept count; GraphQL counts are not.)
- **Only the GitHub API is proxied, not git.** The proxy serves `/api/v3` + `/api/graphql` (plus `/login`/`/ui`), not git transport — so `gh repo clone` / `git push` *through the proxy* fail (it is not a git server), and git traffic is never carried or filtered by it. Policy governs **API** access (including reading file contents via the `contents` API); cloning or pushing a repo's code over git is out of scope. A client that also holds a direct `github.com` credential can run git (and API) straight to GitHub, bypassing the proxy entirely — see [docs/deployment.md](docs/deployment.md) "Client gotchas".
- As **defense-in-depth**, a **fine-grained upstream PAT** scoped to only the repos the proxy should reach still bounds what any query — typed or not — can touch, so GitHub itself enforces the floor. Recommended for high-stakes setups.
- It does not authenticate *which* local process uses the socket, only that it is your user.
- mTLS / per-identity client certs are not implemented; GHE-mode identity is the bearer proxy token.

## Deployment & operations

- **Token custody.** The real GitHub token sits on the proxy host (env var or `github_token` in config, **plaintext** — encrypted storage is not implemented). Whoever can read the host's memory/config has it. As defense-in-depth, give the proxy a **fine-grained PAT** scoped as narrowly as GitHub allows, so a host compromise is bounded.
- **Bind loopback.** `admin_bind` is plain HTTP and the proxy `bind` (GHE) is HTTPS with a self-signed cert. Keep both on loopback unless you mean to expose them; a non-loopback `admin_bind` sends the admin secret in cleartext (the server logs a warning). For remote clients, front the GHE listener with your own TLS/network controls.
- **Rate limits.** All proxied traffic *and* node-ID resolution calls consume the single upstream token's rate limit. A mutation or a `node(id:)`/`nodes(ids:)` read adds one batched GraphQL `nodes(ids:)` call for its uncached node IDs (resolved repository mappings are cached 30 min; non-repo and unresolved results are not cached). Resolution is gated on the policy being able to act at that level — writes need a write grant, reads a read grant — and capped at 100 IDs/request, but not otherwise throttled, so a token can spend some GraphQL budget resolving IDs in repos it can't ultimately access.
- **Fail-closed effects.** When the resolver can't reach GitHub or is rate-limited, mutations are denied. Over-complex GraphQL and node types the resolver doesn't recognize are denied. Plan for "denied" being the safe failure during upstream trouble.
- **Availability.** Single process, no HA. The audit log is async and **can drop entries under sustained overload** (bounded 1024-entry channel); a `SYSTEM` warning entry records how many were dropped. Treat the audit log as best-effort, not guaranteed.
- **Restart behavior.** Proxy tokens, the admin secret, and TLS certs persist across restarts. The node-resolution cache is in-memory and repopulates lazily. **There is no policy hot-reload** — edit `policy.toml` (socket mode) and restart; for GHE tokens, a policy change means issuing a new token.

## Limitations

- Single process, single upstream token. No mTLS team mode, multi-token routing, encrypted token storage, glob patterns in rules, or policy hot-reload.
- Node-ID scoping resolves **every** referenced node ID against GitHub using a query generated from the embedded schema (covering all repo-scoped `Node` types, both modern and legacy ID forms). Coverage of *newly added* repo-scoped types therefore tracks how fresh the embedded schema is; a node that doesn't resolve adds no scope (a lone such node is denied as an unscoped write).
- A GraphQL query that reads `viewer`/`rateLimit` *alongside* a repository now also requires the `user`/`meta` unscoped category — grant them if your clients send such combined queries.
- The proxy trusts GitHub's node→repository resolution; it does not independently re-verify GitHub's responses.
- `mode = "allow"` permits anything the classifier cannot map to a deny rule. GraphQL node-ID reads/writes are resolved and checked **when the node's type is repo-scoped**; a node whose type the resolver does not recognize as belonging to a repository (e.g. a `ProjectV2`, which can be repo-owned) adds no scope, so under `allow` a `node(id:)` read of it falls through — as does a REST endpoint the classifier does not recognize as repo/org-scoped (e.g. repo-by-numeric-id `GET /repositories/{id}`). **Use `mode = "deny"` for a safe baseline** (there, an unmapped node/endpoint is denied, not allowed); reserve `allow` for low-stakes setups where you accept that anything unmapped is permitted.

## Testing against real GitHub

Unit tests run against a mock; two scripts validate the parts a mock can't:

- **`scripts/smoke-test.sh [owner/repo]`** — confirms the node-resolution GraphQL query is schema-valid on live GitHub and that media-type passthrough (`diff`/raw) works end to end. Read-only; defaults to the public `cli/cli`.
- **`scripts/gh-cli-matrix.sh <proxy-host> <owner> <allowed-repo> <denied-repo>`** — drives real `gh` against a running proxy and asserts the policy boundary across everyday commands (read / write / enumerate / search; allowed vs denied vs other-owner; REST + GraphQL). Refuses to run unless `gh` is actually on the proxy (the `bgh-proxy` canary), and creates + closes one transient probe issue in the allowed repo.

```bash
./scripts/gh-cli-matrix.sh proxy.example.ts.net myuser my-allowed-repo my-denied-repo
#   ... 22 passed, 0 FAILED
#   Every command behaved per policy.
```

The full set of bypass vectors (REST case/traversal; GraphQL multi-root / `node(id:)` / search / node-id mutation / cross-repo navigation / reserved-alias / gzip) is covered against the mock in `internal/{proxy,gqlfilter,classifier}`.

## Undoing

```bash
# Stop using the proxy
gh config unset http_unix_socket

# Stop the server
pkill bgh-proxy
```
