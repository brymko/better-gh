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

# Set your GitHub token
export BGH_GITHUB_TOKEN=$(gh auth token)

# Edit the policy
$EDITOR ~/.config/bgh/policy.toml

# Start the proxy
bgh-proxy serve

# Point gh at the proxy (socket mode)
gh config set http_unix_socket ~/.config/bgh/proxy.sock
```

## Two modes

### Socket mode (local use with `gh`)

`gh` sends all requests through a unix socket. No TLS, no proxy tokens needed — the socket file is `0600` so only your user can access it.

Policy is loaded from `~/.config/bgh/policy.toml`:

```toml
[defaults]
mode = "deny"
allow_unscoped_reads = true   # let /user/repos etc. through

[[org]]
name = "brymko"
access = "read"

[[repo]]
name = "brymko/better-gh"
access = "read-write"
```

`gh` sends its own GitHub token, but the proxy ignores it and uses `BGH_GITHUB_TOKEN` for upstream requests. The socket policy controls what gets through.

### GHE mode (remote clients, CI bots)

Listens on HTTPS with a self-signed cert. Each client gets a **proxy token** with its own scoped policy. Clients send the proxy token in the `Authorization` header.

```bash
# Create a token scoped to one repo
bgh-proxy token create --name ci-bot --default deny --repo my-org/my-repo=read

# Client uses the printed secret
curl -H "Authorization: token <secret>" https://localhost:7843/api/v3/repos/my-org/my-repo/pulls
```

## Policy specification

Policy files use TOML. In socket mode, the policy is loaded from `~/.config/bgh/policy.toml`. In GHE mode, each proxy token carries its own embedded policy.

### Full example

```toml
[defaults]
mode = "deny"                    # "deny" or "allow"
allow_unscoped_reads = true      # allow reads with no identifiable repo/org

[[org]]
name = "my-company"
access = "read"                  # default for all repos in this org

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
name = "personal/dotfiles"
access = "read-write"
```

### `[defaults]` section

| Field | Values | Description |
|---|---|---|
| `mode` | `"deny"` (default), `"allow"` | Fallback decision when no rule matches. |
| `allow_unscoped_reads` | `true`, `false` (default) | Allow unscoped read requests under deny-default. See [Unscoped requests](#unscoped-requests). Has no effect when `mode = "allow"`. |

### `[[org]]` rules

| Field | Values | Description |
|---|---|---|
| `name` | string | Org login, e.g. `"my-company"`. Exact match only, no globs. |
| `access` | `"none"`, `"read"`, `"read-write"` | Access granted to any repo in this org that doesn't have its own `[[repo]]` rule. |

Org matching uses the `owner` segment from REST paths (`/repos/{owner}/...`) or the `owner` argument from GraphQL `repository(owner:, name:)`. For org-scoped endpoints (`/orgs/{org}/...`), the org name is used directly.

### `[[repo]]` rules

| Field | Values | Description |
|---|---|---|
| `name` | string | Full `owner/repo` name, e.g. `"my-company/frontend"`. Exact match only. |
| `access` | `"none"`, `"read"`, `"read-write"` | Access granted to this specific repo. Takes priority over `[[org]]` rules. |

### Access levels

| Level | Permits | REST methods | GraphQL |
|---|---|---|---|
| `none` | Nothing | All blocked | All blocked |
| `read` | Read-only | `GET`, `HEAD` | Queries only |
| `read-write` | Everything | All methods | Queries and mutations |

Aliases: `"write"` and `"readwrite"` are accepted as synonyms for `"read-write"`.

### Evaluation order

For each request, the classifier extracts `(repo, org, access_level)`. The policy engine evaluates rules in this order:

```
1. Exact [[repo]] match on "owner/repo"
   → found: check access level → allow or deny
   → not found: continue

2. [[org]] match on org name
   → found: check access level → allow or deny
   → not found: continue

3. allow_unscoped_reads check
   → if enabled AND repo="" AND org="" AND access=read → allow
   → otherwise: continue

4. [defaults].mode
   → "allow" → allow
   → "deny"  → deny
```

Evaluation stops at the first matching rule. A `[[repo]]` rule always takes priority over an `[[org]]` rule for the same org, and both take priority over the default.

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

**GraphQL** — scope extracted from the query AST:

| Pattern | Example | Scope |
|---|---|---|
| `repository(owner:, name:)` | `repository(owner: "my-org", name: "frontend")` | repo = `my-org/frontend` |
| `search(query: "repo:...")` | `search(query: "repo:my-org/frontend is:open")` | repo = `my-org/frontend` |

Variables are resolved: `repository(owner: $owner, name: $name)` with `{"owner": "my-org", "name": "frontend"}` works.

**Node ID cache** — GraphQL mutations that reference objects by opaque node ID (e.g. `mergePullRequest(input: {pullRequestId: "PR_kwDO..."})`) have no repo in the query itself. The proxy caches `node_id → owner/repo` mappings from previous repo-scoped query responses (30 min TTL) and uses them to resolve scope for subsequent mutations. This is how `gh pr merge 123` works — `gh pr view 123` first queries the PR (repo-scoped), the response contains the node ID, and the merge mutation uses that cached mapping.

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

These requests have no identifiable repo or org. Under `mode = "deny"`, they are **denied by default**. Setting `allow_unscoped_reads = true` permits the read-only ones.

This matters because `gh` needs several of these endpoints to function — `gh auth status` calls `/user`, `gh repo list` (without an owner) calls `/user/repos`, and many commands start with a `{ viewer { login } }` GraphQL query.

**REST endpoints — reads (allowed by `allow_unscoped_reads`):**

| Path | `gh` command | Purpose |
|---|---|---|
| `GET /user` | `gh auth status` | Current authenticated user |
| `GET /user/repos` | `gh repo list` (no owner) | List your repos |
| `GET /user/orgs` | `gh org list` | List your orgs |
| `GET /user/starred` | `gh api user/starred` | List starred repos |
| `GET /user/subscriptions` | `gh api user/subscriptions` | List watched repos |
| `GET /gists` | `gh gist list` | List your gists |
| `GET /notifications` | `gh api notifications` | List notifications |
| `GET /search/repositories` | `gh search repos ...` | Search repos |
| `GET /search/issues` | `gh search issues ...` | Search issues/PRs |
| `GET /search/code` | `gh search code ...` | Search code |
| `GET /rate_limit` | `gh api rate_limit` | Check rate limit |
| `GET /feeds` | `gh api feeds` | Timeline feeds |
| `GET /events` | `gh api events` | Public events |
| `GET /` | (GHE handshake) | API root |

**REST endpoints — writes (always denied under deny-default, even with `allow_unscoped_reads`):**

| Path | `gh` command | Purpose |
|---|---|---|
| `POST /gists` | `gh gist create` | Create a gist |
| `POST /user/repos` | `gh repo create` (personal) | Create a repo |
| `PATCH /user` | `gh api -X PATCH user` | Update your profile |
| `PUT /notifications` | `gh api -X PUT notifications` | Mark all notifications read |
| `DELETE /notifications/threads/{id}` | — | Delete notification subscription |

**GraphQL — reads (allowed by `allow_unscoped_reads`):**

| Query | `gh` command | Purpose |
|---|---|---|
| `{ viewer { login } }` | most `gh` commands | Identify current user |
| `{ viewer { repositories(...) } }` | `gh repo list` | List your repos |
| `{ rateLimit { ... } }` | — | Check rate limit |
| `{ search(...) }` (no `repo:` qualifier) | `gh search ...` | Cross-repo search |

**GraphQL — writes (denied unless node ID cache resolves a repo):**

| Mutation | `gh` command | Purpose |
|---|---|---|
| `addStar(input: {starrableId: $id})` | `gh api graphql -f query='mutation...'` | Star a repo |
| `mergePullRequest(input: {pullRequestId: $id})` | `gh pr merge` | Merge a PR (resolved via node cache) |
| `closePullRequest(input: {pullRequestId: $id})` | `gh pr close` | Close a PR (resolved via node cache) |
| `addComment(input: {subjectId: $id, body: ...})` | `gh pr comment`, `gh issue comment` | Add a comment (resolved via node cache) |

Unscoped write mutations that reference a node ID will be resolved to a repo via the node ID cache if a previous query cached that ID. If the ID is not in the cache, the mutation is denied.

### Examples

**Deny-default, read one org, write one repo:**
```toml
[defaults]
mode = "deny"
allow_unscoped_reads = true

[[org]]
name = "my-company"
access = "read"

[[repo]]
name = "my-company/frontend"
access = "read-write"
```

Result: `gh pr list -R my-company/backend` works (read, org rule). `gh pr merge -R my-company/frontend` works (write, repo rule). `gh pr merge -R my-company/backend` denied (write > org read). `gh pr list -R other/repo` denied (default deny).

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
  [--org <org>=read|read-write|none]... \
  [--repo <owner/repo>=read|read-write|none]...
bgh-proxy token list
bgh-proxy token show <name-or-id>
bgh-proxy token revoke <name-or-id>
bgh-proxy token delete <name-or-id>
```

`token create` prints the secret to stdout (shown once, not retrievable again). The CLI talks to the admin API, so changes take effect immediately on the running server.

### Web UI

Admin UI served on a separate plain HTTP port (default `127.0.0.1:7844`). Open it in a browser, paste the admin secret to authenticate.

- List all tokens with status, creation date, last used
- Create tokens with org/repo rules via form
- View token details and policy
- Revoke tokens

### Admin API

```
GET    /api/tokens          List all tokens
POST   /api/tokens          Create token (JSON body)
GET    /api/tokens/{id}     Get token detail
DELETE /api/tokens/{id}     Revoke token
```

All endpoints require `Authorization: token <admin-secret>`.

## Configuration

`~/.config/bgh/config.toml`:

```toml
bind = "127.0.0.1:7843"           # GHE HTTPS listener
admin_bind = "127.0.0.1:7844"     # Admin UI (plain HTTP)
socket = "~/.config/bgh/proxy.sock"
mode = "both"                     # "socket", "ghe", or "both"
# github_token = "ghp_..."        # or set BGH_GITHUB_TOKEN
audit_log = "~/.config/bgh/audit.jsonl"
policy_file = "~/.config/bgh/policy.toml"
```

## Files

```
~/.config/bgh/
├── config.toml        # Server configuration
├── policy.toml        # Socket mode policy
├── tokens.json        # Proxy token store
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
{"ts":"2026-05-26T14:30:00Z","method":"GET","path":"/repos/brymko/better-gh/pulls","repo":"brymko/better-gh","access":"read","policy_result":"allowed","github_status":200,"duration_ms":142,"mode":"socket","token_name":"(socket)"}
{"ts":"2026-05-26T14:30:01Z","method":"POST","path":"/repos/unknown/repo/pulls","repo":"unknown/repo","access":"write","policy_result":"denied: default policy is deny","github_status":null,"duration_ms":5,"mode":"ghe","token_name":"ci-bot"}
```

## Undoing

```bash
# Stop using the proxy
gh config unset http_unix_socket

# Stop the server
pkill bgh-proxy
```
