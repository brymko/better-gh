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

> [!IMPORTANT]
> `serve` defaults to **`mode = "both"`** (what `init` writes), which additionally starts the **GHE HTTPS listener** — mounting the *unauthenticated* `/login` + `/ui` sign-in surface. The **admin API/UI on `admin_bind`** (a full-access token-minting surface) starts in **every** mode, *including* `mode = "socket"` — it is not gated by mode. This is safe-by-default only because `bind`/`admin_bind` default to **loopback**. Setting `mode = "socket"` drops only the GHE `/login`+`/ui` listener (not the admin surface); for remote-only use set `mode = "ghe"`. **Firewall `admin_bind` regardless of mode**, and put any non-loopback listener behind a network allowlist (see [docs/deployment.md](docs/deployment.md)).

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

`gh` sends its own GitHub token, but the proxy ignores it and uses the **custodian** for upstream requests — the token captured by the first GitHub sign-in (`owner.json`) if the deployment has been claimed, otherwise the pre-seeded fallback (`BGH_GITHUB_TOKEN` / `github_token` / `bgh-proxy login`). In the default `mode = "both"`, a `gh auth login` / `/ui` sign-in on the GHE listener claims the deployment, and that captured token then backs **socket** traffic too. Either way the socket policy controls what gets through.

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

`[org.permissions]` apply both to the org's **repos** (via repo requests that fall through to the org rule — e.g. `pulls` governs `/repos/{org}/{repo}/pulls`) **and** to **org-direct subpaths**, keyed by the path's first sub-segment: `[org.permissions] members = "none"` denies `GET /orgs/{org}/members`, `hooks = "none"` denies `/orgs/{org}/hooks`, `blocks = "none"` denies `/orgs/{org}/blocks`, and so on. A subpath whose segment has no matching permission key falls back to the rule's base `access` (and the same applies to `/users/{user}/...`). Without this, a per-resource `none` on an org-direct resource was silently ignored on reads (the request fell back to base access).

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
| `contents` | `contents`, `readme`, `zipball`, `tarball`, `git/blobs`, `git/trees` | `object`, `blob`, `tree`, `createCommitOnBranch` |
| `actions` | `actions` | `Workflow`/`WorkflowRun`-class runtime types (`Environment` is `deployments`, see below) |
| `releases` | `releases` | `releases`, `release`, `latestRelease`, mutations containing `Release` |
| `commits` | `commits`, `compare`, `git/commits` | `commit`, `commitComments` |
| `branches` | `branches`, `git/refs`, `git/tags` | `refs`, `ref`, `defaultBranchRef`, mutations containing `Ref`/`Branch` (except `createCommitOnBranch`) |
| `checks` | `check-runs`, `check-suites`, `statuses` | mutations containing `Check` |
| `comments` | `comments` | — |
| `hooks` | `hooks` | — |
| `deployments` | `deployments`, `environments` | `deployments`, `environments`, mutations containing `Deployment` |
| `pages` | `pages` | — |
| `keys` | `keys`, `deploy-keys` | — |
| `metadata` | `stargazers`, `subscribers`, `topics`, `languages`, `tags`, `forks`, `contributors`, `collaborators`, `teams`, `license`, `community`, `traffic`, repo root | `name`, `owner`, `url`, `id`, `isPrivate`, `stargazers`, etc. |

> **Caveat:** several privacy/admin-sensitive sub-resources collapse into the coarse `metadata` key and **cannot be denied independently** of general repo metadata — notably `traffic` (clone/view analytics, normally admin-only), the `collaborators` roster, and `teams`. If those matter, deny the whole repo (`access = "none"`) rather than relying on a per-resource carve-out, or scope the custodian with a fine-grained PAT that excludes them.

> **Spell `[repo.permissions]` keys exactly as in the first column above.** A `[repo.permissions]` key that is **not** one of these is **rejected** — `bgh-proxy serve` refuses to start on a typo in `policy.toml`, and the mint paths (CLI/admin API, owner console, `gh auth login`) reject it with an error. (Earlier builds silently accepted a misspelled key like `contnets = "none"`; because it matched no request, the per-resource `none` was silently ignored and the resource fell back to the rule's base access — a fail-open footgun, now closed.) Note this validation covers **repo** keys; **org** per-resource keys are open-ended (any org subpath segment, e.g. `members`, `blocks`) and are **not** checked against a fixed list — so a misspelled `[org.permissions]` key **silently fails open** (the real resource falls back to the rule's base access). Org keys *are* matched case-insensitively, but for an org-direct deny carve-out, double-check the segment name or deny at the base access level. (The GraphQL owner-root fields `membersWithRole`/`teams` are enforced against the `members`/`teams` keys, matching the REST `/orgs/{org}/{members,teams}` paths.)

The low-level **Git Data API** (`/repos/{owner}/{repo}/git/*`) has no resource key of its own; it is governed by the resource its operation actually touches — `git/refs`, `git/tags` → `branches`; `git/blobs`, `git/trees` → `contents`; `git/commits` → `commits` — so a `branches = "none"` or `contents = "none"` rule covers the equivalent git-plumbing calls (creating/force-pushing a ref, reading raw file bytes) just as it covers the high-level paths. (Over GraphQL, per-resource enforcement on objects reached by navigation comes from the response filter's type→resource map, which is derived from GitHub's schema `@docsCategory` so it stays complete across schema refreshes — see the [Security model](#security-model).)

If the resource cannot be determined, the rule's base `access` level is used — **except** that a **write** whose resource is unrecognized or indeterminate is **denied** when the matching rule defines `[…permissions]` (fail-closed). This holds for both an unmapped REST sub-resource (e.g. `POST /repos/o/r/dispatches`, which can trigger workflows, escaping `actions = "none"`) **and** a GraphQL mutation whose field maps to no specific resource (e.g. `addComment`, `addReaction`, `lockLockable`), so neither can dodge a per-resource `none`. Reads, and rules without per-resource permissions, still fall back to the base `access`.

For GraphQL **mutations addressed by node ID**, the per-resource key is taken from the **resolved object's type** (a node GitHub confirms is a `PullRequest` is `pulls`, an `Issue` is `issues`, …), not from the mutation's name — so `addComment` on a pull request is governed by `pulls` and on an issue by `issues`, and `mergeBranch` (which advances a branch) is governed by `branches`. This means a per-resource rule applies to the resource a mutation actually touches regardless of how the mutation is named.

### Access levels

| Level | Permits | REST methods | GraphQL |
|---|---|---|---|
| `none` | Nothing | All blocked | All blocked |
| `read` | Read-only | `GET`, `HEAD` | Queries only |
| `read-write` | Everything | All methods | Queries and mutations |

Aliases: `"write"` and `"readwrite"` are accepted as synonyms for `"read-write"` — there is **no write-only level**, so `--repo o/r=write` grants full read **and** write.

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

3b. Unscoped write guard
   → if access=write AND repo="" AND org="" → deny ("unscoped write")
      (a write with no repo/org never falls through to `mode = "allow"`; the only
       exception is step 3 already granting that category read-write, e.g.
       `[defaults.unscoped] gists = "read-write"` permitting `POST /gists`)

4. [defaults].mode
   → "allow" → allow
   → "deny"  → deny
```

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
| `user(login:)` | `user(login: "octocat")` | org = `octocat` (e.g. `gh org list`) |

#### Unscoped requests

These requests have no identifiable repo or org. Under `mode = "deny"`, they are **denied by default** unless `[defaults.unscoped]` grants access for their category.

This matters because `gh` needs several of these endpoints to function — `gh auth status` calls `/user`, `gh repo list` (without an owner) calls `/user/repos`, and many commands start with a `{ viewer { login } }` GraphQL query.

> In **GHE mode** the proxy answers `GET /user` itself with a synthetic identity (`{"login":"bgh-proxy","id":0}`) so `gh auth login`/`status` can complete before any policy applies — this short-circuits the `user` category for that one GET (it returns fake, not custodian, data; any other `/user/*` path and all of socket mode are classified normally). The empty-path `GET /` GHE handshake is likewise answered synthetically (an empty JSON object `{}` plus a *fixed* placeholder `X-OAuth-Scopes: repo, read:org` header — a hardcoded constant, **not** the custodian's real scopes) and bypasses the `meta` category. Setting `user = "none"` therefore does **not** block GHE `GET /user` (nor does `meta = "none"` block `GET /`); `user = "none"` blocks `viewer{}`, `/user/repos`, `/user/orgs`, etc.

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
| `meta` | `rateLimit { ... }`, `__schema` / `__type` / `__typename` (schema introspection) | `gh repo list` (schema discovery) |

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

> **`--repo-perm`/`--org-perm` without a matching `--repo`/`--org` create a base-`none` rule.** A bare `--repo-perm owner/repo:pulls=read-write` (no `--repo owner/repo=…`) grants **only** `pulls` — the rule's base access is `none`, so every other resource of that repo stays denied. (This matches socket-mode `policy.toml`, where a `[repo.permissions]` block with no `access =` line defaults the base to `none`. Earlier builds defaulted the auto-created base to `read`, silently making the whole repo readable — e.g. `GET .../contents/.env` — which was the opposite of the operator's likely intent.) To grant a read base alongside a per-resource write, pass `--repo owner/repo=read --repo-perm owner/repo:pulls=read-write` explicitly.

### Web UIs

Two separate UIs, different auth:

- **Owner console** — `/ui` on the **GHE HTTPS** listener, authenticated by **GitHub sign-in** (the deployment owner). List / revoke / edit (re-issue) / create tokens, via a builder (repo/org fields autocompleted from your own account) or a pasted TOML policy. This is the one remote clients reach — see **GHE mode** above. **Note:** tokens minted through a GitHub sign-in (the owner console *and* `gh auth login`) have their `user` and `meta` unscoped categories raised to at least `read` (so the post-login `{viewer{login}}` check and the GHE handshake succeed); `bgh-proxy token create` and socket-mode `policy.toml` do **not** do this. `user`/`meta` are not repo data, so this never widens repo access.
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

All endpoints require `Authorization: token <admin-secret>`. Token changes go through the running server, so `revoke`/`delete` take effect immediately (do not edit `tokens.json` by hand while the server is running — it rewrites the file on create/revoke/delete and on last-used updates, at most once per minute per token, so a hand edit can be clobbered).

## Configuration

`~/.config/bgh/config.toml`:

```toml
bind = "127.0.0.1:7843"           # GHE HTTPS listener
admin_bind = "127.0.0.1:7844"     # Admin UI (plain HTTP, loopback)
socket = "~/.config/bgh/proxy.sock"
mode = "both"                     # "socket", "ghe", or "both"
# github_token = "ghp_..."        # optional fallback custodian (or BGH_GITHUB_TOKEN); the first sign-in captures one
# external_url = "https://proxy.example.com"  # public URL when behind a TLS-terminating front (Tailscale/Caddy) — used in the device-flow verification URL
# oauth_client_id = "..."         # OAuth app for sign-in / `bgh-proxy login` (default: gh's public app, no registration); for `bgh-proxy login` the BGH_OAUTH_CLIENT_ID env var / --client-id flag override this
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
{"ts":"2026-05-26T14:30:03Z","method":"GET","path":"/orgs/acme/members","org":"acme","resource":"members","access":"read","policy_result":"denied: org 'acme' resource 'members' policy is none, requested read","github_status":null,"duration_ms":3,"mode":"ghe","token_name":"ci-bot"}
```

Each entry records the decision scope: `repo` (`owner/repo`) for repo-scoped requests, `org` for org/user-scoped requests (`/orgs/{org}/…`, `/users/{user}/…`), `unscoped_category` for the rest, plus the `resource` the request touched.

> The audit log is itself **confidentiality-sensitive**: it records the repo/org names and full paths of *every* request, including **denied** ones — so it enumerates the private-repo names a client tried (and failed) to reach, plus every allowed access pattern, in cleartext. Keep `audit.jsonl` at `0600` and, if you ship it off-host, treat the destination as private. It is also **best-effort** (async, bounded queue): under sustained overload entries are dropped and a `SYSTEM` entry records the dropped count — don't treat it as a guaranteed record of every decision.

## Security model

The proxy holds one **powerful upstream GitHub token** — by default the broad token captured from your GitHub **sign-in** (`repo read:org gist workflow`: full read/write to every private repo you can see) — and hands out **narrow access** to clients. The goal: a client must not be able to exceed the policy it was given, even though the upstream token can do far more.

**Where the boundary is — read this first.** Avoiding fine-grained PATs *is the point* of this project (they're coarse to manage, never expire, and still can't express per-repo read-only or per-resource grants). So the default custodian is a **broad** token and **the proxy's own classification + policy + response filtering *is* the security boundary** — there is **no GitHub-side floor** behind it. That has a sharp consequence: where the proxy **fails closed** it is sound on its own. Both read paths now fail closed: the GraphQL filter types each query against the embedded schema and denies what it can't tag, and the REST filter types each response against GitHub's embedded **OpenAPI description** (`internal/restfilter`) — it knows, for every endpoint, where repositories appear and redacts denied ones, and a path the spec doesn't describe is denied rather than forwarded. A narrowly-scoped fine-grained PAT *can* be pre-seeded as the custodian to add a GitHub-enforced floor, but that re-introduces exactly the PAT hassle this tool exists to remove — it's an opt-in trade-off, not the default (see the last bullet).

**Trust boundaries**
- **Socket mode** trusts the local user. The socket is created `0600` (owner-only connect), so only your user reaches it; `gh`'s own token is ignored and the single `policy.toml` applies to everything on the socket. Any process running as you gets that policy.
- **GHE mode** trusts whoever holds a valid proxy token, plus whoever trusts the self-signed CA. Each proxy token carries its own embedded policy. Tokens are stored as SHA-256 hashes (`tokens.json`, `0600`) and compared in constant time.
- The **admin API/UI** (token minting) is guarded by a separate `admin-secret`. Anyone with it can create full-access tokens.
- The **`/login/*` and `/ui` endpoints are unauthenticated** (they are the token-*acquisition* surface, mounted on the GHE listener). They do **not** require a proxy token; minting is gated only by the **GitHub owner sign-in** (TOFU — a non-owner cannot mint). So exposing the GHE listener does not let a stranger mint a token, but it does expose an unauthenticated surface (device-flow starts — rate-limited and capped — and the classic **device-code phishing** risk: only complete a sign-in *you* initiated). The device-flow rate limit is keyed on the request source address, so behind a TLS-terminating front (Caddy/Tailscale Serve reverse-proxying from loopback) it is a single **global** cap, not per-client — it bounds a flood but is not a substitute for a network allowlist. **Keep the GHE listener network-access-controlled** (Tailscale ACL strongly preferred over a public Caddy domain); see [docs/deployment.md](docs/deployment.md).

**What is enforced**
- Per-repo / per-org / per-resource read vs write, deny-by-default.
- GraphQL queries are scoped to **every** repository/org/search target they touch — a query touching a denied repo alongside an allowed one is denied. `operationName` is honored.
- GraphQL requests that address objects by node ID (mutations, and `node(id:)`/`nodes(ids:)` reads) are scoped by **authoritative resolution**: each node ID is resolved to its real repository by GitHub before the request is authorized, so it cannot be misdirected to a repo the token can't access. A node ID that resolves to an **org/user/enterprise-owned** type (Organization, Team, ProjectV2, audit entries, **Gist** — owner-private, not repo-attributable) **fails closed** — read such an object via the policy-checked `organization(login:)`/`user(login:)`/`viewer` root instead. (The `enterprise(slug:)` root is likewise scoped to its slug as an org.)
- Names match case-insensitively (GitHub routes them that way), so a re-cased path can't dodge a rule.
- Requests with `.`/`..` path segments (including `%2F`-encoded) are rejected `400`.
- Unparseable, over-deep, or cyclic GraphQL fails closed (denied), and never crashes the proxy.
- **GraphQL read isolation is enforced by schema-aware response filtering.** The proxy types each read against GitHub's GraphQL schema, rewrites it to tag every repo-scoped object with its repository **and its type**, forwards it, and then **redacts from the response** every object the policy denies for that **(repository, resource)** — the resource derived from the tagged type (`PullRequest`→`pulls`, `Issue`→`issues`, …). This is sound no matter how the query reaches a repo — multi-root, `owner.repositories`, `owner.repository(name:)`, `forks`, `node(id:)`, search results, `viewer { repositories }`, and selections written against an **interface/union** type (e.g. `... on Comment { body }`, or a field typed `ReferencedSubject`/`Node`): the proxy injects a marker for every repo-scoped concrete type the selection could resolve to, so whichever object comes back self-identifies its repository. Each repo-scoped datum is checked against its *real* repository, and a per-resource restriction like `pulls = "none"` is enforced even on objects reached by *navigation*, not just at the entry point (including repo-owned content types that have **no direct repository link** — timeline events, deployment reviews, single-select issue-field options, … — which are tagged with their type and attributed to their nearest enclosing repository, then per-resource-checked there; the navigation analogue of the round-16 `node(id:)` fail-closed for the same types). Denied data comes back as `null`; allowed data is untouched. (This also means enabling the `user`/`search` categories no longer leaks denied-repo *contents* via enumeration — those repos are redacted.) The **same filtering covers mutation response payloads** (a mutation's return selection is itself a read sub-graph), so a write grant on one repo cannot read a denied repo through the value a mutation returns.
- **The filter sees plaintext and fails closed.** The proxy does **not** forward the client's `Accept-Encoding`, so upstream responses arrive decompressed and every body can be typed and redacted; a GraphQL response that cannot be parsed is **denied**, never passed through. A query that pre-declares the proxy's reserved marker alias (which could otherwise suppress a repository tag) is rejected (fail closed).
- **REST responses are redacted too — typed against GitHub's OpenAPI spec.** Coverage and the location of every repository in each endpoint's response are **derived mechanically from GitHub's embedded OpenAPI description** (`internal/restfilter`, generated into `openapi_table.go`), not a hand-maintained list — so the whole REST surface is covered, including the many endpoints earlier builds missed (`/user/repos`, `/orgs/{org}/{repos,issues}`, the activity feeds `/{,orgs/{org}/,users/{u}/}events`, `/users/{u}/{starred,subscriptions}`, the org alert feeds `/orgs/{org}/{secret-scanning,dependabot,code-scanning}/alerts` — including the **cleartext secret-scanning secret** — `/orgs/{org}/teams/{team}/repos`, `/{orgs/{org},user}/migrations` whose nested `repositories[]` is redacted in place, `/search/*`, …). Denied-repo entries are dropped (or a singleton repo nulled); a search that drops matches has `total_count` rewritten to the kept count (with `incomplete_results`) so it can't serve as an existence oracle. A response that embeds a *full* issue/PR of another repo through a **cross-reference** (the issue timeline's `cross-referenced` event, whose `source.issue` may be in a denied repo even when the path repo is allowed) is **scrubbed** in place — the foreign `source` is nulled while the event row survives — since dropping the whole event would delete every ordinary timeline entry (`internal/restfilter` cross-ref scrub). The same scrub nulls a pull request's `head.repo` / `base.repo` (each a *full* Repository of a possibly-denied fork) on `GET /repos/{o}/{r}/pulls`, `/pulls/{n}`, and `/commits/{sha}/pulls` while keeping the PR row (round-17), **and on the matching WRITE responses** that echo the same shape (`POST`/`PATCH /pulls`, `POST`/`DELETE /pulls/{n}/requested_reviewers`, `PATCH /repos/{o}/{r}`, `POST /forks` — round-20/21), since write responses are otherwise streamed unfiltered. The per-resource carve-out is also enforced on the cross-repo **content** feeds (`/user/issues`, `/search/issues`, `/search/code`, `/notifications`, and the activity-event feeds `/{,orgs/{org}/,users/{u}/}events` whose `payload.issue`/`pull_request` content is dropped when `issues` is denied), and the org-named bare-repo array `GET /orgs/{org}/attestations/repositories` is redacted with the path org. Without this, the `user`/`search`/`notifications`/`events` categories — or a `[[org]]`-read token with a per-repo `none` carve-out — could enumerate denied repos' metadata, read their code via `/search/code`, or read a carved-out repo's issue content via the feeds, sidestepping the GraphQL filter. Like the GraphQL filter it **fails closed**: a recognized repo-bearing response that can't be parsed (or is too large to buffer) is denied, and a GET whose path is off-spec is denied unless the classifier already scoped it to one repo. An endpoint the spec marks *repo-free* (`Pass`) is **not** forwarded blind either: for a non-path-scoped response the proxy scans the actual JSON for a repository identity the spec may have under-located (an untyped/opaque response schema) and **fails closed if a denied repo is present** — and a Pass op that names its repo only by an opaque numeric id the scan cannot map (the Copilot `/agents/tasks` lookups) fails closed when not path-scoped — while binary downloads and path-scoped responses still stream untouched.
- **The upstream token's reach is not advertised.** The `X-OAuth-Scopes`, `X-Accepted-OAuth-Scopes`, and `X-OAuth-Client-Id` response headers (which reveal the custodian token's scopes and OAuth client), `X-GitHub-SSO` (the SAML-SSO organizations the custodian is authorized for), `Github-Authentication-Token-Expiration` (the custodian's expiry timestamp / token-type), and any upstream `Set-Cookie`, are stripped from forwarded responses; the request-side `Cookie` header is not forwarded upstream either. So a proxy-token holder cannot learn how powerful the real token is, which orgs it reaches, or when it expires. Header stripping is a denylist of these known custodian-reach headers; benign headers (`ETag`, `Link`, the `X-RateLimit-*` family, `X-GitHub-Request-Id`, …) still pass.

**What is *not* a boundary** — read these before trusting it:
- **REST read isolation is typed against the OpenAPI spec and fails closed (like GraphQL) — bounded only by spec freshness.** Single-repo REST paths (`/repos/{owner}/{repo}/…`) are scoped by the classifier; multi-repo responses are redacted at the repository locations the embedded OpenAPI description gives for each endpoint (derived mechanically, not hand-listed — so coverage is the whole REST surface, including endpoints earlier builds missed). A GET whose path the spec doesn't describe is **denied**, not forwarded (unless the classifier already scoped it to one repo). The one residual is the same as GraphQL's: a brand-new GitHub endpoint not yet in the embedded spec is denied until the spec is refreshed (an availability cost, not a leak). Regenerate the table from GitHub's published spec periodically (`go run ./internal/restfilter/gen`).
- **The response filter is only as current as its embedded schema.** It is sound for any query it can type. A query using a field newer than the proxy's schema snapshot can't be tagged, so it is **denied outright** — a GraphQL request is fully filtered or denied, never forwarded unfiltered. (Earlier builds fell back to the classifier's cross-repo-nav denylist for untyped reads, but that denylist isn't complete enough to bound them, so a scoped read navigating cross-repo via an unlisted field could leak under drift; the proxy now fails closed instead.) Keep the schema reasonably fresh (`internal/gqlfilter/schema.graphql`); a stale schema costs availability (newer-field queries are denied), not isolation.
- **Per-resource redaction is driven by the schema's own categorization.** The filter tags each object with its GraphQL type and enforces per-resource policy (e.g. `pulls = "none"`, `deployments = "none"`) on it wherever it appears — entry point *and* navigation. The type→resource map is **derived from each type's `@docsCategory` directive in GitHub's embedded schema** (with a few overrides where the category names a different axis, e.g. commit statuses → `checks`, git refs → `branches`), and a build-time invariant (`gqlfilter.TestR15_TypeResourceCoverageInvariant`) fails the build if any repo-scoped type whose category is a real per-resource key would map to `metadata` — so a schema refresh cannot silently reintroduce a per-resource fail-open. A repo-scoped type whose `@docsCategory` has **no** dedicated per-resource key (discussions, projects, packages, security-advisories, …) falls back to the rule's base access; such types have no per-resource policy key to enforce anyway. Keep the embedded schema fresh so the mapping stays current.
- **Only response `data` is redacted, not GraphQL `errors`.** A denied/absent repo's *name* can still surface in an upstream error message (e.g. "Could not resolve to a Repository …"). This isolates repo *contents*, not the existence/names of repos a query already references.
- **Counts and aggregates leak; only contents are redacted.** The filter removes denied-repo *objects* from a GraphQL response, but a connection's `totalCount` / `search`'s `issueCount`/`repositoryCount`/`discussionCount` are scalars computed by GitHub over the full (pre-redaction) set, so they reveal *how many* denied items matched — and `totalCount − len(nodes)` discloses the hidden count regardless of how elements are dropped. In particular `search(query:"<text>", type:ISSUE){ issueCount }` is an existence oracle for issue/PR/discussion *text* in denied repos, and `viewer { repositories { totalCount } }` leaks the custodian token's repo breadth. This is not soundly closable in the response filter (count fields can be aliased, `totalCount` is a cross-page total, and stripping counts would break legitimate counts on *allowed* repos), so it is an **accepted residual** of being a policy proxy over a broad token: contents are redacted, counts/existence are not. (The REST `/search` `total_count` is opportunistically rewritten to the kept count; GraphQL counts are not. A fine-grained PAT custodian would stop GitHub counting denied repos at the source, but that's opt-in — see the last bullet.)
- **Only the GitHub API is proxied, not git.** The proxy serves `/api/v3` + `/api/graphql` (plus `/login`/`/ui`), not git transport — so `gh repo clone` / `git push` *through the proxy* fail (it is not a git server), and git traffic is never carried or filtered by it. Policy governs **API** access (including reading file contents via the `contents` API); cloning or pushing a repo's code over git is out of scope. A client that also holds a direct `github.com` credential can run git (and API) straight to GitHub, bypassing the proxy entirely — see [docs/deployment.md](docs/deployment.md) "Client gotchas".
- **An optional fine-grained PAT custodian is the *only* way to get a GitHub-enforced floor — and it runs against the project's grain.** By default the custodian is your broad sign-in token and the proxy is the sole boundary. If you pre-seed a fine-grained PAT (`BGH_GITHUB_TOKEN` / `github_token`) scoped to only the repos the proxy should reach, GitHub itself bounds every request — typed or not, listed or not — so the residuals above (the count oracle, a host compromise's blast radius, a brand-new endpoint not yet in the embedded spec) collapse to what that PAT can see. But this re-introduces exactly the coarse-PAT management this project exists to avoid, so it's a deliberate trade-off for high-stakes setups, **not** the recommended default.
- It does not authenticate *which* local process uses the socket, only that it is your user.
- mTLS / per-identity client certs are not implemented; GHE-mode identity is the bearer proxy token.

## Deployment & operations

- **Rotation, backup & incident response.** See [docs/deployment.md](docs/deployment.md) → "Operations & incident response" for the full runbook: rotating the captured custodian token, **rotating the `admin-secret`** (delete the `admin-secret` file and restart — note that rotating the custodian or deleting `owner.json` does **not** invalidate it; it independently mints full-access tokens), clearing a pre-seeded fallback custodian, backing up `owner.json`/`tokens.json`/`admin-secret`, shipping the audit log off-host, and responding to host / owner-account / client-token compromise.
- **Token custody.** The real GitHub token sits on the proxy host (**plaintext** — encrypted storage is not implemented), and by default it is your **broad sign-in token**: full `repo` access to everything you can see. Whoever can read the host's memory/config has all of that. The proxy concentrates one powerful credential on one host *by design* — so that clients never hold it — which makes **protecting that host paramount** (it is the thing the whole model trades for client-side safety). Optionally pre-seeding a fine-grained PAT as the custodian bounds a host compromise to that PAT's repos, at the cost of the coarse-PAT management this project avoids.
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
- `mode = "allow"` permits anything the classifier cannot map to a deny rule. GraphQL node-ID reads/writes are resolved and checked **when the node's type is repo-scoped**. A resolved node whose runtime type the *embedded schema* does not recognize at all (live schema drift) fails **closed**, and a node whose type is **unambiguously repo-owned but has no schema path to its repository** (e.g. `Workflow`, `DeployKey`, `ClosedEvent`, `DeploymentReview`, `RepositoryTopic` — derived from `@docsCategory`) also fails **closed** (round-16), so it can't be used to read a denied repo. The remaining fall-through under `allow` is a node whose type is *genuinely ambiguous* — can belong to an org **or** a repo (e.g. a `ProjectV2`) — which adds no scope; deny-by-default avoids relying on this. REST is tighter under `allow` than it used to be: because the response filter is always active, a GET whose path the OpenAPI spec does not describe and that is not scoped to one repo is **denied off-spec** (e.g. repo-by-numeric-id `GET /repositories/{id}`), not forwarded, and a `Pass` (repo-free) response is scanned at runtime and **denied if it actually carries a denied repo** the spec did not locate (see below). **Use `mode = "deny"` for a safe baseline** anyway; reserve `allow` for low-stakes setups where you accept that anything unmapped-but-on-spec is permitted. With no upstream floor in the default deployment, there is nothing behind `mode = "allow"` to catch what it lets through, so deny-by-default is strongly preferred.

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
