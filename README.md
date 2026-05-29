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

## Policy evaluation

```
Request for: my-org/frontend (write)

  1. Exact repo rule match?
     └─ my-org/frontend → read-write ✓ ALLOWED

  2. Org rule match?
     └─ my-org → read ✗ DENIED (write > read)

  3. Unscoped read? (allow_unscoped_reads)
     └─ only for requests with no repo/org

  4. Global default
     └─ deny ✗ DENIED
```

Access levels: `none` (block all), `read` (GET/HEAD only), `read-write` (all methods).

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
