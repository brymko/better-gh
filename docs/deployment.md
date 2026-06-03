# Deploying bgh-proxy for remote clients (with a trusted TLS cert)

When the proxy runs on a remote host (a VPS) and clients reach it over the network,
`gh` must trust the proxy's TLS certificate. bgh-proxy's built-in cert is **self-signed**
(meant for localhost), so a remote client would otherwise need a CA install — and on macOS
that means a **global** keychain root (`gh`/Go ignore `SSL_CERT_FILE` on darwin), which can
MITM any site. That's a poor fit for the model where the **client is assumed compromised**.

The clean answer is to give the proxy a **publicly-trusted** certificate, terminated on the
**server** side, so the client needs *nothing* but the scoped `bgh_` token:

- **Tailscale Serve** — a real Let's Encrypt cert on your `*.ts.net` name, reachable only by
  your tailnet. No public exposure, no domain. *Recommended for private servers.*
- **Caddy + Let's Encrypt** — a real cert on a public domain. Use when clients aren't on a
  tailnet.

Both keep all "new software" on the **server** (which holds the real token and is trusted);
the infected client runs only `gh`. Neither requires SSH credentials on the client (putting
SSH-to-the-proxy-host on a compromised client would be strictly worse than the problem).

In both, run the proxy bound to **loopback** and let the front terminate TLS:

```toml
# ~/.config/bgh/config.toml
bind        = "127.0.0.1:7843"          # loopback only; the front reaches it here
mode        = "ghe"
external_url = "https://<public-name>"  # so the `gh auth login` device-flow URL is the public one
```

`external_url` matters because, behind a TLS-terminating front, the proxy can't infer the
public address from the request — set it to exactly what clients type after `--hostname`.

---

## Option A — Tailscale Serve (private, real cert, no domain)

### One-time tailnet setup (admin console — free)
1. **MagicDNS** enabled.
2. **HTTPS certificates** enabled — <https://login.tailscale.com/admin/dns> → "HTTPS Certificates".
3. **Serve** enabled — <https://login.tailscale.com/f/serve>.
4. *(Recommended)* an ACL so client nodes can reach **only** the proxy's serve port — see below.

### On the proxy host (joined to the tailnet)
```bash
# 1. set external_url to this node's MagicDNS name, e.g.:
#    external_url = "https://vps.tailnet.ts.net"
# 2. start the proxy (loopback). No token needed — the first GitHub sign-in below
#    captures the custodian and claims the deployment (TOFU). (Pre-seed BGH_GITHUB_TOKEN
#    only if the proxy must forward before anyone signs in.)
bgh-proxy serve
# 3. front it with a real cert (helper: scripts/serve-behind-tailscale.sh):
tailscale serve --bg https+insecure://127.0.0.1:7843
#    serves https://vps.tailnet.ts.net/  → proxies to the loopback proxy
```
`https+insecure://` only skips verifying the *loopback* self-signed cert (transport between
Tailscale and the proxy on the same host); the cert clients see is the real Let's Encrypt one.

### On any tailnet client — zero trust setup
Sign in once (the first sign-in claims the deployment + captures the custodian; afterwards
only that GitHub account may sign in):
```bash
# Web: open https://vps.tailnet.ts.net/ui → Sign in with GitHub → owner console (create/list/revoke tokens) → copy the token
# CLI:
gh auth login --hostname vps.tailnet.ts.net   # browser flow; mints a scoped token
gh pr list -R allowed/repo
```
The Let's Encrypt root is already in every OS trust store, so `gh` and the browser trust it
with no keychain change, no `SSL_CERT_FILE`, no SSH.

### Hardening: contain a compromised client with an ACL
A tailnet node key on an infected client grants *network reach to allowed ports* — not a
shell (unlike SSH). Restrict it to just the proxy so a compromise can reach nothing else:
```jsonc
// tailnet policy (admin console → Access Controls)
{
  "acls": [
    // clients tagged :workstation may reach ONLY the proxy node's serve port
    { "action": "accept", "src": ["tag:workstation"], "dst": ["tag:bgh-proxy:443"] }
  ]
}
```
Then a compromised client can reach the proxy (gated by its scoped token) and nothing else
on the host — and the only secret on it is that scoped token.

### Teardown
```bash
tailscale serve reset
```

---

## Option B — Caddy + Let's Encrypt (public domain)

Use when clients are not on a tailnet. The proxy becomes reachable on the public internet.
Normal API traffic is gated by the `bgh_` token (256-bit; brute force is infeasible) — **but the
`/login/*` and `/ui` endpoints are NOT token-gated**: they are the token-*acquisition* surface, so
they accept unauthenticated requests and are protected only by the GitHub owner sign-in (a non-owner
cannot mint a token). Two consequences for a public deployment:

- **Token minting still requires owning the deployment** (the first-sign-in TOFU gate), so exposure
  does not let a stranger mint tokens. But the device-flow start endpoints are an unauthenticated
  surface: they are rate-limited and capped (a flood is refused with `429`/`503`), yet you should
  still **prefer Option A or a network allowlist** so untrusted clients can't reach them at all.
- **Device-code phishing** is inherent to the device flow: an attacker who tricks *you* (the owner)
  into completing a sign-in they initiated could obtain the resulting token. Only complete a sign-in
  you started yourself, and confirm the user code matches the one in your own terminal/browser.

### Prerequisites
- A domain, e.g. `proxy.example.com`, with an A/AAAA record → the VPS.
- TCP **80** and **443** open (80 for the ACME challenge, 443 for serving).

### Caddyfile (see `scripts/Caddyfile.example`)
```caddy
proxy.example.com {
    reverse_proxy https://127.0.0.1:7843 {
        transport http {
            tls_insecure_skip_verify   # backend is the proxy's self-signed loopback cert
        }
    }
}
```

### Run
```bash
# config.toml: external_url = "https://proxy.example.com"
bgh-proxy serve                      # loopback proxy; sign in (below) to bootstrap the custodian
caddy run --config Caddyfile.example # auto-provisions the Let's Encrypt cert
```

### Client — zero trust setup
Open `https://proxy.example.com/ui` for the owner console (sign in with GitHub → create / list / revoke tokens), or:
```bash
gh auth login --hostname proxy.example.com
```

---

## Why not the alternatives (for the compromised-client model)

| Approach | Verdict |
|---|---|
| **SSH `-L` forward** | ✗ Requires SSH creds to the proxy host on the infected client → lateral movement to the box that holds the *real* token. Strictly worse than the problem. |
| **Install the self-signed CA in the client keychain** | ✗ A global root CA that can MITM *any* site; persistent system change on an untrusted machine. |
| **`SSL_CERT_FILE=ca.pem gh …`** | ~ Works and is *process-scoped* (good) — **but only on Linux**. macOS/Go ignores it. |
| **Real cert, terminated server-side (this doc)** | ✓ Client needs nothing but the scoped token. |

`gh auth login`'s OAuth client also bypasses `http_unix_socket` (it dials the host directly
over TLS), so a forwarded unix socket can't carry the interactive login — another reason the
trusted-cert route is the one that "just works".

## Client gotchas — make sure gh actually uses the proxy

The proxy only enforces policy on traffic that reaches it. `gh` has two ways to silently route
around it — both bit us in testing:

- **`GITHUB_TOKEN` / `GH_TOKEN` env var** — if set, `gh` uses it and talks to `github.com`
  directly, *ignoring `--hostname`*. `unset GITHUB_TOKEN GH_TOKEN`.
- **`http_unix_socket`** — if `gh config get http_unix_socket` returns a path (e.g. a local
  socket-mode proxy you ran earlier), `gh` routes **everything** through that socket regardless
  of `--hostname`, and socket mode applies its *own* policy + custodian, ignoring the client
  token. Clear it: `gh config set http_unix_socket ""`.

Confirm you're actually on the proxy: `gh api user --hostname <proxy>` returns
`{"login":"bgh-proxy"}` (a synthetic identity). If it returns your real GitHub profile, one of
the above is bypassing the proxy.

## Policy tips

`gh repo list` / `gh org list` enumerate **an owner** (your account) via
`repositoryOwner(login:)` / `user(login:)`, so they are classified as an **org** scope — they
need an `org` rule for your username, not just per-repo rules:

```toml
[[org]]
name = "your-login"               # lets `gh repo list` / `gh org list` enumerate your account
access = "read"

[[repo]]
name = "your-login/private-thing" # ...while still redacting a specific repo from the listing
access = "none"
```

(A fully denied repo is redacted to `null` in the GraphQL response, so `gh repo list` shows it
as a blank row rather than dropping it — its name and data never leave the proxy.)
