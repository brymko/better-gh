# 04 — Proxy Core & Forwarding

**Depends on**: 02, 03

## Summary

The axum server: receive requests, classify, evaluate policy, forward to GitHub, return response.

## Tasks

- [ ] Axum server binding to configured address (default `127.0.0.1:7843`)
- [ ] Catch-all route for `/api/v3/*path` and `/api/graphql`
- [ ] Request pipeline:
  1. Validate client secret from `Authorization` header
  2. Classify request (ticket 02)
  3. Evaluate policy (ticket 03)
  4. Denied → 403 JSON: `{ "message": "bgh: denied — <reason>" }`
  5. Allowed → forward to GitHub
- [ ] GitHub forwarding via `reqwest`:
  - Rewrite `/api/v3/repos/...` → `https://api.github.com/repos/...`
  - Rewrite `/api/graphql` → `https://api.github.com/graphql`
  - Strip incoming auth, attach real GitHub token
  - Set `X-GitHub-Api-Version: 2022-11-28`
  - Forward `Content-Type`, `Accept`, request body
  - Stream response back: status, headers, body
- [ ] Config loading from `bgh-proxy.toml`
- [ ] Token from `BGH_GITHUB_TOKEN` env var or `github_token` config field
- [ ] Graceful shutdown on SIGTERM/SIGINT

## Acceptance

Proxy starts, forwards allowed requests to GitHub, returns responses. `curl http://localhost:7843/api/v3/repos/owner/repo` works when policy allows. Denied requests get 403.
