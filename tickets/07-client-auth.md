# 07 — Client Auth (Local Mode)

**Depends on**: 04

## Summary

Generate a shared secret on startup so only the local user can access the proxy.

## Tasks

- [ ] On `bgh-proxy serve`, generate 256-bit random secret (32 bytes, hex-encoded)
- [ ] Write to `~/.config/bgh/client-secret` with mode 0600
- [ ] Create `~/.config/bgh/` directory if it doesn't exist
- [ ] On first run, print to stderr:
  ```
  bgh-proxy: client secret written to ~/.config/bgh/client-secret
  Setup: gh auth login --hostname localhost:7843 --with-token < ~/.config/bgh/client-secret
  ```
- [ ] Validate `Authorization: Bearer <secret>` or `Authorization: token <secret>` on every request
- [ ] Invalid/missing auth → 401 JSON: `{ "message": "bgh: unauthorized" }`
- [ ] Regenerate secret on each restart

## Acceptance

Requests without the correct secret get 401. Correct secret passes auth. `gh auth login --with-token` flow works.
