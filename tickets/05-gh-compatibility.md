# 05 — gh CLI Compatibility

**Depends on**: 04

## Summary

Make `gh auth login --hostname bgh.local` and subsequent commands work through the proxy.

## Tasks

- [ ] Spike: run `gh` against a local server, capture exactly what requests it makes during `gh auth login --hostname` and common commands. Document findings.
- [ ] `GET /api/v3` — return GHE-compatible root endpoint JSON. Determine the minimal fields `gh` requires.
- [ ] `GET /api/v3/user` — forward to GitHub and return (used by `gh auth login` to verify token)
- [ ] Handle both `Authorization: Bearer` and `Authorization: token` header formats
- [ ] Verify `Link` header pagination passthrough works
- [ ] Verify 403 error format displays correctly in `gh` output
- [ ] Test these commands end-to-end through the proxy:
  - `gh pr list -R owner/repo`
  - `gh pr view N -R owner/repo`
  - `gh issue list -R owner/repo`
  - `gh repo view owner/repo`
  - `gh api repos/owner/repo/pulls`
- [ ] Document any commands that don't work and why

## Acceptance

`gh auth login --hostname localhost:7843` succeeds. The listed commands produce correct output through the proxy.
