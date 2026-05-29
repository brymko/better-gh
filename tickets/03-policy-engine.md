# 03 — Policy Engine

**Depends on**: 02

## Summary

Load TOML policy and evaluate `(repo, access_level)` against it.

## Tasks

- [ ] Policy TOML structs:
  ```toml
  [defaults]
  mode = "deny"          # or "allow"

  [[org]]
  name = "my-company"
  access = "read"

  [[repo]]
  name = "my-company/frontend"
  access = "read-write"
  ```
- [ ] Load + validate: reject unknown fields, invalid access values
- [ ] `fn evaluate(&self, repo: Option<&str>, org: Option<&str>, access: AccessLevel) -> PolicyResult`
  - Exact repo match → use that rule
  - Else org match (extract org from `owner/repo`) → use org rule
  - Else global default
  - Compare requested access against allowed access (`Write` on a `read` rule → denied)
- [ ] `PolicyResult`: `Allowed` | `Denied { reason: String }`
- [ ] Tests: deny-default blocks unknown, org default applies, repo override wins, read request allowed on read-write rule, write request denied on read rule

## Acceptance

All resolution paths tested. Policy loads from file. Invalid configs produce clear errors.
