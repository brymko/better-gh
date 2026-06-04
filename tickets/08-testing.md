# 08 — Testing

> **Historical note:** these describe the original *Rust* plan; the code shipped in **Go** (see go.mod and internal/). See ../README.md and ../SPEC.md for the as-built design.

**Depends on**: 04

## Summary

Unit and integration tests.

## Tasks

### Unit tests
- [ ] Request classifier: REST URL patterns, GraphQL mutation detection, edge cases
- [ ] Policy engine: deny-default, org defaults, repo overrides, access level checks
- [ ] Audit log entry serialization

### Integration tests
- [ ] Mock GitHub API (axum server returning canned responses for `/repos/*/pulls`, `/user`, root endpoint)
- [ ] Proxy integration: start proxy pointed at mock, send requests via `reqwest`:
  - Allowed read → 200, reaches mock
  - Allowed write → 200, reaches mock
  - Denied write on read-only policy → 403, mock not hit
  - Denied repo → 403
  - Invalid auth → 401
  - Audit log entries written for all cases
- [ ] Config loading: valid config, missing fields, invalid values

### CI
- [ ] GitHub Actions workflow: `cargo test`, `cargo clippy`, `cargo fmt --check`

## Acceptance

`cargo test` passes. Integration tests cover classify → policy → forward → audit pipeline.
