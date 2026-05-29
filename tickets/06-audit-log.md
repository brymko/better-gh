# 06 — Audit Log

**Depends on**: 04

## Summary

Log every request as JSONL.

## Tasks

- [ ] `AuditEntry` struct: `ts`, `method`, `path`, `repo`, `access`, `policy_result`, `github_status`, `duration_ms`
- [ ] Async writer: `tokio::sync::mpsc` channel, dedicated task appending to file
- [ ] Log allowed and denied requests
- [ ] Configurable file path via `audit_log` in `bgh-proxy.toml`
- [ ] Default path: `~/.config/bgh/audit.jsonl`

## Acceptance

Every proxied and denied request produces a JSONL line. `cat audit.jsonl | jq .` works.
