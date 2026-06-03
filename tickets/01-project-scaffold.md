# 01 — Project Scaffold

> **Historical note:** these tickets describe the original *Rust* plan. The implementation
> shipped in **Go** (`go.mod`, `cmd/bgh-proxy`, `internal/*`); the Cargo/axum/tokio steps below
> map to the Go stdlib `net/http` server + `BurntSushi/toml` + `vektah/gqlparser` in the code.
> See [README.md](../README.md) and [SPEC.md](../SPEC.md) for the as-built design.

## Summary

Set up the Rust project for `bgh-proxy`.

## Tasks

- [ ] Create Cargo project `bgh-proxy`
- [ ] Add dependencies: `axum`, `reqwest` (with `rustls-tls`), `tokio`, `clap`, `serde`, `serde_json`, `toml`, `chrono`
- [ ] Stub `main.rs` with clap: `bgh-proxy serve [--config path]`
- [ ] Add `rust-toolchain.toml` (nightly)
- [ ] Add `.gitignore`
- [ ] Verify `cargo build` and `bgh-proxy --help`

## Acceptance

Binary builds. `--help` prints usage.
