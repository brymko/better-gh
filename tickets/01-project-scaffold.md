# 01 — Project Scaffold

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
