---
name: current test framework + fixture pattern
description: standard cargo test + tests/common helpers; fixtures under tests/fixtures
type: project
originSessionId: 22222222-2222-4222-8222-222222222222
---

The project uses standard `cargo test`. Helpers live in `tests/common/mod.rs`
(imported by sibling test files via `mod common;`). Fixture data lives in
`tests/fixtures/<adapter>/`.

The three-command gate is `cargo fmt --check && cargo check --workspace
--all-targets && cargo clippy --workspace --all-targets && cargo test --workspace
--all-targets`. CI passes `--locked` on the cargo-touching commands.
