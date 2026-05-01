# nexum-core tests

This directory holds **integration tests** for `nexum-core` — anything that exercises
the public crate API end-to-end. Unit tests live alongside the code they test, in
`#[cfg(test)] mod tests` blocks inside `src/`.

## Conventions

- **Each integration test gets an isolated temp home** via `NexumTestHome` from
  `tests/common/mod.rs`. Never read or write `~/.nexum/` directly from a test.
- **Prefer `Paths::with_home(...)` over `Paths::resolve()`** in tests. `with_home`
  doesn't touch the environment, which keeps tests thread-safe — cargo runs tests in
  parallel by default and env vars are process-global.
- **Fixture data**, when needed by later phases, will live under
  `tests/fixtures/<adapter>/`. Each fixture is the smallest set of files that
  exercises a specific case; large fixtures get a one-line README explaining what
  they cover.
- **Snapshot tests** (when added in a later phase) use the `insta` crate and store
  snapshots under `tests/snapshots/`. Run `cargo insta review` after intentional
  output changes.

## Running

The three-command gate (also enforced by CI):

```sh
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets
cargo test --workspace --all-targets
```

To run only `nexum-core`'s tests:

```sh
cargo test -p nexum-core                              # all tests in this crate
cargo test -p nexum-core --test paths_smoke           # one integration test file
cargo test -p nexum-core paths::tests                 # one unit-test module
```

## Why `tests/common/mod.rs` and not `tests/common.rs`

Cargo treats every file directly under `tests/` as its own integration-test binary.
A `tests/common.rs` would compile + run as a test binary all on its own (with no
tests in it). Putting helpers in `tests/common/mod.rs` exempts them from that —
they're imported by sibling test files via `mod common;`.
