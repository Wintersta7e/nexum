<div align="center">

# nexum

**Cross-agent memory for AI coding tools.**

Keep what you and your agents learn from getting lost between sessions, between
tools, or to a tampered local file — one signed, searchable notebook over both
Claude Code and Codex CLI memory. Read it from the CLI or any MCP-aware host.

[![CI](https://github.com/Wintersta7e/nexum/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Wintersta7e/nexum/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Wintersta7e/nexum/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/Wintersta7e/nexum/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/gh/Wintersta7e/nexum/graph/badge.svg)](https://codecov.io/gh/Wintersta7e/nexum)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE-APACHE)
[![Rust](https://img.shields.io/badge/rust-1.95-orange?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![Edition](https://img.shields.io/badge/edition-2024-purple)](https://doc.rust-lang.org/edition-guide/rust-2024/)
[![SQLite](https://img.shields.io/badge/SQLite-FTS5%20%2B%20vec0-003B57?logo=sqlite&logoColor=white)](https://www.sqlite.org)
[![MCP](https://img.shields.io/badge/MCP-stdio-7C3AED)](https://modelcontextprotocol.io)
[![Status](https://img.shields.io/badge/status-personal%20%C2%B7%20actively%20developed-brightgreen)](#status)

</div>

---

## Why

If you use Claude Code and OpenAI Codex CLI side-by-side (or just one of them),
you've probably noticed: memory written in one tool is invisible to the other;
the "why" behind a decision evaporates by next week; failed approaches get
re-attempted because the lesson never made it into a memory file; and anyone who
can run code as you can edit your memory files — and your agent will trust
whatever's there.

`nexum` is one tool that addresses all four — a single signed, searchable
notebook layered over the memory both tools already write, with cryptographic
provenance so a malicious postinstall can't quietly inject memory your agent
will trust.

> A tool I built for myself to suit my own workflow. It's open source under
> Apache-2.0, and if you find it useful, you're welcome to use it. There's no
> adoption goal and no support guarantees, but issues and PRs are read.

## Status

Actively developed personal tool. The read path, the write path, the trust
state machine, the MCP stdio server, semantic ranking, typed extraction, and the
admin / recovery command surface are all in `main` and validated end-to-end
against real Codex + Claude Code data via the Docker harness. Three crates
compile clean; the gate is green at
`cargo fmt + check + clippy -D warnings + test`.

**Remaining work:** a recommendation → decision promotion flow when matching
commits land in your project repo.

## Features

### Reads & search

- **Hybrid reads** of both Claude Code's per-CWD memory and Codex's
  `~/.codex/memories/` as upstream — no replacement, no fragmentation.
- **Structured search** on the unioned corpus:
  `nexum search "concurrency" --type failure --since 30d` plus
  `nexum list / get / recent / by-session`. The `--metadata-type` filter slices
  by adapter-specific frontmatter type (e.g. CC's `feedback`, `reference`,
  `user`); every result row surfaces it as `metadata_type` alongside
  `record_type`.
- **Semantic ranking** when you opt in — `nexum models install bge-m3` downloads
  the SHA256-verified bge-m3 ONNX weights, flips the embed flag on, and
  `nexum search` then fuses FTS BM25 with vector k-NN via RRF. Search results
  carry `embed_status` and `vector_candidates` signals so agents can tell hybrid
  hits from FTS-only fallback.

### Trust & provenance

- **Cryptographic provenance** — every record nexum writes is signed with your
  SSH key (commits to `~/.nexum/notebook.git/`), so a malicious npm postinstall
  can't quietly inject memory your agent will trust.
- **Read-time trust projection** — the verifier projects `signature_status`,
  `trust_basis`, and a typed warning taxonomy on every read; warn / hide /
  strict policies route results without silently dropping evidence.
- **Tampering detection** — `nexum trust validate-events` and
  `nexum index --check` re-walk the trust-events history and exit non-zero when a
  forbidden mutation of `.trust/events.yml` is detected.
- **Trusted-key state machine** — bootstrap, key rotation, key compromise, and
  authorized re-anchor with a chain-anchor-lost warning all flow through one
  materialized view that read verbs consult per row.

### Agent surface

- **Agent-ready `--json` errors** — every read verb's failure under `--json`
  emits a wire-stable `ErrorEnvelope` to stdout: stable `error_code` string,
  structured `remediation` (command + rationale), and a per-variant `context`
  preserving fields like `path`, `signature_status`, and `matches`. Agents
  branch on `error_code` and surface remediation directly to users without
  having to regex prose.
- **MCP stdio server** — `nexum-mcp` exposes six read-only tools (`search`,
  `get`, `list`, `recent`, `by_session`, `list_projects`) over the rmcp stdio
  transport, wrapping the same core read verbs the CLI uses. Drop it into any
  MCP-aware host.

### Write & extraction

- **Typed extraction** — `nexum extract --session <id>` / `--since <duration>` /
  `--backfill --dry-run` / `--backfill --dry-run-id <hash>`. Reads CC
  transcripts and Codex rollouts, scrubs common secret shapes, sends a 10–30 KB
  digest to the configured `ModelClient` (default Anthropic), validates the YAML
  response, and commits each record to `notebook.git` via the existing
  signed-commit pipeline. The hash-bound two-step backfill flow gives an explicit
  cost-acknowledgement loop; first-run consent is recorded per (provider, model
  family) for `--quiet` and cron-style use. Committed records are immediately
  queryable via the standard read verbs (`get` / `list` / `search`).

### Admin / recovery

- **Operational command surface** — `nexum keys list`, `nexum keys rotate`,
  `nexum keys revoke <fp> --rotation | --strict`,
  `nexum keys recover --reanchor <path> | --reanchor-without-pin <path>`,
  `nexum trust regenerate-files`,
  `nexum trust dismiss-pre-recovery-warning --code <code>`, `nexum doctor`
  (default multi-check report) and `nexum doctor --resolve-pending-reanchor`,
  `nexum index --sweep [--aggressive]`, `nexum index --reembed`, and
  `nexum migrate`.
- Key listing surfaces the current git signer alongside the bootstrap pin;
  rotation is additive; revocation is two-mode with an estimated affected-records
  prompt under `--strict`. Bootstrap recovery covers both the pin-intact
  (`--reanchor`) and pin-lost (`--reanchor-without-pin`) cases, with a
  `.reanchor_pending` sentinel state machine that survives mid-flight crashes and
  a post-recovery warning ack via `dismiss-pre-recovery-warning`.
- The default `doctor` report runs four checks — key-state summary, signer-file
  diff, merge-commit detection, reanchor-sentinel status — with structured
  severity per check.
- Every mutation runs under a writer-process lock and rolls back on failure so
  the worktree stays clean. Revocation enforces eight preflights
  (would-unsign-store, would-sign-own-revocation, signer-is-Active, and five
  more) so misconfigured signing setups surface as wire-stable error codes
  instead of broken commits.

## Stack

| Layer | Choice | Notes |
|---|---|---|
| Core | [Rust][rust] 1.95, edition 2024 | Strict workspace clippy (`pedantic`, `-D warnings`) from commit one |
| Index | [SQLite][sqlite] FTS5 + [sqlite-vec][sqlite-vec] (`vec0`) | BM25 full-text fused with vector k-NN via RRF |
| Embeddings | bge-m3 ONNX (opt-in) | SHA256-verified weights via `nexum models install` |
| Provenance | SSH-signed git commits | Every written record committed + signed to `~/.nexum/notebook.git` |
| Agent surface | [MCP][mcp] (rmcp) stdio + `--json` `ErrorEnvelope` | Six read-only tools; wire-stable error contract |
| CLI | [clap][clap] (derive) | Synchronous — no async runtime in the human-facing path |
| Extraction | Anthropic API client (default) | Pluggable `ModelClient`; YAML-validated, signed records |

## Quick start

```bash
# Build
cargo build --release

# Initialize ~/.nexum/ (signs the bootstrap commit with your SSH key)
./target/release/nexum init -y

# Index your CC + Codex memory
./target/release/nexum index

# (Optional) install the bge-m3 ONNX weights to enable semantic ranking
./target/release/nexum models install bge-m3

# Query
./target/release/nexum search "concurrency"
./target/release/nexum recent --limit 20 --json
./target/release/nexum trust validate-events

# Inspect trust state (each known key + role + current git signer)
./target/release/nexum keys list

# Store health (key-state + signer files + sentinel + merge-commit)
./target/release/nexum doctor --json
```

The MCP stdio server lives in the same workspace:

```bash
cargo build --release --bin nexum-mcp
# Point your MCP-aware host at: target/release/nexum-mcp
```

### Reproducible end-to-end test

The `e2e/` tree wraps `nexum init + index + read verbs` inside an isolated Docker
container with `--network none`, `--cap-drop ALL`, and `--rm`. Default fixtures
are bundled; bind-mount your real install read-only via env var to exercise the
adapter against production-shape data.

```bash
./e2e/run.sh codex                              # bundled fixtures
CODEX_HOME="$HOME/.codex" ./e2e/run.sh codex    # real install (read-only)
./e2e/run.sh cc                                 # cc adapter, bundled
CC_HOME="$HOME/.claude" ./e2e/run.sh cc         # real cc install
```

## Layout

```
nexum/
├── crates/
│   ├── nexum-core/   # library — adapters, indexer, query, trust, embed, api facade
│   ├── nexum-cli/    # binary "nexum"      (human-facing CLI)
│   └── nexum-mcp/    # binary "nexum-mcp"  (stdio MCP server)
├── e2e/              # Docker-isolated end-to-end test harness
├── Cargo.toml        # workspace deps + strict workspace lints
├── rust-toolchain.toml
└── deny.toml         # cargo-deny: licenses, advisories, bans, sources
```

## Design principles

1. **Upstream, don't replace.** nexum reads the memory Claude Code and Codex
   already write — it unions and signs, it doesn't fragment or fork your store.
2. **Trust is projected, not assumed.** Every read carries `signature_status`
   and a typed warning taxonomy; nothing is silently dropped.
3. **Agent-first I/O.** Stable `error_code` strings, structured remediation, and
   decision cues over prose — built to be branched on, not regex'd.
4. **Fail safe, roll back clean.** Every mutation runs under a writer-process
   lock and rolls back on failure so the worktree stays consistent.
5. **One engine, two surfaces.** The CLI and the MCP server wrap the same core
   read verbs — what you can do by hand, an agent can do over stdio.

## License

[Apache-2.0](LICENSE-APACHE).

---

<sub>nexum is a personal tool — built for my own daily use, with no telemetry,
analytics, or growth metrics. Not chasing adoption, but if you're interested
you're welcome to try it.</sub>

[rust]:       https://www.rust-lang.org
[sqlite]:     https://www.sqlite.org
[sqlite-vec]: https://github.com/asg017/sqlite-vec
[mcp]:        https://modelcontextprotocol.io
[clap]:       https://docs.rs/clap
