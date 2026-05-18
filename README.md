# nexum

Cross-agent memory for AI coding tools — built so the things you and
your agents learn don't get lost between sessions, between agents, or
to a tampered local file.

[![CI](https://github.com/Wintersta7e/nexum/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Wintersta7e/nexum/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Wintersta7e/nexum/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/Wintersta7e/nexum/actions/workflows/codeql.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
![Rust](https://img.shields.io/badge/Rust-1.95-CE412B?logo=rust)
![SQLite](https://img.shields.io/badge/SQLite-FTS5%20%2B%20vec0-003B57?logo=sqlite&logoColor=white)
![MCP](https://img.shields.io/badge/MCP-stdio-7C3AED)

> A tool I built for myself to suit my own workflow. If you find it
> useful, you're welcome to use it.

## What you get

If you use Claude Code and OpenAI Codex CLI side-by-side (or just one
of them), you've probably noticed: memory written in one tool is
invisible to the other; the "why" behind a decision evaporates by next
week; failed approaches get re-attempted because the lesson never made
it into a memory file; and anyone who can run code as you can edit
your memory files — and your agent will trust whatever's there.

`nexum` is one tool that addresses all four:

- **Hybrid reads** of both Claude Code's per-CWD memory and Codex's
  `~/.codex/memories/` as upstream — no replacement, no fragmentation.
- **Structured search** on the unioned corpus:
  `nexum search "concurrency" --type failure --since 30d` plus
  `nexum list / get / recent / by-session`. The `--metadata-type` filter
  slices by adapter-specific frontmatter type (e.g. CC's `feedback`,
  `reference`, `user`); every result row surfaces it as `metadata_type`
  alongside `record_type`.
- **Cryptographic provenance** — every record nexum writes is signed
  with your SSH key (commits to `~/.nexum/notebook.git/`), so a
  malicious npm postinstall can't quietly inject memory your agent
  will trust.
- **Read-time trust projection** — the verifier projects
  `signature_status`, `trust_basis`, and a typed warning taxonomy on
  every read; warn / hide / strict policies route results without
  silently dropping evidence.
- **Tampering detection** — `nexum trust validate-events` and
  `nexum index --check` re-walk the trust-events history and exit
  non-zero when a forbidden mutation of `.trust/events.yml` is
  detected.
- **Trusted-key state machine** — bootstrap, key rotation, key
  compromise, and authorized re-anchor with a chain-anchor-lost
  warning all flow through one materialized view that read verbs
  consult per row.
- **Agent-ready `--json` errors** — every read verb's failure under
  `--json` emits a wire-stable `ErrorEnvelope` to stdout: stable
  `error_code` string, structured `remediation` (command +
  rationale), and a per-variant `context` preserving fields like
  `path`, `signature_status`, and `matches`. Agents branch on
  `error_code` and surface remediation directly to users without
  having to regex prose.
- **Semantic ranking** when you opt in — `nexum models install bge-m3`
  downloads the SHA256-verified bge-m3 ONNX weights, flips the embed
  flag on, and `nexum search` then fuses FTS BM25 with vector k-NN via
  RRF. Search results carry `embed_status` and `vector_candidates`
  signals so agents can tell hybrid hits from FTS-only fallback.
- **MCP stdio server** — `nexum-mcp` exposes six read-only tools
  (`search`, `get`, `list`, `recent`, `by_session`, `list_projects`)
  over the rmcp stdio transport, wrapping the same core read verbs the
  CLI uses. Drop it into any MCP-aware host.
- **Admin / recovery commands** — `nexum keys rotate`,
  `nexum trust regenerate-files`, `nexum doctor --resolve-pending-reanchor`,
  `nexum index --sweep [--aggressive]`, `nexum index --reembed`, and
  `nexum migrate` cover the operational surface (key rotation,
  trust-file regeneration, sentinel resolution, stale-row sweep,
  embedding backfill, schema migration). Every mutation runs under a
  writer-process lock and rolls back on failure so the worktree
  stays clean.
- **Typed extraction** — `nexum extract --session <id>` / `--since <duration>` /
  `--backfill --dry-run` / `--backfill --dry-run-id <hash>`. Reads CC transcripts
  and Codex rollouts, scrubs common secret shapes, sends a 10-30 KB digest to the
  configured `ModelClient` (default Anthropic), validates the YAML response, and
  commits each record to `notebook.git` via the existing signed-commit pipeline.
  Hash-bound two-step backfill flow gives an explicit cost-acknowledgement loop;
  first-run consent is recorded per (provider, model family) for `--quiet` and
  cron-style use. Committed records are immediately queryable via the standard
  read verbs (`get` / `list` / `search`).

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
```

The MCP stdio server lives in the same workspace:

```bash
cargo build --release --bin nexum-mcp
# Point your MCP-aware host at: target/release/nexum-mcp
```

## Reproducible end-to-end test

The `e2e/` tree wraps `nexum init + index + read verbs` inside an
isolated Docker container with `--network none`, `--cap-drop ALL`, and
`--rm`. Default fixtures are bundled; bind-mount your real install
read-only via env var to exercise the adapter against production-shape
data.

```bash
./e2e/run.sh codex                              # bundled fixtures
CODEX_HOME="$HOME/.codex" ./e2e/run.sh codex    # real install (read-only)
./e2e/run.sh cc                                 # cc adapter, bundled
CC_HOME="$HOME/.claude" ./e2e/run.sh cc         # real cc install
```

## Status

The read path, the write path, the trust state machine, the MCP
stdio server, semantic ranking, typed extraction, and the admin /
recovery command surface are all in `main` and validated end-to-end
against real codex + cc data via the Docker harness. Three crates
compile clean, gate green at
`cargo fmt + check + clippy -D warnings + test`.

Remaining work: a recommendation -> decision promotion flow when
matching commits land in your project repo.

## Layout

```
nexum/
├── Cargo.toml             # workspace
├── crates/
│   ├── nexum-core/        # library — adapters, indexer, query, trust, embed, api facade
│   ├── nexum-cli/         # binary "nexum"
│   └── nexum-mcp/         # binary "nexum-mcp" (stdio MCP server)
└── e2e/                   # Docker-isolated end-to-end test harness
```

## License

Apache-2.0. See [`LICENSE-APACHE`](./LICENSE-APACHE).
