# nexum

Cross-agent memory for AI coding tools — built so the things you and your agents learn don't get lost between sessions, between agents, or to a tampered local file.

> **Status:** pre-implementation. Next step: the stack-validation spike under `crates/nexum-spike/`.

## What it does for you

If you use Claude Code and OpenAI Codex CLI side-by-side (or just one of them), you've probably noticed:

- Memory written in one tool is invisible to the other.
- The "why" behind a decision evaporates by next week.
- Failed approaches get re-attempted because the lesson never made it into a memory file.
- Anyone who can run code as you can edit your memory files — and your agent will trust whatever's there.

**`nexum` is one tool that fixes all four.** Concretely, it:

1. **Reads** both Claude Code's per-CWD memory and Codex's `~/.codex/memories/` as upstream — no replacement, no fragmentation.
2. **Searches** them with semantic + structured queries you can actually run: `nexum search "concurrency" --type failure --since 30d`.
3. **Extracts** structured records (decisions, recommendations, failures with `revealed_constraint`) from past Codex sessions using a refusal-trained prompt that empirically holds up: 77% session coverage, 0 fabrications observed in sampled output.
4. **Signs** every record it writes with your SSH key (commits to `~/.nexum/notebook.git/`), so a malicious npm postinstall can't quietly inject memory your agent will trust.
5. **Promotes** `recommendation` → `decision` when a matching commit lands in your project — the corpus stays connected to what actually shipped.
6. **Speaks MCP** to both Claude Code and Codex, and has a CLI for everything an agent can do plus things only you'd want (audits, key rotation, recovery).

## Why these features specifically

The combination — hybrid reading of both native stores, refusal-trained typed extraction, cryptographic provenance, git-correlation promotion — isn't covered end-to-end by any single MCP memory tool we're aware of. Each existing tool covers some of it; nexum aims to cover all of it.

## Status

Pre-implementation. Before the first line of production code lands: a small `crates/nexum-spike/` validates the concrete stack assumptions (sqlite-vec DDL on Linux + Windows, bge-m3 ONNX cold-start time on real hardware, async/blocking executor split under saturation, the full SSH-signed trust state machine roundtrip with real records). When the spike comes back clean, real implementation begins.

## Layout

```
nexum/
├── Cargo.toml             # workspace
└── crates/
    ├── nexum-core/        # library — all logic, types, errors, config
    ├── nexum-cli/         # binary "nexum"
    ├── nexum-mcp/         # binary "nexum-mcp" (stdio MCP server)
    └── nexum-spike/       # workspace-private; pre-implementation stack-validation
```

## License

Apache-2.0. See `LICENSE-APACHE`.
