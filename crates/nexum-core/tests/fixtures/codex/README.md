# Codex fixture (Codex-CLI-style state DB + session logs)

Mirrors the canonical `~/.codex/state_5.sqlite` + `~/.codex/sessions/` layout that the
§5 Codex adapter reads. Schema and sample rows are deterministic; everything is
hand-written placeholder content.

## Files

- `build_state.sql` — SQL source of truth for the SQLite DB. Schema + sample rows.
  Edit this when changing the fixture; rebuild the SQLite file (see "Rebuilding").
- `state_5.sqlite` — pre-built fixture SQLite (~16 KB). Committed so tests don't
  need a build step.
- `sessions/session-NNN.jsonl` — sample session-log JSONL files. Each line is one
  recorded turn (`role`, `content`, optional `tool_use`, etc.).

## Rebuilding state_5.sqlite

When you change `build_state.sql`, regenerate the SQLite file:

```sh
rm -f state_5.sqlite
sqlite3 state_5.sqlite < build_state.sql
```

Then commit both files together so the SQL and the binary stay in sync.

## Used by

- `crates/nexum-spike/src/bin/probe_codex.rs` — Phase 1a investigation probe.
- Phase 3's Codex adapter integration tests.

## Names

All thread / session / project / model identifiers are generic placeholders
(`project-a`, `session-001`, `model-x`, etc.). Anything that looks like a real
product or person is fabricated.
