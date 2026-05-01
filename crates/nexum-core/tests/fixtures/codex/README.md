# Codex fixture (Codex-CLI-style state DB + session logs)

Refreshed in Phase 1b (post-patch3/4/5) to mirror the real Codex on-disk layout.

## Files

- `build_state.sql` — SQL source of truth for the SQLite DB. Schema mirrors the
  §5 patch4 column projection on `threads` (id / rollout_path / cwd /
  git_origin_url / created_at / updated_at / title / git_sha / git_branch /
  model). NO `sessions` table — real Codex doesn't have one; transcripts live
  in JSONL files.
- `state_5.sqlite` — pre-built fixture SQLite (~16 KB).
- `sessions/<Y>/<M>/<D>/rollout-<ts>-<thread-id>.jsonl` — per-thread session
  transcripts. Date-organized hierarchy mirrors real Codex layout. Each
  thread's `rollout_path` column points at the corresponding file.

## Threads

| id | cwd | git_origin_url | rollout_path |
|---|---|---|---|
| thread-aaa | /synthetic/project-a | https://example.invalid/project-a.git | sessions/2026/04/01/... |
| thread-bbb | /synthetic/project-b | (null) | sessions/2026/04/02/... |
| thread-ccc | /synthetic/project-c | (null) | sessions/2026/04/03/... |

## Rebuilding state_5.sqlite

```sh
rm -f state_5.sqlite
sqlite3 state_5.sqlite < build_state.sql
```

## Used by

- Phase 1b's `nexum-core::project::resolve` integration tests.
- Phase 3's Codex adapter tests.
- (No longer used by `probe_codex` — that probe will be deleted with the rest
  of the Phase 1a probes once Phase 2+ no longer needs them.)

## Names

All thread / session / cwd identifiers are generic placeholders.
