---
name: capability tour shape
description: list of verbs the tour exercises and the assertion attached to each step
type: project
originSessionId: 00000000-0000-4000-8000-000000000003
---

The capability tour groups its steps so a single run touches every
read-path verb the agent surface exposes.

- `init`            — bootstrap a fresh `$HOME/.nexum/`; verify the
                      bootstrap commit signature.
- `index`           — ingest the bundled CC + Codex fixtures; expect
                      `ingested >= 4` (three CC records + at least one
                      Codex H2 section).
- `recent`          — newest records first; expect non-empty `results`.
- `search`          — query for the term `tour`; expect ≥1 hit.
- `list`            — filtered by source type; expect ≥1 hit per source.
- `get`             — fetch by id; expect the record body to round-trip.
- `by-session`      — fetch by `originSessionId` from any fixture;
                      expect at least the originating record.
- `project`         — list registered projects; expect the synthetic
                      slug to appear.
- `doctor`          — run multi-check; expect `status = ok` with no
                      `Critical` items.
- `index` (re-run)  — second pass; expect `upserted = 0` (idempotent).
- MCP stdio smoke   — start `nexum-mcp` on stdio, hand-shake, and issue
                      one `search` tool call; expect a JSON-RPC response
                      with `result.records[0].id` defined.

The tour fails fast on any non-zero exit. Each step prints a heading
so a failed run can be re-played from the start of the failing step.
