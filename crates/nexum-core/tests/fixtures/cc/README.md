# CC fixture (Claude-Code-style memory store)

Mirrors the canonical `~/.claude/projects/<encoded-cwd>/` layout that the §5 CC adapter
reads. Two synthetic projects:

- `project-a-cwd-hash/` — single top-level `CLAUDE.md` (one of the two forms in the wild).
- `project-b-cwd-hash/` — top-level `CLAUDE.md` AND a subdir `memory/MEMORY.md` (the
  other form). Lets probes / adapter tests verify they handle both layouts.

All file contents use generic placeholder names. Anything that looks like a real project
or person is a fabrication.

## Used by

- `crates/nexum-spike/src/bin/probe_cc.rs` — Phase 1a investigation probe.
- Phase 1b's `nexum-core::project` tests (resolve fixtures' "project IDs" from cwd hashes).
- Phase 3's CC adapter integration tests.

## Adding cases

Each new directory under `projects/` is a separate synthetic project. Use the form
`<placeholder-name>-cwd-hash/` so tests can string-match against the dir name without
any pretense of decoding a real cwd.
