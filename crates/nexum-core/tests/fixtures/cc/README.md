# CC fixture (Claude-Code-style memory store)

Mirrors the canonical `~/.claude/projects/<cwd-slug>/` layout that the §5 CC adapter
reads, post-`v1.7-patch3`/`patch4`. Three synthetic projects covering the cases the
adapter must handle:

- `-tmp-fixture-projalpha/` — clean-path slug. Slug decodes unambiguously to
  `/tmp/fixture/projalpha`. Has a `memory/` directory with the index file
  (`MEMORY.md`) plus three per-topic record files. No session transcripts.
- `-tmp-fixture-projbeta/` — clean-path slug. Slug decodes to
  `/tmp/fixture/projbeta`. Has both a `memory/` directory AND a sibling
  `<session-uuid>.jsonl` transcript. Lets the adapter test verify that
  the §5 read-path correctly **skips** project-root JSONLs (they're §10's
  territory, not §5's).
- `-tmp-fixture-my-hyphenated-app/` — **ambiguous slug**. Decodes to either
  `/tmp/fixture/my-hyphenated-app` OR `/tmp/fixture/my/hyphenated/app` (or
  several other splits). Exercises the patch4 caveat that slug decoding is
  best-effort and must yield to `git_origin_url` / registered project name
  signals when available. Tests should treat this project's `project_id`
  resolution as either ambiguous-warn or registry-overridden.

## Layout each `memory/` directory has

```
memory/
  MEMORY.md                          # INDEX file. Lists pointers to per-topic
                                     # records as `- [Title](file.md) — hook`.
                                     # The §5 adapter SKIPS this as a record;
                                     # it's a navigation aid only.
  feedback_<topic>.md                # one record per file. YAML-frontmatter
  project_<topic>.md                 # Markdown matching the §5 "File shape we
  reference_<topic>.md               # read" spec (name / description / type /
                                     # originSessionId in frontmatter; freeform
                                     # body below).
```

## What's NOT here (intentional)

- **Top-level `CLAUDE.md`.** Patch3 / probe-cc found that real CC stores never
  have this form (zero of 51 projects on the probed install). The §5 adapter no
  longer canonicalizes it.
- Real third-party project / company / app names. Anything that looks recognizable
  is a fabrication; placeholder names only.

## Used by

- `crates/nexum-spike/src/bin/probe_cc.rs` — Phase 1a investigation probe (still
  works against this layout — the probe just reports "subdir-memory-MEMORY.md"
  for the index files and "other" for the per-topic records, which is fine for
  its limited purpose).
- Phase 1b's `nexum-core::project` tests (slug-decode + project_id resolution).
- Phase 3's CC adapter integration tests (per-topic file parsing; JSONL skip
  rule; ambiguous-slug warning surface).

## Adding cases

New projects: pick a realistic-looking slug (leading `-` + path components
joined by `-`). Avoid real cwd paths. Document the case the project is meant to
exercise in this README.

For per-topic memory files: use the YAML frontmatter shape §5 specifies. The
`type` value selects which §5 mapping table row applies (feedback / user /
project / reference; anything else falls into the `untyped` bucket via
`extras.cc_type`).
