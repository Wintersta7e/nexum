# CC fixture (Claude-Code-style memory store)

Mirrors the canonical `~/.claude/projects/<cwd-slug>/` layout that the CC
adapter reads. Three synthetic projects covering the cases the adapter must
handle:

- `-tmp-fixture-projalpha/` — clean-path slug. Decodes unambiguously to
  `/tmp/fixture/projalpha`. Has a `memory/` directory with the index file
  (`MEMORY.md`) plus three per-topic record files. No session transcripts.
- `-tmp-fixture-projbeta/` — clean-path slug. Decodes to
  `/tmp/fixture/projbeta`. Has both a `memory/` directory AND a sibling
  `<session-uuid>.jsonl` transcript. Verifies that the read-path correctly
  **skips** project-root JSONLs (the adapter ingests `memory/` records, not
  raw session transcripts).
- `-tmp-fixture-my-hyphenated-app/` — **ambiguous slug**. Decodes to either
  `/tmp/fixture/my-hyphenated-app` OR `/tmp/fixture/my/hyphenated/app` (or
  several other splits). Exercises the slug-decode caveat that decoding is
  best-effort and must yield to `git_origin_url` / registered project name
  signals when available. Tests should treat this project's `project_id`
  resolution as either ambiguous-warn or registry-overridden.

## Layout each `memory/` directory has

```
memory/
  MEMORY.md                          # INDEX file. Lists pointers to per-topic
                                     # records as `- [Title](file.md) — hook`.
                                     # The adapter SKIPS this as a record;
                                     # it's a navigation aid only.
  feedback_<topic>.md                # one record per file. YAML-frontmatter
  project_<topic>.md                 # Markdown matching the canonical "File
  reference_<topic>.md               # shape we read" spec (name / description
                                     # / type / originSessionId in frontmatter;
                                     # freeform body below).
```

## What's NOT here (intentional)

- **Top-level `CLAUDE.md`.** Real CC stores never have this form (verified
  against probed installs). The adapter no longer canonicalizes it.
- Real third-party project / company / app names. Anything that looks
  recognizable is a fabrication; placeholder names only.

## Used by

- `crates/nexum-core::project` tests (slug-decode + project_id resolution).
- CC adapter integration tests (per-topic file parsing; JSONL skip rule;
  ambiguous-slug warning surface).

## Adding cases

New projects: pick a realistic-looking slug (leading `-` + path components
joined by `-`). Avoid real cwd paths. Document the case the project is meant
to exercise in this README.

For per-topic memory files: use the YAML frontmatter shape the adapter
specifies. The `type` value selects which mapping-table row applies
(feedback / user / project / reference; anything else falls into the
`untyped` bucket via `extras.cc_type`).
