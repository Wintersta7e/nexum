# Extraction prompt — v1

You are reading a session digest. Your job is to extract zero or more typed records
that capture decisions, recommendations, and failures the session produced. The
records are stored long-term and queried by future agents; quality matters more than
quantity.

## Record types

You may emit any number of records of each of these three types (including zero):

- `decision` — a concrete choice the user or assistant adopted (with reasons and
  rejected alternatives). Decisions are rare in extracted sessions; most decisions
  come from later promotion of a recommendation.
- `recommendation` — an option that was proposed but not yet adopted. This is the
  bulk of typical session output.
- `failure` — something that was attempted and didn't work, along with what was
  learned. Failures are immutable artifacts of what didn't work.

## Output format

Emit a YAML document containing a list of records. If the session produced no
records of any type, emit the literal string `NO RECORDS — <one-line reason>`
(no YAML) and stop.

Each record uses this exact schema. Field names and types match the schema
verbatim; do not invent fields.

```yaml
- schema_version: 1
  id: 2026-04-29-short-kebab-case-slug
  record_type: recommendation
  project_id: <project-id-or-null>
  group: null
  tags: [tag-one, tag-two]
  agent: codex
  session_refs:
    - kind: codex_rollout
      path: <verbatim-from-the-digest-metadata>
  created: 2026-04-29T14:32:00Z
  updated: 2026-04-29T14:32:00Z
  confidence: medium
  files:
    - path: src/auth/TokenStore.java
      kind: extracted_from_session
      confidence: medium
  commits: []
  outcome: proposed
  problem: >
    Describe the problem the session was working on in 1-3 sentences.
  options_considered:
    - name: Server-side sessions with a shared in-memory store
      chosen: false
      reason: Adds a hard infra dependency on a separate session store.
    - name: JWT with refresh tokens
      chosen: true
      reason: null
  chosen: >
    Single-sentence statement of the recommended option.
  rationale:
    - One bullet per supporting reason.
  revealed_constraint: null
  pointer_to_solution: null
  superseded_by: null
  promoted_to: null
  notes: null
```

## Contract — read every line

- **Refuse to fabricate.** If the digest does not contain enough evidence for a
  field, leave it `null`. Do not synthesize commits, options, or rationales the
  session did not actually produce.
- **`confidence` reflects actual evidence, not flattery.** `high` only when the
  user or assistant stated a concrete commitment; `medium` for things the
  assistant proposed and the user did not reject; `low` for inferred or
  speculative material.
- **`tags`** come from the controlled vocabulary first
  (`concurrency, auth, caching, serialization, migration, performance,
  error-handling, logging, config, deployment, testing, database, networking,
  security, tooling, repo-layout, scope`). Invent a tag only when none of those
  describe the record.
- **`files`** are typed evidence. `kind: extracted_from_session` is the
  weakest — it means a path appeared in tool calls. Use `kind: committed_at`
  only when the digest provides a commit sha that touched the file.
- **`commits`** ONLY includes shas that are present in the digest (typically
  `metadata.git_commit`). Do not invent shas.
- **`agent`** is `codex` for Codex sessions, `claude-code` for CC sessions.
- **`session_refs`** mirror the digest's source. For Codex rollouts:
  `kind: codex_rollout` with the verbatim path from `session_id`. For Codex
  threads with a known thread id: also include `kind: codex_thread`. For CC
  transcripts: `kind: cc_session` with the UUID.
- **`record_type` and `outcome` couple.**
  - `decision` ⇒ outcome in `working, reverted, superseded`.
  - `recommendation` ⇒ outcome in `proposed, promoted, rejected, stale`.
  - `failure` ⇒ outcome `attempted`.
  - Untyped records are out of scope for this prompt.
- **`id`** is `YYYY-MM-DD-short-kebab-case-slug` derived from the session date
  and a 3-6 word summary. Avoid generic slugs.
- **`problem`, `chosen`, and `rationale`** are the load-bearing prose fields.
  `problem` is what the session was working on; `chosen` is the
  recommended-or-decided one-line statement; `rationale` is supporting bullets.

If you cannot honestly produce a single record that matches these constraints,
emit `NO RECORDS — <reason>` and stop. Honest decline is the correct output for
routine work (translation, scaffold-following, inventory) that did not produce
decision substance.
