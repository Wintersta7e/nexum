-- crates/nexum-core/tests/fixtures/codex/build_state.sql
--
-- Refreshed in Phase 1b to mirror real Codex on-disk schema (post-patch4).
-- The §5 Codex adapter reads the projection: id, rollout_path, cwd,
-- git_origin_url, created_at, updated_at, title, git_sha, git_branch, model.
-- Real Codex `threads` has 27 columns total (sandbox_policy, tokens_used, etc.);
-- the fixture mirrors only the projection — the §5 "tolerate additional
-- columns" rule means tests that exercise the adapter's column SELECT must
-- still pass against a fixture that has FEWER columns than real Codex.
--
-- No `sessions` table — real Codex doesn't have one (transcripts live in
-- JSONL files under sessions/<Y>/<M>/<D>/).

PRAGMA foreign_keys = OFF;

CREATE TABLE threads (
    id TEXT PRIMARY KEY,
    rollout_path TEXT NOT NULL,
    cwd TEXT NOT NULL,
    git_origin_url TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    title TEXT NOT NULL,
    git_sha TEXT,
    git_branch TEXT,
    model TEXT
);

INSERT INTO threads (id, rollout_path, cwd, git_origin_url, created_at, updated_at, title, git_sha, git_branch, model) VALUES
    ('thread-aaa',
     'sessions/2026/04/01/rollout-2026-04-01T10-05-00-thread-aaa.jsonl',
     '/synthetic/project-a',
     'https://example.invalid/project-a.git',
     1743501600,
     1743503400,
     'thread alpha',
     'abc12345',
     'main',
     'model-x'),
    ('thread-bbb',
     'sessions/2026/04/02/rollout-2026-04-02T11-30-00-thread-bbb.jsonl',
     '/synthetic/project-b',
     NULL,
     1743590400,
     1743592200,
     'thread beta',
     NULL,
     NULL,
     'model-y'),
    ('thread-ccc',
     'sessions/2026/04/03/rollout-2026-04-03T12-05-00-thread-ccc.jsonl',
     '/synthetic/project-c',
     NULL,
     1743678300,
     1743678300,
     'thread gamma (ongoing)',
     NULL,
     NULL,
     'model-x');
