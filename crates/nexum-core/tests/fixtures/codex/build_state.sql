-- crates/nexum-core/tests/fixtures/codex/build_state.sql
--
-- Source of truth for the fixture SQLite. Mirrors the schema the §5 Codex adapter
-- assumes (threads table with cwd / git_origin_url / created columns; sessions table
-- with thread_id linkage). Three threads, four sessions across them. Deterministic
-- timestamps so tests can string-match.

PRAGMA foreign_keys = OFF;

CREATE TABLE threads (
    id TEXT PRIMARY KEY,
    cwd TEXT,
    git_origin_url TEXT,
    created TEXT NOT NULL
);

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    thread_id TEXT NOT NULL,
    rollout_path TEXT NOT NULL,
    model TEXT,
    started TEXT NOT NULL,
    ended TEXT,
    FOREIGN KEY (thread_id) REFERENCES threads(id)
);

INSERT INTO threads (id, cwd, git_origin_url, created) VALUES
    ('thread-aaa', '/synthetic/project-a',  'https://example.invalid/project-a.git', '2026-04-01T10:00:00Z'),
    ('thread-bbb', '/synthetic/project-b',  NULL,                                    '2026-04-02T11:00:00Z'),
    ('thread-ccc', NULL,                    NULL,                                    '2026-04-03T12:00:00Z');

INSERT INTO sessions (id, thread_id, rollout_path, model, started, ended) VALUES
    ('session-001', 'thread-aaa', 'sessions/session-001.jsonl', 'model-x', '2026-04-01T10:05:00Z', '2026-04-01T10:30:00Z'),
    ('session-002', 'thread-aaa', 'sessions/session-002.jsonl', 'model-x', '2026-04-01T11:00:00Z', '2026-04-01T11:20:00Z'),
    ('session-003', 'thread-bbb', 'sessions/session-003.jsonl', 'model-y', '2026-04-02T11:30:00Z', '2026-04-02T12:00:00Z'),
    ('session-004', 'thread-ccc', 'sessions/session-004.jsonl', 'model-x', '2026-04-03T12:05:00Z',  NULL);
