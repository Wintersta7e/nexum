-- Index DDL. Loaded into Rust via include_str! and applied by
-- index::schema::apply().

-- CHECK constraints apply on freshly-created records tables. Existing DBs
-- migrated via migrate_existing (ADD COLUMN only) continue to operate correctly
-- because the Rust from_db_str parsers default unknown values. A future
-- "rebuild" verb would regenerate the table from scratch to enforce them there.
CREATE TABLE records (
    rowid INTEGER PRIMARY KEY,
    id TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('cc-native', 'codex-native', 'local')),
    project_id TEXT NOT NULL,
    record_type TEXT NOT NULL CHECK (record_type IN ('decision', 'recommendation', 'failure', 'untyped')),
    title TEXT NOT NULL,
    summary TEXT,
    body TEXT NOT NULL,
    body_origin_path TEXT,
    tags JSON NOT NULL,
    tags_fts TEXT NOT NULL,
    confidence TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    outcome TEXT NOT NULL CHECK (outcome IN ('working', 'reverted', 'superseded', 'proposed', 'promoted', 'rejected', 'stale', 'attempted', 'n-a')),
    agent TEXT NOT NULL CHECK (agent IN ('codex', 'claude-code', 'manual')),
    session_refs JSON,
    files JSON,
    commits JSON,
    created TEXT NOT NULL,
    updated TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    index_hash TEXT NOT NULL,
    signature_status TEXT NOT NULL CHECK (signature_status IN ('verified', 'unsigned', 'invalid', 'unknown')),
    record_commit_sha TEXT,
    signer_fingerprint TEXT,
    trust_basis TEXT CHECK (trust_basis IS NULL OR trust_basis IN ('current', 'historical', 'pre-reanchor', 'unsigned', 'unknown')),
    warning_code TEXT,
    extras JSON,
    indexed_at TEXT NOT NULL,
    UNIQUE (source, project_id, id)
);

CREATE INDEX idx_records_identity ON records(source, project_id, id);
CREATE INDEX idx_records_id ON records(id);
CREATE INDEX idx_records_project ON records(project_id);
CREATE INDEX idx_records_type ON records(record_type);
CREATE INDEX idx_records_source ON records(source);
CREATE INDEX idx_records_updated ON records(updated);
CREATE INDEX idx_records_hash ON records(content_hash);
CREATE INDEX idx_records_signature ON records(signature_status);

CREATE VIRTUAL TABLE record_embeddings USING vec0(
    record_rowid INTEGER PRIMARY KEY,
    embedding FLOAT[1024]
);

CREATE VIRTUAL TABLE records_fts USING fts5(
    title, summary, body, tags_fts,
    content='records',
    content_rowid='rowid',
    tokenize='unicode61 remove_diacritics 2'
);

CREATE TRIGGER records_ai AFTER INSERT ON records BEGIN
    INSERT INTO records_fts(rowid, title, summary, body, tags_fts)
    VALUES (new.rowid, new.title, new.summary, new.body, new.tags_fts);
END;

CREATE TRIGGER records_ad AFTER DELETE ON records BEGIN
    INSERT INTO records_fts(records_fts, rowid, title, summary, body, tags_fts)
    VALUES('delete', old.rowid, old.title, old.summary, old.body, old.tags_fts);
END;

CREATE TRIGGER records_au AFTER UPDATE ON records BEGIN
    INSERT INTO records_fts(records_fts, rowid, title, summary, body, tags_fts)
    VALUES('delete', old.rowid, old.title, old.summary, old.body, old.tags_fts);
    INSERT INTO records_fts(rowid, title, summary, body, tags_fts)
    VALUES (new.rowid, new.title, new.summary, new.body, new.tags_fts);
END;
