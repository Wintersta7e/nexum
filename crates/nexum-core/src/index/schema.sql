-- §7 index DDL. Loaded into Rust via include_str! and applied by
-- index::schema::apply(). Keep in sync with §7 of the design spec.

CREATE TABLE records (
    rowid INTEGER PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,
    project_id TEXT,
    record_type TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT,
    body TEXT,
    body_origin_path TEXT,
    tags JSON NOT NULL,
    tags_fts TEXT NOT NULL,
    confidence TEXT,
    outcome TEXT,
    agent TEXT,
    session_refs JSON,
    files JSON,
    commits JSON,
    created TEXT NOT NULL,
    updated TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    signature_status TEXT NOT NULL,
    extras JSON,
    indexed_at TEXT NOT NULL
);

CREATE UNIQUE INDEX idx_records_id ON records(id);
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
