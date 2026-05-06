PRAGMA user_version = 2;

-- records table
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
    record_commit_sha TEXT,
    signer_fingerprint TEXT,
    crypto_result TEXT NOT NULL CHECK (crypto_result IN ('good', 'bad-signature', 'unknown-signer', 'no-signature')),
    -- The commit on .trust/events.yml that was effective when this record was
    -- signed. Used by the read-time projection to look up trust state via
    -- `trust_events.effective_commit = relevant_trust_events_commit`. Computed
    -- at index time. NULL for cc-native / codex-native records (no notebook
    -- commit) and for local records where no events.yml commit is reachable.
    relevant_trust_events_commit TEXT,
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
CREATE INDEX idx_records_crypto ON records(crypto_result);
CREATE INDEX idx_records_trust_events_commit ON records(relevant_trust_events_commit);

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

CREATE TABLE trust_events (
    event_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('BootstrapKey', 'KeyAdded', 'KeyRotatedOut', 'KeyCompromised', 'BootstrapReanchor')),
    fingerprint TEXT,
    old_fingerprint TEXT,
    new_fingerprint TEXT,
    public_key TEXT,
    effective_commit TEXT NOT NULL,
    effective_commit_topo_pos INTEGER NOT NULL,
    introduced_by_signer TEXT NOT NULL,
    chain_validated_by TEXT,
    reason TEXT,
    -- 0 = chain anchor preserved (Case A), 1 = anchor lost (Case B). Set only
    -- on BootstrapReanchor rows; NULL on all other kinds. Materializer reads
    -- `acknowledge_chain_anchor_lost` from the event payload.
    chain_anchor_lost INTEGER,
    materialized_at TEXT NOT NULL
);
CREATE INDEX idx_trust_events_topo ON trust_events(effective_commit_topo_pos);
CREATE INDEX idx_trust_events_fp ON trust_events(fingerprint);
CREATE INDEX idx_trust_events_introducer ON trust_events(introduced_by_signer);

CREATE TABLE trust_chain_tampering (
    at_commit TEXT NOT NULL,
    at_topo_pos INTEGER NOT NULL,
    event_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('ReorderedDeleted', 'MutatedPayload', 'DuplicateId')),
    detected_at TEXT NOT NULL,
    PRIMARY KEY (at_commit, event_id, kind)
);

CREATE TABLE meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
