//! Shared module for integration tests that exercise the trust materializer.
//! Exposes the fixture builder used by `materializer_state_machine` and
//! `materializer_tampering`, plus the two integration-test setup helpers
//! (`fresh_index_db`, `fresh_notebook_with_bootstrap`) that both files
//! consume.

#![allow(dead_code)]

pub mod fixtures;

use nexum_core::indexer::db::open_or_create;
use rusqlite::Connection;
use tempfile::TempDir;
use uuid::Uuid;

use fixtures::{KeyPair, NotebookFixture, commit_events_yml, init_notebook, new_keypair};

/// Open a fresh on-disk index database with the canonical DDL applied (and
/// the sqlite-vec extension auto-registered). The returned connection
/// behaves like a regular `rusqlite::Connection`.
pub fn fresh_index_db() -> (TempDir, Connection) {
    let dir = tempfile::tempdir().expect("create index-db tempdir");
    let conn = open_or_create(&dir.path().join("index.db")).expect("open_or_create succeeds");
    (dir, conn)
}

/// Build a fixture with a primary key and the bootstrap commit already
/// applied. The returned `tempfile::TempDir` owns the directory holding
/// the primary signing key on disk; tests must keep it alive until they
/// stop calling `commit_events_yml` (because git re-reads the private key
/// for every signed commit). The bootstrap event UUID is also returned so
/// tests that assert `chain_validated_by` linkage can reference it.
pub fn fresh_notebook_with_bootstrap() -> (NotebookFixture, KeyPair, Uuid, TempDir) {
    let key_dir = tempfile::Builder::new()
        .prefix("nexum-trust-keys-")
        .tempdir()
        .expect("create key tempdir");
    let primary = new_keypair(key_dir.path(), "primary");
    let fixture = init_notebook(&primary);
    let bootstrap_event = Uuid::now_v7();
    let yaml = format!(
        "schema_version: 1\nevents:\n  - event_id: {ev}\n    kind: BootstrapKey\n    fingerprint: \"{fp}\"\n    public_key: \"{pk}\"\n    reason: \"Initial bootstrap\"\n",
        ev = bootstrap_event,
        fp = primary.fingerprint,
        pk = primary.public_openssh.trim(),
    );
    commit_events_yml(fixture.path(), &yaml, &primary.private_path);
    (fixture, primary, bootstrap_event, key_dir)
}
