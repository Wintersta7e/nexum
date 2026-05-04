//! Index DB schema migration framework.
//!
//! Each registered migration is a `fn(&Transaction, from_version) -> Result<()>`;
//! the framework backs up the DB via `SQLite`'s online-backup API before any
//! mutation, runs migrations in version order inside transactions, and bumps
//! `PRAGMA user_version` after each. Read-only callers refuse if the on-disk
//! version is older than `INDEX_DB_LATEST_VERSION`.

pub mod index_db;

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    #[error("sqlite error during migration: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io error during backup: {0}")]
    Io(#[from] std::io::Error),
    #[error("migration required: on-disk schema is v{v_disk}; binary supports v{v_code}")]
    MigrationRequired { v_disk: u32, v_code: u32 },
    #[error("incompatible store: on-disk schema is v{v_disk}; binary supports up to v{v_code}")]
    IncompatibleStore { v_disk: u32, v_code: u32 },
    #[error("migration v{from}->v{to} failed: {cause}")]
    StepFailed { from: u32, to: u32, cause: String },
    #[error("post-migration schema verification failed: {0}")]
    Schema(#[from] crate::index::schema::SchemaError),
}

/// Outcome of a `migrate_to_latest` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// On-disk version already matches `INDEX_DB_LATEST_VERSION`.
    NoOp,
    /// Migrations applied; the path of the pre-migration backup is preserved
    /// so the caller can mention it in user-facing output.
    Migrated {
        from: u32,
        to: u32,
        backup_path: PathBuf,
    },
}
