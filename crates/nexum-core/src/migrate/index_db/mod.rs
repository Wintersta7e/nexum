//! Index DB migration registry. Each entry maps (from, to) to a migration fn.

mod v1_to_v2;

use std::path::{Path, PathBuf};

use chrono::Utc;
use rusqlite::{Connection, Transaction};

use super::{MigrationError, MigrationOutcome};

/// Latest index DB schema version known to the migration framework. Mirrors
/// `crate::index::schema::INDEX_DB_LATEST_VERSION` so the two stay in lockstep.
pub const INDEX_DB_LATEST_VERSION: u32 = crate::index::schema::INDEX_DB_LATEST_VERSION;

/// Function signature for a single migration step. Runs inside a transaction
/// the framework opens; the framework also commits the transaction and bumps
/// `PRAGMA user_version` after a successful return.
pub type Migration = fn(tx: &Transaction, from: u32) -> Result<(), MigrationError>;

/// Ordered list of registered migrations. New steps append in version order.
const MIGRATIONS: &[(u32, u32, Migration)] = &[(1, 2, v1_to_v2::apply)];

/// Migrate the on-disk index DB up to `INDEX_DB_LATEST_VERSION`.
///
/// Refuses (returns `MigrationError::MigrationRequired`) if the caller has
/// not asserted ownership of `~/.nexum/.lock` via `lock_held = true`. This
/// keeps read-only commands from racing the migrator on a shared store.
///
/// Backs up the live DB to `<dir>/.bak/index.db.bak-v<n>-<timestamp>` via
/// `SQLite`'s online-backup API before applying any mutation. Each migration
/// runs inside its own transaction; `PRAGMA user_version` is bumped on
/// successful commit. After the migration loop, `verify_post_apply` confirms
/// every expected v2 table / trigger / column is present so a step that
/// silently forgot to create something fails loud rather than committing
/// cleanly.
///
/// # Errors
///
/// - `MigrationError::Sqlite` if any pragma read or migration statement fails.
/// - `MigrationError::Io` if the backup file cannot be created.
/// - `MigrationError::MigrationRequired` when `lock_held = false` and the
///   on-disk version is older than the binary's latest.
/// - `MigrationError::IncompatibleStore` when the on-disk version is newer
///   than the binary's latest (downgrade is unsupported).
/// - `MigrationError::StepFailed` when a registered migration returns an
///   error; the underlying message is preserved in `cause`.
/// - `MigrationError::Schema` when post-apply verification finds any
///   expected v2 table / trigger / column missing after the loop.
// Caller asserts lock ownership at runtime; we have no compile-time check.
// The lock-guard newtype lands when the lock-holder code lands.
pub fn migrate_to_latest(
    conn: &mut Connection,
    db_path: &Path,
    lock_held: bool,
) -> Result<MigrationOutcome, MigrationError> {
    // Pre-versioning DBs (written before user_version was tracked) get
    // synthesized to v1 by `schema::apply` before this function is ever
    // called; we never see a v_disk == 0 case here in practice.
    let v_disk = crate::index::schema::read_user_version(conn)?;
    if v_disk == INDEX_DB_LATEST_VERSION {
        return Ok(MigrationOutcome::NoOp);
    }
    if v_disk > INDEX_DB_LATEST_VERSION {
        return Err(MigrationError::IncompatibleStore {
            v_disk,
            v_code: INDEX_DB_LATEST_VERSION,
        });
    }
    if !lock_held {
        return Err(MigrationError::MigrationRequired {
            v_disk,
            v_code: INDEX_DB_LATEST_VERSION,
        });
    }

    let backup_path = backup_with_online_api(conn, db_path, v_disk)?;
    for (from, to, f) in MIGRATIONS.iter().filter(|(f, _, _)| *f >= v_disk) {
        let tx = conn.transaction()?;
        f(&tx, *from).map_err(|e| MigrationError::StepFailed {
            from: *from,
            to: *to,
            cause: e.to_string(),
        })?;
        tx.execute(&format!("PRAGMA user_version = {to}"), [])?;
        tx.commit()?;
    }
    crate::index::schema::verify_post_apply(conn)?;
    Ok(MigrationOutcome::Migrated {
        from: v_disk,
        to: INDEX_DB_LATEST_VERSION,
        backup_path,
    })
}

/// Snapshot the live DB to a sibling `.bak/index.db.bak-v<n>-<timestamp>`
/// file via `SQLite`'s online-backup API. Returns the absolute backup path so
/// callers can surface it in user-facing output.
fn backup_with_online_api(
    src: &Connection,
    src_path: &Path,
    v_disk: u32,
) -> Result<PathBuf, MigrationError> {
    let parent = src_path.parent().ok_or_else(|| {
        MigrationError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "db_path has no parent directory",
        ))
    })?;
    let bak_dir = parent.join(".bak");
    std::fs::create_dir_all(&bak_dir)?;
    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let bak_path = bak_dir.join(format!("index.db.bak-v{v_disk}-{stamp}"));
    let mut dst = Connection::open(&bak_path)?;
    let backup = rusqlite::backup::Backup::new(src, &mut dst)?;
    backup.run_to_completion(64, std::time::Duration::from_millis(0), None)?;
    Ok(bak_path)
}
