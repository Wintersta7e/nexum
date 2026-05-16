//! Read verbs must refuse an index.db whose `PRAGMA user_version` is older
//! than the binary's latest schema version.

mod common;

use common::NexumTestHome;
use nexum_core::{api, api::ApiError, index::schema::INDEX_DB_LATEST_VERSION, indexer::db};

/// Build a fresh index.db via `open_or_create` (which runs the full DDL and
/// sets `user_version` to `INDEX_DB_LATEST_VERSION`), then stomp `user_version`
/// back to 1 so the store looks like it needs migration.
fn create_downgraded_index(paths: &nexum_core::paths::Paths) {
    let _ = db::open_or_create(&paths.index_db).expect("open_or_create");
    let conn = rusqlite::Connection::open(&paths.index_db).expect("open for downgrade");
    conn.execute_batch("PRAGMA user_version = 1;")
        .expect("stomp user_version");
}

#[test]
fn list_projects_refuses_a_too_old_index_db() {
    let home = NexumTestHome::new().expect("test home");
    let paths = home.paths();
    create_downgraded_index(&paths);

    let cfg = nexum_core::config::types::Config::seed();
    let err = api::list_projects(&paths, &cfg).expect_err("expected refusal");
    match err {
        ApiError::MigrationRequired { v_disk, v_code } => {
            assert_eq!(v_disk, 1);
            assert_eq!(v_code, INDEX_DB_LATEST_VERSION);
        }
        other => panic!("expected MigrationRequired; got {other:?}"),
    }
}

#[test]
fn search_refuses_a_too_old_index_db() {
    let home = NexumTestHome::new().expect("test home");
    let paths = home.paths();
    create_downgraded_index(&paths);

    let cfg = nexum_core::config::types::Config::seed();
    let opts = nexum_core::query::SearchOpts::new("anything");
    let err = api::search(&paths, &cfg, &opts).expect_err("expected refusal");
    assert!(
        matches!(err, ApiError::MigrationRequired { v_disk: 1, .. }),
        "expected MigrationRequired(v_disk=1); got {err:?}"
    );
}
