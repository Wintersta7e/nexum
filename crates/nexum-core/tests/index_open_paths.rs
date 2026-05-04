//! Integration tests: read verbs must NOT silently create the index DB.
//!
//! Each verb here calls into `api::*` against a paths value whose
//! `index_db` does not exist. The verbs must surface
//! `QueryError::IndexMissing` (carrying the path) rather than racing
//! ahead, opening a fresh database, and reporting an empty result set —
//! which would be indistinguishable to a user from "indexed but nothing
//! matched".

mod common;

use common::NexumTestHome;
use nexum_core::api;
use nexum_core::query::{Filters, GetOpts, QueryError, SearchOpts};
use nexum_core::records::RecordKey;

fn assert_index_missing(err_msg: &str, paths_dbg: &str) {
    assert!(
        err_msg.contains("index database not found"),
        "expected IndexMissing message at `{paths_dbg}`, got: `{err_msg}`"
    );
}

#[test]
fn search_against_missing_index_errors_without_creating_db() {
    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    let cfg = common::test_cfg_local_only();
    assert!(
        !paths.index_db.exists(),
        "precondition: index DB must not exist"
    );

    let result = api::search(&paths, &cfg, &SearchOpts::new(""));
    let err = result.expect_err("search must error when index is missing");
    let err_str = format!("{err}");
    assert_index_missing(&err_str, &paths.index_db.display().to_string());
    assert!(
        matches!(err, api::ApiError::Query(QueryError::IndexMissing { .. })),
        "expected ApiError::Query(QueryError::IndexMissing), got `{err:?}`"
    );
    assert!(
        !paths.index_db.exists(),
        "search must not create the index DB"
    );
}

#[test]
fn list_against_missing_index_errors_without_creating_db() {
    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    let cfg = common::test_cfg_local_only();
    assert!(!paths.index_db.exists());

    let result = api::list(&paths, &cfg, &Filters::default(), 50, None);
    let err = result.expect_err("list must error when index is missing");
    assert_index_missing(&format!("{err}"), &paths.index_db.display().to_string());
    assert!(
        matches!(err, api::ApiError::Query(QueryError::IndexMissing { .. })),
        "expected ApiError::Query(QueryError::IndexMissing), got `{err:?}`"
    );
    assert!(
        !paths.index_db.exists(),
        "list must not create the index DB"
    );
}

#[test]
fn get_against_missing_index_errors_without_creating_db() {
    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    assert!(!paths.index_db.exists());

    let key = RecordKey::bare("anything");
    let result = api::get(&paths, &key, &GetOpts::default());
    let err = result.expect_err("get must error when index is missing");
    assert_index_missing(&format!("{err}"), &paths.index_db.display().to_string());
    assert!(
        matches!(err, api::ApiError::Query(QueryError::IndexMissing { .. })),
        "expected ApiError::Query(QueryError::IndexMissing), got `{err:?}`"
    );
    assert!(!paths.index_db.exists(), "get must not create the index DB");
}

#[test]
fn recent_against_missing_index_errors_without_creating_db() {
    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    let cfg = common::test_cfg_local_only();
    assert!(!paths.index_db.exists());

    let result = api::recent(&paths, &cfg, 10, None);
    let err = result.expect_err("recent must error when index is missing");
    assert_index_missing(&format!("{err}"), &paths.index_db.display().to_string());
    assert!(
        matches!(err, api::ApiError::Query(QueryError::IndexMissing { .. })),
        "expected ApiError::Query(QueryError::IndexMissing), got `{err:?}`"
    );
    assert!(
        !paths.index_db.exists(),
        "recent must not create the index DB"
    );
}

#[test]
fn list_projects_against_missing_index_errors_without_creating_db() {
    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    assert!(!paths.index_db.exists());

    let result = api::list_projects(&paths);
    let err = result.expect_err("list_projects must error when index is missing");
    assert_index_missing(&format!("{err}"), &paths.index_db.display().to_string());
    assert!(
        matches!(err, api::ApiError::Query(QueryError::IndexMissing { .. })),
        "expected ApiError::Query(QueryError::IndexMissing), got `{err:?}`"
    );
    assert!(
        !paths.index_db.exists(),
        "list_projects must not create the index DB"
    );
}
