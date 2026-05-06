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
use nexum_core::query::{Filters, GetOpts, QueryError, SearchOpts, SessionLookup};
use nexum_core::records::RecordKey;

fn assert_index_missing(err: &api::ApiError) {
    assert!(
        matches!(err, api::ApiError::Query(QueryError::IndexMissing { .. })),
        "expected ApiError::Query(QueryError::IndexMissing), got: `{err:?}`"
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
    assert_index_missing(&err);
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
    assert_index_missing(&err);
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
    let cfg = common::test_cfg_local_only();
    let result = api::get(&paths, &cfg, &key, &GetOpts::default());
    let err = result.expect_err("get must error when index is missing");
    assert_index_missing(&err);
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
    assert_index_missing(&err);
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
    assert_index_missing(&err);
    assert!(
        !paths.index_db.exists(),
        "list_projects must not create the index DB"
    );
}

#[test]
fn by_session_against_missing_index_errors_without_creating_db() {
    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    let cfg = common::test_cfg_local_only();
    assert!(!paths.index_db.exists());

    let lookup = SessionLookup::CcSession {
        uuid: uuid::Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
    };
    let result = api::by_session(&paths, &cfg, &lookup);
    let err = result.expect_err("by_session must error when index is missing");
    assert_index_missing(&err);
    assert!(
        !paths.index_db.exists(),
        "by_session must not create the index DB"
    );
}
