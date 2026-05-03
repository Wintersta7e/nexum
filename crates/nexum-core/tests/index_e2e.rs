//! End-to-end test — ingest fixtures into a fresh `index.db`, then run the
//! query verbs and assert on results.

mod common;

use common::NexumTestHome;
use nexum_core::{
    api,
    config::types::{AdapterCcConfig, AdapterCodexConfig, AdapterLocalConfig, Config},
    indexer::db::open_or_create,
    indexer::run::run as indexer_run,
    query::{Filters, GetOpts, SearchOpts, SessionLookup},
};
use std::path::Path;

fn fixture_cc_projects() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("cc")
        .join("projects")
}

fn fixture_codex_memories() -> std::path::PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("codex");
    std::fs::create_dir_all(dir.join("memories")).ok();
    dir.join("memories")
}

fn fixture_codex_state_db() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("codex")
        .join("state_5.sqlite")
}

fn write_local_yaml(home: &NexumTestHome, sub: &str, id: &str, body: &str) {
    let p = home
        .path()
        .join("notebook.git")
        .join(sub)
        .join(format!("{id}.yml"));
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let kind = match sub {
        "decisions" => "decision",
        "recommendations" => "recommendation",
        "failures" => "failure",
        _ => "untyped",
    };
    std::fs::write(
        p,
        format!(
            "schema_version: 1\nid: {id}\nrecord_type: {kind}\ntitle: {id}\nbody: |\n  {body}\nproject_id: example-project\ntags: [auth, security]\nagent: manual\ncreated: 2026-04-29T00:00:00Z\nupdated: 2026-04-29T00:00:00Z\nconfidence: high\noutcome: working\n"
        ),
    )
    .unwrap();
}

fn cfg_with_fixture_paths() -> Config {
    let mut cfg = Config::seed();
    cfg.adapters.cc = AdapterCcConfig {
        enabled: true,
        projects_dir: fixture_cc_projects().display().to_string(),
        max_age_years: 99,
    };
    cfg.adapters.codex = AdapterCodexConfig {
        enabled: true,
        memories_dir: fixture_codex_memories().display().to_string(),
        state_db: fixture_codex_state_db().display().to_string(),
        read_raw_memories: false,
    };
    cfg.adapters.local = AdapterLocalConfig { enabled: true };
    cfg
}

#[test]
fn full_pass_indexes_cc_fixtures_local_yaml_and_runs_search() {
    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    std::fs::create_dir_all(home.path().join("notebook.git")).unwrap();
    write_local_yaml(&home, "decisions", "alpha", "concurrency body");
    write_local_yaml(&home, "decisions", "beta", "auth body");

    let cfg = cfg_with_fixture_paths();
    let mut conn = open_or_create(&paths.index_db).unwrap();
    let outcome = indexer_run(&mut conn, &cfg, &paths).unwrap();
    drop(conn);
    // CC fixtures + 2 local yamls.
    assert!(
        outcome.upserts >= 8,
        "expected at least 8 upserts, got {}",
        outcome.upserts
    );

    // Search by FTS body term.
    let res = api::search(&paths, &cfg, &SearchOpts::new("concurrency")).unwrap();
    assert!(
        res.results.iter().any(|r| r.id == "alpha"),
        "concurrency body should match `alpha`: got {:?}",
        res.results.iter().map(|r| &r.id).collect::<Vec<_>>()
    );

    // Get the full record for `alpha`.
    let opts = GetOpts {
        include_unsigned: false,
        trust_policy: "warn-but-show".into(),
    };
    let r = api::get(&paths, "alpha", &opts).unwrap().unwrap();
    assert_eq!(r.id, "alpha");
}

#[test]
fn list_recent_pagination_works_against_real_index() {
    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    std::fs::create_dir_all(home.path().join("notebook.git")).unwrap();
    for i in 0..5 {
        write_local_yaml(&home, "decisions", &format!("d{i}"), &format!("body {i}"));
    }
    let mut cfg = Config::seed();
    cfg.adapters.cc.enabled = false;
    cfg.adapters.codex.enabled = false;
    cfg.adapters.local.enabled = true;
    let mut conn = open_or_create(&paths.index_db).unwrap();
    indexer_run(&mut conn, &cfg, &paths).unwrap();
    drop(conn);
    let rs1 = api::list(&paths, &cfg, &Filters::default(), 2, None).unwrap();
    assert_eq!(rs1.results.len(), 2);
    let cursor = rs1.next_cursor.expect("next_cursor present");
    let rs2 = api::list(&paths, &cfg, &Filters::default(), 2, Some(&cursor)).unwrap();
    assert_eq!(rs2.results.len(), 2);
    let id1: std::collections::HashSet<_> = rs1.results.iter().map(|r| &r.id).collect();
    let id2: std::collections::HashSet<_> = rs2.results.iter().map(|r| &r.id).collect();
    assert!(id1.is_disjoint(&id2), "pagination must not overlap");
}

#[test]
fn by_session_finds_cc_fixture_session_referenced_record() {
    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    std::fs::create_dir_all(home.path().join("notebook.git")).unwrap();

    let cfg = cfg_with_fixture_paths();
    let mut conn = open_or_create(&paths.index_db).unwrap();
    indexer_run(&mut conn, &cfg, &paths).unwrap();
    drop(conn);

    // The fixture's projalpha/memory/feedback_test_isolation.md
    // has originSessionId 11111111-1111-4111-8111-111111111111.
    let lookup = SessionLookup::CcSession {
        uuid: uuid::Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
    };
    let rs = api::by_session(&paths, &cfg, &lookup).unwrap();
    assert!(
        !rs.results.is_empty(),
        "expected at least one record referencing the fixture session"
    );
}

#[test]
fn second_pass_with_unchanged_corpus_is_zero_upserts() {
    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    std::fs::create_dir_all(home.path().join("notebook.git")).unwrap();
    write_local_yaml(&home, "decisions", "stable", "body");

    let mut cfg = Config::seed();
    cfg.adapters.cc.enabled = false;
    cfg.adapters.codex.enabled = false;
    cfg.adapters.local.enabled = true;
    let mut conn = open_or_create(&paths.index_db).unwrap();
    indexer_run(&mut conn, &cfg, &paths).unwrap();
    let second = indexer_run(&mut conn, &cfg, &paths).unwrap();
    assert_eq!(second.upserts, 0);
}
