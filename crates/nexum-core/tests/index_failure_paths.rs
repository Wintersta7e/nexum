//! Failure-path integration tests — cross-module behavior under partial,
//! malformed, and ambiguous inputs.

mod common;

use common::NexumTestHome;
use nexum_core::{
    adapter::{Adapter, PassCompleteness, codex::CodexAdapter},
    indexer::{db::open_or_create, run::run as indexer_run, state::STALE_THRESHOLD},
};

#[test]
fn codex_with_missing_state_db_yields_partial_pass() {
    let home = NexumTestHome::new().unwrap();
    let memories = home.path().join("memories");
    std::fs::create_dir_all(&memories).unwrap();
    std::fs::write(
        memories.join("MEMORY.md"),
        "## Task 1\nbody\n### keywords\nauth\n",
    )
    .unwrap();
    let adapter = CodexAdapter::new(memories, home.path().join("missing.sqlite"), false);
    let pass = adapter.list().unwrap();
    assert!(
        matches!(pass.completeness, PassCompleteness::Partial { .. }),
        "expected Partial completeness, got {:?}",
        pass.completeness
    );
    assert_eq!(pass.records.len(), 1, "well-formed records still ingested");
}

#[test]
fn partial_pass_suppresses_delete_computation_in_indexer() {
    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    let nb = home.path().join("notebook.git");
    common::write_local_yaml(&nb, "decisions", "alpha", "body");

    let cfg = common::test_cfg_local_only();
    let mut conn = open_or_create(&paths.index_db).unwrap();
    indexer_run(&mut conn, &cfg, &paths).unwrap();

    // Inject a malformed yaml. The local pass becomes Partial; the indexer
    // must NOT delete `alpha`.
    let bad = nb.join("decisions").join("bad.yml");
    std::fs::write(&bad, ":: not [valid yaml [").unwrap();

    let outcome = indexer_run(&mut conn, &cfg, &paths).unwrap();
    let count: i64 = conn
        .query_row("SELECT count(*) FROM records WHERE id = 'alpha'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 1, "alpha must persist across a Partial pass");
    assert_eq!(outcome.deletes, 0, "no deletes on a Partial pass");
}

#[test]
fn three_authoritative_misses_after_partial_reset_dont_delete() {
    // This test's narrative is structured around STALE_THRESHOLD == 3. If the
    // constant changes, update the loop bounds + assertion messages below.
    assert_eq!(STALE_THRESHOLD, 3, "test logic assumes threshold == 3");

    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    let nb = home.path().join("notebook.git");
    common::write_local_yaml(&nb, "decisions", "alpha", "body");

    let cfg = common::test_cfg_local_only();
    let mut conn = open_or_create(&paths.index_db).unwrap();
    indexer_run(&mut conn, &cfg, &paths).unwrap();

    // Remove alpha — next Authoritative pass bumps miss counter.
    std::fs::remove_file(nb.join("decisions").join("alpha.yml")).unwrap();
    indexer_run(&mut conn, &cfg, &paths).unwrap(); // counter = 1
    indexer_run(&mut conn, &cfg, &paths).unwrap(); // counter = 2

    // Inject malformed file → next pass is Partial → counter resets.
    let bad = nb.join("decisions").join("bad.yml");
    std::fs::write(&bad, ":: not [yaml [").unwrap();
    indexer_run(&mut conn, &cfg, &paths).unwrap();

    // Remove bad file, run two more Authoritative passes; alpha must NOT
    // be deleted (counter = 2/3).
    std::fs::remove_file(&bad).unwrap();
    indexer_run(&mut conn, &cfg, &paths).unwrap();
    indexer_run(&mut conn, &cfg, &paths).unwrap();
    let count: i64 = conn
        .query_row("SELECT count(*) FROM records WHERE id = 'alpha'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(
        count, 1,
        "Partial pass must reset counters; only 2/3 misses since reset"
    );

    // Third post-reset Authoritative miss → delete.
    indexer_run(&mut conn, &cfg, &paths).unwrap();
    let count: i64 = conn
        .query_row("SELECT count(*) FROM records WHERE id = 'alpha'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 0, "third post-reset Authoritative miss deletes");
}

#[test]
fn ambiguous_cc_slug_ingests_with_first_candidate_fallback() {
    // The `-tmp-fixture-my-hyphenated-app` slug has 4 internal hyphens.
    // The adapter must produce a record without panicking, fall back to
    // the ranked first candidate, and ingest.
    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    std::fs::create_dir_all(home.path().join("notebook.git")).unwrap();

    let mut cfg = nexum_core::config::types::Config::seed();
    cfg.adapters.cc.enabled = true;
    cfg.adapters.cc.projects_dir = common::fixture_cc_projects().display().to_string();
    cfg.adapters.codex.enabled = false;
    cfg.adapters.local.enabled = false;
    let mut conn = open_or_create(&paths.index_db).unwrap();
    let outcome = indexer_run(&mut conn, &cfg, &paths).unwrap();
    assert!(outcome.upserts > 0);

    let n: i64 = conn
        .query_row(
            "SELECT count(*) FROM records WHERE source = 'cc-native' AND id = 'feedback_naming'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1, "my-hyphenated-app fixture must produce one record");
}
