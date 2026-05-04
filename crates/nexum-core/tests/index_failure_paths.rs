//! Failure-path integration tests — cross-module behavior under partial,
//! malformed, and ambiguous inputs.

mod common;

use common::{NexumTestHome, record_count};
use nexum_core::{
    adapter::{Adapter, PassCompleteness, codex::CodexAdapter},
    indexer::{db::open_or_create, run::run as indexer_run, state::STALE_THRESHOLD},
    records::types::Source,
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

#[test]
fn missing_root_with_prior_records_does_not_prune() {
    let home = NexumTestHome::new().unwrap();
    let mut paths = home.paths();
    // Point notebook_git at a path we can remove later.
    let nb = home.path().join("notebook.git");
    paths.notebook_git = nb.clone();
    std::fs::create_dir_all(&nb).unwrap();
    common::write_local_yaml(&nb, "decisions", "r1", "body text");

    let cfg = common::test_cfg_local_only();
    let mut conn = open_or_create(&paths.index_db).unwrap();
    let first_outcome = indexer_run(&mut conn, &cfg, &paths).unwrap();
    assert_eq!(record_count(&paths.index_db), 1, "initial record inserted");

    // First pass must have been authoritative (root existed).
    let local_first = first_outcome
        .per_source
        .iter()
        .find(|s| s.source == Source::Local)
        .expect("local source must appear in first outcome");
    assert_eq!(
        local_first.completeness,
        nexum_core::indexer::run::PerSourceCompleteness::Authoritative,
        "first pass with existing root must be authoritative"
    );

    // Remove the root entirely. Re-run: must NOT prune the prior record.
    std::fs::remove_dir_all(&nb).unwrap();
    let outcome = indexer_run(&mut conn, &cfg, &paths);
    assert!(
        outcome.is_ok(),
        "missing root + prior records must not error"
    );
    assert_eq!(
        record_count(&paths.index_db),
        1,
        "prior record retained after missing root"
    );

    // Second pass must report missing_root, not authoritative.
    let local_second = outcome
        .unwrap()
        .per_source
        .into_iter()
        .find(|s| s.source == Source::Local)
        .expect("local source must appear in second outcome");
    assert_eq!(
        local_second.completeness,
        nexum_core::indexer::run::PerSourceCompleteness::MissingRoot,
        "second pass must report missing_root after root removal"
    );

    // Three more missing-root passes must still not prune.
    indexer_run(&mut conn, &cfg, &paths).unwrap();
    indexer_run(&mut conn, &cfg, &paths).unwrap();
    indexer_run(&mut conn, &cfg, &paths).unwrap();
    assert_eq!(
        record_count(&paths.index_db),
        1,
        "prior record retained across repeated missing-root passes"
    );
}

#[test]
fn missing_root_with_empty_index_is_no_op() {
    let home = NexumTestHome::new().unwrap();
    let mut paths = home.paths();
    // Point notebook_git at a path that will never exist.
    paths.notebook_git = home.path().join("does-not-exist");

    let cfg = common::test_cfg_local_only();
    let mut conn = open_or_create(&paths.index_db).unwrap();
    let outcome = indexer_run(&mut conn, &cfg, &paths);
    assert!(
        outcome.is_ok(),
        "missing root on empty index must not error"
    );
    assert_eq!(record_count(&paths.index_db), 0, "empty index stays empty");

    // Confirm the adapter saw MissingRoot, not Authoritative-empty. Without
    // this the test would still pass if the adapter silently fell back to an
    // authoritative-zero pass.
    let outcome = outcome.unwrap();
    let local = outcome
        .per_source
        .iter()
        .find(|s| s.source == Source::Local)
        .expect("local source must appear in outcome");
    assert_eq!(
        local.completeness,
        nexum_core::indexer::run::PerSourceCompleteness::MissingRoot,
        "local source must report missing_root, not authoritative"
    );
}
