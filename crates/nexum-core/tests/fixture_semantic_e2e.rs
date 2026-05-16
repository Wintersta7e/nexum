//! End-to-end: a tiny three-cluster fixture corpus exercises the full
//! semantic ranking path. The query "concurrency" matches nothing via
//! FTS5 BM25 (no record body contains the literal token) but is
//! semantically closest to the four thread-safety records.
//!
//! Two tests live here:
//!
//! - `fts_only_query_returns_zero_for_no_keyword_match` always runs.
//!   With `embed.enabled = false` (the seed default) the FTS branch
//!   is the only one that fires, and it finds nothing.
//! - `semantic_query_returns_thread_safety_cluster` is `#[ignore]`d
//!   and gated by the `NEXUM_E2E_EMBED` env var plus a real bge-m3
//!   model directory in `NEXUM_TEST_BGE_M3_DIR`. It asserts that the
//!   semantic branch lifts the four concurrency records to the top.

mod common;

use std::path::{Path, PathBuf};

use common::{NexumTestHome, test_cfg_local_only};
use nexum_core::api;
use nexum_core::indexer::db::open_or_create;
use nexum_core::indexer::run::run as indexer_run;
use nexum_core::query::SearchOpts;

const FIXTURE_DIR: &str = "tests/fixtures/semantic";

fn fixture_corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_DIR)
}

/// Copy every `*.yml` in `src` into `dst/decisions/` so the local
/// adapter picks them up. The adapter only walks
/// `notebook.git/{decisions,recommendations,failures}` — every fixture
/// in this corpus declares `record_type: decision` to match.
fn copy_fixtures_into_notebook(src: &Path, notebook_git: &Path) {
    let dst = notebook_git.join("decisions");
    std::fs::create_dir_all(&dst).expect("create_dir_all decisions");
    for entry in std::fs::read_dir(src).expect("read fixture dir").flatten() {
        let p = entry.path();
        if p.extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("yml"))
        {
            let name = p.file_name().expect("file name");
            std::fs::copy(&p, dst.join(name)).expect("copy fixture yaml");
        }
    }
}

#[test]
fn fts_only_query_returns_zero_for_no_keyword_match() {
    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    let nb = home.path().join("notebook.git");
    std::fs::create_dir_all(&nb).unwrap();
    copy_fixtures_into_notebook(&fixture_corpus(), &nb);

    let cfg = test_cfg_local_only();
    assert!(
        !cfg.embed.enabled,
        "seed config must keep embeddings disabled by default",
    );

    let mut conn = open_or_create(&paths.index_db).unwrap();
    let outcome = indexer_run(&mut conn, &cfg, &paths).unwrap();
    assert_eq!(outcome.upserts, 12, "12 fixture records must index");
    drop(conn);

    let res = api::search(&paths, &cfg, &SearchOpts::new("concurrency")).unwrap();
    assert_eq!(
        res.results.len(),
        0,
        "FTS5 must return zero rows for a query token that appears in no \
         indexed column; got: {:?}",
        res.results.iter().map(|r| &r.id).collect::<Vec<_>>()
    );
}

#[test]
#[ignore = "requires bge-m3 model installed; gated by NEXUM_E2E_EMBED env"]
fn semantic_query_returns_thread_safety_cluster() {
    if std::env::var_os("NEXUM_E2E_EMBED").is_none() {
        eprintln!(
            "skipping: set NEXUM_E2E_EMBED=1 and point NEXUM_TEST_BGE_M3_DIR \
             at an installed bge-m3 directory"
        );
        return;
    }
    let model_dir = std::env::var_os("NEXUM_TEST_BGE_M3_DIR")
        .map(PathBuf::from)
        .expect("NEXUM_TEST_BGE_M3_DIR must point at an installed bge-m3 directory");

    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    let nb = home.path().join("notebook.git");
    std::fs::create_dir_all(&nb).unwrap();
    copy_fixtures_into_notebook(&fixture_corpus(), &nb);

    let mut cfg = test_cfg_local_only();
    cfg.embed.enabled = true;
    cfg.embed.model_path = model_dir.join("model.onnx").display().to_string();

    let mut conn = open_or_create(&paths.index_db).unwrap();
    let outcome = indexer_run(&mut conn, &cfg, &paths).unwrap();
    assert_eq!(outcome.upserts, 12);
    drop(conn);

    let mut opts = SearchOpts::new("concurrency");
    opts.top_k = 4;
    let res = api::search(&paths, &cfg, &opts).unwrap();

    let ids: Vec<&str> = res.results.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids.len(), 4, "expected the top 4 matches, got {ids:?}");
    assert!(
        ids.iter().all(|id| id.starts_with("concurrency_")),
        "semantic ranking should lift the four thread-safety records to \
         the top; got {ids:?}",
    );
}
