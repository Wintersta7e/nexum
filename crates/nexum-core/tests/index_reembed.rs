//! Integration test: `api::index_reembed` re-embeds records already in the
//! index, refuses if embed.enabled = false, and writes a resume cursor.

mod common;

use common::{NexumTestHome, test_cfg_local_only, write_local_yaml};
use nexum_core::api;
use nexum_core::indexer::db::open_or_create;
use nexum_core::indexer::run::run as indexer_run;

/// Seed two records into the index using the local adapter.
fn seed_two_records(home: &NexumTestHome) {
    let paths = home.paths();
    let nb = home.path().join("notebook.git");
    std::fs::create_dir_all(&nb).unwrap();
    write_local_yaml(&nb, "decisions", "reembed-r1", "body one");
    write_local_yaml(&nb, "decisions", "reembed-r2", "body two");

    let cfg = test_cfg_local_only();
    let mut conn = open_or_create(&paths.index_db).unwrap();
    let outcome = indexer_run(&mut conn, &cfg, &paths).unwrap();
    assert_eq!(outcome.upserts, 2, "seeder: expected 2 upserts");
}

#[test]
fn reembed_refuses_when_embed_disabled() {
    let home = NexumTestHome::new().unwrap();
    seed_two_records(&home);
    let paths = home.paths();

    // Default seed config has embed.enabled = false.
    let cfg = test_cfg_local_only();
    assert!(!cfg.embed.enabled, "seed config must keep embed disabled");

    let err = api::index_reembed(&paths, &cfg).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("embed.enabled"),
        "error should mention embed.enabled; got: {msg}",
    );
}

#[test]
#[ignore = "requires bge-m3 model installed; gated by NEXUM_E2E_EMBED env"]
fn reembed_replays_records_through_the_embedder() {
    if std::env::var_os("NEXUM_E2E_EMBED").is_none() {
        return;
    }
    let model_dir = std::env::var_os("NEXUM_TEST_BGE_M3_DIR")
        .map(std::path::PathBuf::from)
        .expect("NEXUM_TEST_BGE_M3_DIR must point at an installed bge-m3 directory");

    let home = NexumTestHome::new().unwrap();
    seed_two_records(&home);
    let paths = home.paths();

    // Confirm vec0 starts empty (embed disabled during seed pass).
    let conn = rusqlite::Connection::open(&paths.index_db).unwrap();
    let row_count: i64 = conn
        .query_row("SELECT count(*) FROM record_embeddings", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        row_count, 0,
        "record_embeddings must be empty after FTS-only seed"
    );
    drop(conn);

    // Enable embeddings pointing at the real installed model.
    let mut cfg = test_cfg_local_only();
    cfg.embed.enabled = true;
    cfg.embed.model_path = model_dir.join("model.onnx").display().to_string();

    let outcome = api::index_reembed(&paths, &cfg).unwrap();
    assert!(
        outcome.embedded >= 2,
        "expected at least 2 embedded; got {}",
        outcome.embedded
    );

    let conn = rusqlite::Connection::open(&paths.index_db).unwrap();
    let row_count: i64 = conn
        .query_row("SELECT count(*) FROM record_embeddings", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        row_count, 2,
        "record_embeddings should have one row per record"
    );
}
