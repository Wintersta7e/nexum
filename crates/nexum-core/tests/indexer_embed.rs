//! Indexer integration — verifies the vec0 write side. With
//! `embed.enabled = false` (the seed default) no rows should land in
//! `record_embeddings`. With embed enabled and a real model installed,
//! every upserted record gets a sibling embedding row.

mod common;

use common::{NexumTestHome, test_cfg_local_only, write_local_yaml};
use nexum_core::indexer::db::open_or_create;
use nexum_core::indexer::run::run as indexer_run;

#[test]
fn embed_disabled_keeps_vec0_empty() {
    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    let nb = home.path().join("notebook.git");
    std::fs::create_dir_all(&nb).unwrap();
    for i in 0..3 {
        write_local_yaml(&nb, "decisions", &format!("rec{i}"), &format!("body {i}"));
    }

    let cfg = test_cfg_local_only();
    assert!(
        !cfg.embed.enabled,
        "seed config must keep embeddings disabled by default",
    );

    let mut conn = open_or_create(&paths.index_db).unwrap();
    let outcome = indexer_run(&mut conn, &cfg, &paths).unwrap();
    assert_eq!(outcome.upserts, 3);

    let vec_count: i64 = conn
        .query_row("SELECT count(*) FROM record_embeddings", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        vec_count, 0,
        "record_embeddings must stay empty when embed.enabled is false",
    );
}

#[test]
#[ignore = "requires bge-m3 model installed; gated by NEXUM_E2E_EMBED env"]
fn each_upserted_record_has_a_vec0_row() {
    if std::env::var_os("NEXUM_E2E_EMBED").is_none() {
        return;
    }
    let model_dir = std::env::var_os("NEXUM_TEST_BGE_M3_DIR")
        .map(std::path::PathBuf::from)
        .expect("NEXUM_TEST_BGE_M3_DIR must point at an installed bge-m3 directory");

    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    let nb = home.path().join("notebook.git");
    std::fs::create_dir_all(&nb).unwrap();
    for i in 0..3 {
        write_local_yaml(&nb, "decisions", &format!("rec{i}"), &format!("body {i}"));
    }

    let mut cfg = test_cfg_local_only();
    cfg.embed.enabled = true;
    // `build_embedder_for_pass` resolves the parent directory of
    // `model_path`, so point it at `<model_dir>/model.onnx` even though
    // the file may not literally exist on every test rig — the loader
    // checks for it before constructing the Embedder.
    cfg.embed.model_path = model_dir.join("model.onnx").display().to_string();

    let mut conn = open_or_create(&paths.index_db).unwrap();
    let outcome = indexer_run(&mut conn, &cfg, &paths).unwrap();
    assert_eq!(outcome.upserts, 3);

    let vec_count: i64 = conn
        .query_row("SELECT count(*) FROM record_embeddings", [], |r| r.get(0))
        .unwrap();
    assert_eq!(vec_count, 3, "every upsert must write a vec0 row");
}
