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
fn embed_disabled_with_unchanged_content_skips_recompute() {
    // Embed disabled: the indexer never computes embeddings, so a
    // tag-only edit on the second pass must remain a no-op on the
    // `record_embeddings` table (which stays empty). This mirrors the
    // `embed_disabled_keeps_vec0_empty` test but adds a content-unchanged
    // upsert step (overwriting the YAML with identical content_hash for
    // the same id) to assert the skip path is correctness-preserving
    // even when nothing changed.
    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    let nb = home.path().join("notebook.git");
    std::fs::create_dir_all(&nb).unwrap();
    write_local_yaml(&nb, "decisions", "rec0", "body 0");

    let cfg = test_cfg_local_only();
    assert!(!cfg.embed.enabled);

    let mut conn = open_or_create(&paths.index_db).unwrap();
    let first = indexer_run(&mut conn, &cfg, &paths).unwrap();
    assert_eq!(first.upserts, 1);

    // Re-run with the same on-disk content: the dual-hash skip elides the
    // upsert entirely, and record_embeddings remains empty.
    let second = indexer_run(&mut conn, &cfg, &paths).unwrap();
    assert_eq!(second.upserts, 0, "unchanged content_hash skips upsert");

    let vec_count: i64 = conn
        .query_row("SELECT count(*) FROM record_embeddings", [], |r| r.get(0))
        .unwrap();
    assert_eq!(vec_count, 0);
}

#[test]
fn upsert_with_no_embedding_preserves_prior_vec0_row() {
    // Regression: a transient embed failure (or embed disabled on a re-index
    // pass against a row that previously carried a vec0 vector) must NOT
    // strip the stored embedding. Prior behavior unconditionally deleted
    // the vec0 row whenever the content changed, even when no replacement
    // vector was available — silently dropping rows from the semantic
    // branch until another content edit triggered a refresh.
    //
    // The reachable surrogate for the embed-failure path is the embed-
    // disabled path: both produce `embedding = None` at the upsert call
    // site, and the upsert SQL must treat them identically (keep the prior
    // row). The ignored end-to-end test below pins the embed-enabled half
    // of the invariant when a real bge-m3 install is present.
    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    let nb = home.path().join("notebook.git");
    std::fs::create_dir_all(&nb).unwrap();
    write_local_yaml(&nb, "decisions", "rec0", "initial body");

    let cfg = test_cfg_local_only();
    assert!(!cfg.embed.enabled);

    let mut conn = open_or_create(&paths.index_db).unwrap();
    let first = indexer_run(&mut conn, &cfg, &paths).unwrap();
    assert_eq!(first.upserts, 1);

    // Manually seed a vec0 row for the just-inserted record. This mirrors
    // the state after a prior pass that ran with embed.enabled = true.
    let rowid: i64 = conn
        .query_row("SELECT rowid FROM records WHERE id = 'rec0'", [], |r| {
            r.get(0)
        })
        .unwrap();
    let seed_vec = vec![0.5_f32; nexum_core::embed::EMBED_DIM];
    let blob = nexum_core::embed::f32_slice_to_le_bytes(&seed_vec);
    conn.execute(
        "INSERT INTO record_embeddings (record_rowid, embedding) VALUES (?1, vec_f32(?2))",
        rusqlite::params![rowid, blob.as_slice()],
    )
    .unwrap();
    let vec_count: i64 = conn
        .query_row("SELECT count(*) FROM record_embeddings", [], |r| r.get(0))
        .unwrap();
    assert_eq!(vec_count, 1, "seeded vec0 row should be present");

    // Edit the YAML so content changes; re-run indexer with embed disabled.
    // The upsert path runs with `embedding = None` (no embedder) and
    // `content_changed = true`. The fixed code keeps the prior vec0 row.
    std::fs::write(
        nb.join("decisions").join("rec0.yml"),
        "schema_version: 1\nid: rec0\nrecord_type: decision\ntitle: rec0\nbody: |\n  edited body\nproject_id: example\ntags: []\nagent: manual\ncreated: 2026-04-29T00:00:00Z\nupdated: 2026-04-30T00:00:00Z\nconfidence: high\noutcome: working\n",
    )
    .unwrap();
    let second = indexer_run(&mut conn, &cfg, &paths).unwrap();
    assert_eq!(second.upserts, 1, "content change must drive an upsert");

    let vec_count_after: i64 = conn
        .query_row("SELECT count(*) FROM record_embeddings", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        vec_count_after, 1,
        "prior vec0 row must survive a content edit when embedding=None",
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
