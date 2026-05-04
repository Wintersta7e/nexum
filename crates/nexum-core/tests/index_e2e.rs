//! End-to-end test — ingest fixtures into a fresh `index.db`, then run the
//! query verbs and assert on results.

mod common;

use common::NexumTestHome;
use nexum_core::{
    api,
    indexer::db::open_or_create,
    indexer::run::run as indexer_run,
    paths::Paths,
    query::{Filters, GetOpts, SearchOpts, SessionLookup},
    records::{GetOutcome, RecordKey, TrustPolicy},
};

#[test]
fn full_pass_indexes_cc_fixtures_local_yaml_and_runs_search() {
    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    let nb = home.path().join("notebook.git");
    std::fs::create_dir_all(&nb).unwrap();
    common::write_local_yaml(&nb, "decisions", "alpha", "concurrency body");
    common::write_local_yaml(&nb, "decisions", "beta", "auth body");

    let memories_temp = tempfile::TempDir::new().unwrap();
    let cfg = common::test_cfg_with_fixtures(memories_temp.path());
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
        trust_policy: TrustPolicy::WarnButShow,
    };
    let outcome = api::get(&paths, &RecordKey::bare("alpha"), &opts).unwrap();
    let GetOutcome::Found(r) = outcome else {
        panic!("expected Found")
    };
    assert_eq!(r.id, "alpha");
}

#[test]
fn list_recent_pagination_works_against_real_index() {
    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    let nb = home.path().join("notebook.git");
    std::fs::create_dir_all(&nb).unwrap();
    for i in 0..5 {
        common::write_local_yaml(&nb, "decisions", &format!("d{i}"), &format!("body {i}"));
    }
    let cfg = common::test_cfg_local_only();
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

    let memories_temp = tempfile::TempDir::new().unwrap();
    let cfg = common::test_cfg_with_fixtures(memories_temp.path());
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
    let nb = home.path().join("notebook.git");
    std::fs::create_dir_all(&nb).unwrap();
    common::write_local_yaml(&nb, "decisions", "stable", "body");

    let cfg = common::test_cfg_local_only();
    let mut conn = open_or_create(&paths.index_db).unwrap();
    indexer_run(&mut conn, &cfg, &paths).unwrap();
    let second = indexer_run(&mut conn, &cfg, &paths).unwrap();
    assert_eq!(second.upserts, 0);
}

#[test]
fn tag_change_alone_triggers_reindex() {
    // Regression: editing only the tag list of a record (title / summary /
    // body unchanged) must still re-upsert. Before index_hash landed the
    // indexer skipped on content_hash alone, silently dropping tag edits.
    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    let nb = home.path().join("notebook.git");
    std::fs::create_dir_all(&nb).unwrap();

    let yaml_path = nb.join("decisions").join("rec.yml");
    std::fs::create_dir_all(yaml_path.parent().unwrap()).unwrap();
    let yaml_v1 = "schema_version: 1\n\
         id: rec\n\
         record_type: decision\n\
         title: rec\n\
         body: |\n  same body\n\
         project_id: example\n\
         tags: [a]\n\
         agent: manual\n\
         created: 2026-04-29T00:00:00Z\n\
         updated: 2026-04-29T00:00:00Z\n\
         confidence: high\n\
         outcome: working\n";
    std::fs::write(&yaml_path, yaml_v1).unwrap();

    let cfg = common::test_cfg_local_only();
    let mut conn = open_or_create(&paths.index_db).unwrap();
    let first = indexer_run(&mut conn, &cfg, &paths).unwrap();
    assert_eq!(first.upserts, 1);
    let index_hash_v1: String = conn
        .query_row("SELECT index_hash FROM records WHERE id = 'rec'", [], |r| {
            r.get(0)
        })
        .unwrap();
    let content_hash_v1: String = conn
        .query_row(
            "SELECT content_hash FROM records WHERE id = 'rec'",
            [],
            |r| r.get(0),
        )
        .unwrap();

    // Edit ONLY tags. title / summary / body stay byte-identical, so
    // content_hash must NOT change. index_hash MUST change.
    let yaml_v2 = yaml_v1.replace("tags: [a]", "tags: [a, b]");
    assert_ne!(yaml_v1, yaml_v2, "test must actually mutate tags");
    std::fs::write(&yaml_path, yaml_v2).unwrap();

    let second = indexer_run(&mut conn, &cfg, &paths).unwrap();
    assert_eq!(
        second.upserts, 1,
        "tag-only edit must trigger re-upsert (regression: previously 0)"
    );
    let index_hash_v2: String = conn
        .query_row("SELECT index_hash FROM records WHERE id = 'rec'", [], |r| {
            r.get(0)
        })
        .unwrap();
    let content_hash_v2: String = conn
        .query_row(
            "SELECT content_hash FROM records WHERE id = 'rec'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_ne!(
        index_hash_v1, index_hash_v2,
        "index_hash must change when tags change"
    );
    assert_eq!(
        content_hash_v1, content_hash_v2,
        "content_hash must NOT change when only tags change"
    );
}

#[test]
fn verified_local_record_persists_signer_fingerprint_and_basis() {
    // End-to-end smoke for verifier-provenance scaffolding:
    //   1. `nexum init` brings up `notebook.git` with a signed bootstrap
    //      commit and `.trust/historical_signers`.
    //   2. We add a record YAML and commit it under the same SSH key, so
    //      `git log -1 -- <path>` resolves to a signed commit verifiable
    //      against `historical_signers`.
    //   3. The indexer runs and the local adapter populates
    //      `record_commit_sha`, `signer_fingerprint`, and
    //      `trust_basis = "current"` for that row.
    use common::write_ephemeral_keypair;
    use nexum_core::init::{InitOpts, git_ops::git_commit_signed, run as init_run};

    let home = NexumTestHome::new().unwrap();
    let key_dir = tempfile::tempdir().unwrap();
    let priv_path = write_ephemeral_keypair(key_dir.path());
    let init_outcome = init_run(InitOpts {
        ssh_key: Some(priv_path),
        root: Some(home.path().join(".nexum")),
        force: false,
    })
    .expect("init must succeed");
    let nb = init_outcome.root.join("notebook.git");

    // Write a local-format YAML record under decisions/ and commit it
    // signed. Signing config was applied to the repo by `init::run`, so
    // `git_commit_signed` produces a signed commit verifiable against
    // historical_signers.
    let record_id = "verified-record";
    let yaml_rel = std::path::PathBuf::from("decisions").join(format!("{record_id}.yml"));
    let abs = nb.join(&yaml_rel);
    std::fs::create_dir_all(abs.parent().unwrap()).unwrap();
    std::fs::write(
        &abs,
        format!(
            "schema_version: 1\nid: {record_id}\nrecord_type: decision\n\
             title: signed record title\nbody: |\n  signed body\n\
             project_id: example\ntags: []\nagent: manual\n\
             created: 2026-04-29T00:00:00Z\nupdated: 2026-04-29T00:00:00Z\n\
             confidence: high\noutcome: working\n"
        ),
    )
    .unwrap();
    git_commit_signed(&nb, &[&yaml_rel], "add: signed record").expect("signed commit");

    let paths = Paths::with_home(init_outcome.root.clone());
    let cfg = common::test_cfg_local_only();
    let mut conn = open_or_create(&paths.index_db).unwrap();
    indexer_run(&mut conn, &cfg, &paths).unwrap();

    let (basis, fp, sha, warning): (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = conn
        .query_row(
            "SELECT trust_basis, signer_fingerprint, record_commit_sha, warning_code \
             FROM records WHERE id = ?1",
            [record_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        basis.as_deref(),
        Some("current"),
        "verified row must record trust_basis=current"
    );
    assert!(
        fp.as_deref()
            .is_some_and(|s| s.starts_with("SHA256:") || !s.is_empty()),
        "verified row must capture a signer fingerprint, got {fp:?}"
    );
    assert!(
        sha.as_deref().is_some_and(|s| s.len() == 40),
        "verified row must capture a 40-char commit SHA, got {sha:?}"
    );
    assert!(
        warning.is_none(),
        "verified row must not raise a warning_code, got {warning:?}"
    );
}

#[test]
fn cc_records_leave_provenance_columns_null() {
    // The cc / codex adapters do not track notebook-git provenance, so
    // every row they ingest should have NULL in the four verifier columns.
    let home = NexumTestHome::new().unwrap();
    let paths = home.paths();
    std::fs::create_dir_all(home.path().join("notebook.git")).unwrap();
    let memories_temp = tempfile::TempDir::new().unwrap();
    let cfg = common::test_cfg_with_fixtures(memories_temp.path());
    let mut conn = open_or_create(&paths.index_db).unwrap();
    indexer_run(&mut conn, &cfg, &paths).unwrap();

    // Count CC rows where any verifier-provenance column is non-NULL —
    // expectation: zero. Reading the four columns one-shot avoids
    // surfacing a row-by-row materialization.
    let mut stmt = conn
        .prepare(
            "SELECT count(*) FROM records \
             WHERE source = 'cc-native' \
               AND (record_commit_sha IS NOT NULL \
                 OR signer_fingerprint IS NOT NULL \
                 OR trust_basis IS NOT NULL \
                 OR warning_code IS NOT NULL)",
        )
        .unwrap();
    let leaks: i64 = stmt.query_row([], |r| r.get(0)).unwrap();
    assert_eq!(
        leaks, 0,
        "cc-native rows must leave verifier-provenance columns NULL"
    );

    // Sanity: at least one CC row was actually indexed, so the assertion
    // above isn't trivially satisfied by an empty table.
    let cc_rows: i64 = conn
        .query_row(
            "SELECT count(*) FROM records WHERE source = 'cc-native'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(cc_rows > 0, "expected at least one CC fixture row");
}
