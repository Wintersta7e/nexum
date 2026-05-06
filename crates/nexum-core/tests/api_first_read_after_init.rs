//! Regression: read verbs must succeed on the first invocation after a fresh
//! init, even when no prior index pass has populated the trust-events
//! sentinels. The materializer rebuilds on demand inside the read path, which
//! requires write access on the same connection.

mod common;

use common::{NexumTestHome, write_ephemeral_keypair};
use nexum_core::{
    api,
    config::types::Config,
    indexer::db::open_or_create,
    init::{InitOpts, run as init_run},
    paths::Paths,
    query::{Filters, SearchOpts},
};

fn fresh_install_with_empty_index() -> (NexumTestHome, Paths, Config) {
    let home = NexumTestHome::new().unwrap();
    let key_dir = tempfile::tempdir().unwrap();
    let priv_path = write_ephemeral_keypair(key_dir.path());

    let outcome = init_run(InitOpts {
        ssh_key: Some(priv_path),
        root: Some(home.path().join(".nexum")),
        force: false,
    })
    .expect("init succeeds");

    let paths = Paths::with_home(outcome.root);

    // Mirror "indexer ran but produced 0 records and didn't trigger
    // ensure_current" — the codex/cc-only configuration the docker e2e
    // surfaces, where local_pass is None so the indexer skips the
    // materializer call.
    let conn = open_or_create(&paths.index_db).expect("open_or_create succeeds");
    drop(conn);

    let mut cfg = Config::seed();
    cfg.adapters.cc.enabled = false;
    cfg.adapters.codex.enabled = false;
    cfg.adapters.local.enabled = false;
    (home, paths, cfg)
}

#[test]
fn search_after_fresh_init_triggers_materialization_without_readonly_error() {
    let (_home, paths, cfg) = fresh_install_with_empty_index();
    let result = api::search(&paths, &cfg, &SearchOpts::new("anything"));
    result.expect("search must succeed; the materializer needs write access on first read");
}

#[test]
fn list_after_fresh_init_triggers_materialization_without_readonly_error() {
    let (_home, paths, cfg) = fresh_install_with_empty_index();
    let result = api::list(&paths, &cfg, &Filters::default(), 10, None);
    result.expect("list must succeed");
}

#[test]
fn recent_after_fresh_init_triggers_materialization_without_readonly_error() {
    let (_home, paths, cfg) = fresh_install_with_empty_index();
    let result = api::recent(&paths, &cfg, 10, None);
    result.expect("recent must succeed");
}
