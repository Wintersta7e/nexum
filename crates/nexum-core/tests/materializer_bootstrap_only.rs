//! Integration test: a real signed bootstrap commit produced by `init::run`
//! materializes into exactly one `BootstrapKey` row in `trust_events`.

mod common;

use common::{NexumTestHome, write_ephemeral_keypair};
use nexum_core::indexer::db::open_or_create;
use nexum_core::init::{InitOpts, run as init_run};
use nexum_core::paths::Paths;
use nexum_core::trust::events_view::rebuild;

#[test]
fn materializer_against_real_init_produces_one_trust_event() {
    let home = NexumTestHome::default();
    let key_dir = tempfile::tempdir().unwrap();
    let priv_path = write_ephemeral_keypair(key_dir.path());
    let outcome = init_run(InitOpts {
        ssh_key: Some(priv_path),
        root: Some(home.path().join(".nexum")),
        force: false,
    })
    .expect("init must succeed");

    let paths = Paths::with_home(outcome.root.clone());
    let mut conn = open_or_create(&paths.index_db).expect("open index db");

    let m = rebuild(&mut conn, &paths.notebook_git).expect("materializer should succeed");
    assert_eq!(m.events_count, 1);
    assert_eq!(m.tampering_count, 0);

    let (kind, fp): (String, String) = conn
        .query_row(
            "SELECT kind, fingerprint FROM trust_events LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(kind, "BootstrapKey");
    assert_eq!(fp, outcome.fingerprint);
}
