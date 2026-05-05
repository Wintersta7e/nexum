//! Integration tests for the materializer's `BootstrapReanchor` exception.
//!
//! Each test builds a synthetic notebook.git via the fixture builder,
//! optionally writes a bootstrap pin to the fixture's home directory, and
//! runs `rebuild` against a freshly-created index database. The assertions
//! cover both the authorized and unauthorized branches:
//!
//! - Authorized reanchor (pin present, signer matches `new_fingerprint`,
//!   `old_fingerprint` matches the prior bootstrap): `BootstrapReanchor`
//!   row written; chain advances.
//! - Authorized reanchor with `acknowledge_chain_anchor_lost = true`: same
//!   shape, but `chain_anchor_lost` column is `1` (Case B).
//! - Unauthorized reanchor (signer mismatch, or `old_fingerprint` mismatch):
//!   chain freezes via the `chain_frozen_at_topo` meta sentinel; no row
//!   in `trust_chain_tampering`, no row in `trust_events`.
//! - Multi-event commit landing alongside a `BootstrapReanchor`: routed
//!   through the `Diff::Forbidden` path (multi-event append), recording a
//!   `ReorderedDeleted` tampering row.

mod trust;

use nexum_core::index::meta::{KEY_CHAIN_FROZEN_AT_TOPO, read_topo};
use nexum_core::trust::events_view::rebuild;
use trust::fixtures::{commit_events_yml, new_keypair};
use trust::{fresh_index_db, fresh_notebook_with_bootstrap};
use uuid::Uuid;

/// Append a `KeyAdded` event for `secondary` in the second commit, signed by
/// the bootstrap key. Returns the event id of the appended event so callers
/// can chain a third revision against the `bootstrap + KeyAdded` shape.
/// Used by the reanchor tests to introduce the new bootstrap key into the
/// chain via a regular append before the reanchor commit lands.
fn append_secondary_key(
    fixture: &trust::fixtures::NotebookFixture,
    primary: &trust::fixtures::KeyPair,
    bootstrap_event: Uuid,
    secondary: &trust::fixtures::KeyPair,
) -> (Uuid, String) {
    let added_event = Uuid::now_v7();
    let yaml = format!(
        "schema_version: 1\n\
         events:\n  \
         - event_id: {ev1}\n    kind: BootstrapKey\n    fingerprint: \"{fp1}\"\n    public_key: \"{pk1}\"\n    reason: \"Initial bootstrap\"\n  \
         - event_id: {ev2}\n    kind: KeyAdded\n    fingerprint: \"{fp2}\"\n    public_key: \"{pk2}\"\n    reason: \"Pre-recovery key add\"\n",
        ev1 = bootstrap_event,
        fp1 = primary.fingerprint,
        pk1 = primary.public_openssh.trim(),
        ev2 = added_event,
        fp2 = secondary.fingerprint,
        pk2 = secondary.public_openssh.trim(),
    );
    commit_events_yml(fixture.path(), &yaml, &primary.private_path);
    (added_event, yaml)
}

#[test]
fn authorized_reanchor_with_pin_match_writes_event_row_case_a() {
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();
    let secondary = new_keypair(fixture.path(), "secondary");
    let (_added_event, after_added) =
        append_secondary_key(&fixture, &primary, bootstrap_event, &secondary);

    // Pin must match the new bootstrap before the reanchor commit lands —
    // production's recovery commands write the pin first, then create the
    // reanchor commit.
    fixture.write_pin(&secondary.fingerprint, &secondary.public_openssh);

    let reanchor_event = Uuid::now_v7();
    let with_reanchor = format!(
        "{after_added}  - event_id: {ev}\n    kind: BootstrapReanchor\n    old_fingerprint: \"{old}\"\n    new_fingerprint: \"{new}\"\n    reason: \"Bootstrap key lost; recovered via secondary\"\n",
        ev = reanchor_event,
        old = primary.fingerprint,
        new = secondary.fingerprint,
    );
    // Reanchor commit MUST be signed by the new bootstrap (secondary).
    commit_events_yml(fixture.path(), &with_reanchor, &secondary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    let m = rebuild(&mut conn, fixture.path()).expect("rebuild succeeds");
    assert_eq!(
        m.events_count, 3,
        "bootstrap + KeyAdded + BootstrapReanchor → 3 rows"
    );
    assert_eq!(m.tampering_count, 0);

    // The materializer wrote a BootstrapReanchor row with chain_anchor_lost = 0
    // (Case A: pin intact through recovery).
    let (kind, anchor_lost): (String, Option<i64>) = conn
        .query_row(
            "SELECT kind, chain_anchor_lost FROM trust_events WHERE event_id = ?1",
            [reanchor_event.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("BootstrapReanchor row present");
    assert_eq!(kind, "BootstrapReanchor");
    assert_eq!(anchor_lost, Some(0), "Case A → chain_anchor_lost = 0");

    // No chain freeze: authorized reanchor leaves the meta sentinel alone.
    let frozen = read_topo(&conn, KEY_CHAIN_FROZEN_AT_TOPO).expect("read meta");
    assert!(
        frozen.is_none(),
        "authorized reanchor must not freeze chain"
    );
}

#[test]
fn authorized_reanchor_with_acknowledge_anchor_lost_records_case_b() {
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();
    let secondary = new_keypair(fixture.path(), "secondary");
    let (_added_event, after_added) =
        append_secondary_key(&fixture, &primary, bootstrap_event, &secondary);

    // Recovery-without-pin path: the user lost their pin and re-established
    // it pointing at the new bootstrap. The pin file matches `new_fp`, but
    // the event payload acknowledges the chain anchor was lost.
    fixture.write_pin(&secondary.fingerprint, &secondary.public_openssh);

    let reanchor_event = Uuid::now_v7();
    let with_reanchor = format!(
        "{after_added}  - event_id: {ev}\n    kind: BootstrapReanchor\n    old_fingerprint: \"{old}\"\n    new_fingerprint: \"{new}\"\n    reason: \"Pin and bootstrap both lost; acknowledged\"\n    acknowledge_chain_anchor_lost: true\n",
        ev = reanchor_event,
        old = primary.fingerprint,
        new = secondary.fingerprint,
    );
    commit_events_yml(fixture.path(), &with_reanchor, &secondary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    let m = rebuild(&mut conn, fixture.path()).expect("rebuild succeeds");
    assert_eq!(m.events_count, 3);
    assert_eq!(m.tampering_count, 0);

    let anchor_lost: Option<i64> = conn
        .query_row(
            "SELECT chain_anchor_lost FROM trust_events WHERE event_id = ?1",
            [reanchor_event.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        anchor_lost,
        Some(1),
        "acknowledge_chain_anchor_lost = true → chain_anchor_lost = 1 (Case B)"
    );
}

#[test]
fn reanchor_with_pin_missing_freezes_chain() {
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();
    let secondary = new_keypair(fixture.path(), "secondary");
    let (_added_event, after_added) =
        append_secondary_key(&fixture, &primary, bootstrap_event, &secondary);

    // Deliberately do NOT write a pin: the reanchor verifier requires a pin
    // matching `new_fp` as a hard gate. Missing pin → unauthorized.
    fixture.delete_pin();

    let reanchor_event = Uuid::now_v7();
    let with_reanchor = format!(
        "{after_added}  - event_id: {ev}\n    kind: BootstrapReanchor\n    old_fingerprint: \"{old}\"\n    new_fingerprint: \"{new}\"\n    reason: \"Bootstrap key lost\"\n",
        ev = reanchor_event,
        old = primary.fingerprint,
        new = secondary.fingerprint,
    );
    commit_events_yml(fixture.path(), &with_reanchor, &secondary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    let m = rebuild(&mut conn, fixture.path()).expect("rebuild succeeds");
    assert_eq!(
        m.events_count, 2,
        "bootstrap + KeyAdded only; reanchor frozen out"
    );
    assert_eq!(
        m.tampering_count, 0,
        "unauthorized reanchor surfaces via meta sentinel, not tampering row"
    );

    // The chain freeze landed in meta at the reanchor's topo pos (= 2).
    let frozen = read_topo(&conn, KEY_CHAIN_FROZEN_AT_TOPO).expect("read meta");
    assert_eq!(frozen, Some(2), "chain frozen at the unauthorized reanchor");

    // No trust_events row for the unauthorized reanchor.
    let count: i64 = conn
        .query_row(
            "SELECT count(*) FROM trust_events WHERE kind = 'BootstrapReanchor'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn reanchor_with_signer_mismatch_freezes_chain() {
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();
    let secondary = new_keypair(fixture.path(), "secondary");
    let (_added_event, after_added) =
        append_secondary_key(&fixture, &primary, bootstrap_event, &secondary);

    // Pin says secondary, but the reanchor commit gets signed by the
    // primary instead of the secondary — Condition 4 fails (commit must be
    // signed by `new_fingerprint`).
    fixture.write_pin(&secondary.fingerprint, &secondary.public_openssh);

    let reanchor_event = Uuid::now_v7();
    let with_reanchor = format!(
        "{after_added}  - event_id: {ev}\n    kind: BootstrapReanchor\n    old_fingerprint: \"{old}\"\n    new_fingerprint: \"{new}\"\n    reason: \"Bootstrap key lost\"\n",
        ev = reanchor_event,
        old = primary.fingerprint,
        new = secondary.fingerprint,
    );
    // Sign with primary — wrong key for a reanchor commit.
    commit_events_yml(fixture.path(), &with_reanchor, &primary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    let m = rebuild(&mut conn, fixture.path()).expect("rebuild succeeds");
    assert_eq!(m.events_count, 2);
    assert_eq!(
        m.tampering_count, 0,
        "unauthorized reanchor surfaces via the meta sentinel, not as a tampering kind"
    );

    let frozen = read_topo(&conn, KEY_CHAIN_FROZEN_AT_TOPO).expect("read meta");
    assert_eq!(frozen, Some(2));
}

#[test]
fn reanchor_with_old_fingerprint_mismatch_freezes_chain() {
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();
    let secondary = new_keypair(fixture.path(), "secondary");
    let (_added_event, after_added) =
        append_secondary_key(&fixture, &primary, bootstrap_event, &secondary);

    // Pin matches the new bootstrap; commit will be signed by secondary;
    // but `old_fingerprint` references a key that was never bootstrap.
    // Condition 3 fails.
    fixture.write_pin(&secondary.fingerprint, &secondary.public_openssh);

    let reanchor_event = Uuid::now_v7();
    let with_reanchor = format!(
        "{after_added}  - event_id: {ev}\n    kind: BootstrapReanchor\n    old_fingerprint: \"SHA256:never-was-bootstrap\"\n    new_fingerprint: \"{new}\"\n    reason: \"Bootstrap key lost\"\n",
        ev = reanchor_event,
        new = secondary.fingerprint,
    );
    commit_events_yml(fixture.path(), &with_reanchor, &secondary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    let m = rebuild(&mut conn, fixture.path()).expect("rebuild succeeds");
    assert_eq!(m.events_count, 2);
    assert_eq!(m.tampering_count, 0);

    let frozen = read_topo(&conn, KEY_CHAIN_FROZEN_AT_TOPO).expect("read meta");
    assert_eq!(frozen, Some(2));
}

#[test]
fn reanchor_with_pin_fingerprint_not_matching_new_fp_freezes_chain() {
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();
    let secondary = new_keypair(fixture.path(), "secondary");
    let (_added_event, after_added) =
        append_secondary_key(&fixture, &primary, bootstrap_event, &secondary);

    // Pin a third, unrelated fingerprint — neither the primary (old) nor the
    // secondary (the reanchor's new_fingerprint). Condition 2 fails: the pin
    // must equal new_fp at verification time, even though the rest of the
    // reanchor (signer, old_fp, single-event commit) is correctly shaped.
    let tertiary = new_keypair(fixture.path(), "tertiary");
    fixture.write_pin(&tertiary.fingerprint, &tertiary.public_openssh);

    let reanchor_event = Uuid::now_v7();
    let with_reanchor = format!(
        "{after_added}  - event_id: {ev}\n    kind: BootstrapReanchor\n    old_fingerprint: \"{old}\"\n    new_fingerprint: \"{new}\"\n    reason: \"Bootstrap key lost\"\n",
        ev = reanchor_event,
        old = primary.fingerprint,
        new = secondary.fingerprint,
    );
    commit_events_yml(fixture.path(), &with_reanchor, &secondary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    let m = rebuild(&mut conn, fixture.path()).expect("rebuild succeeds");
    assert_eq!(m.events_count, 2);
    assert_eq!(m.tampering_count, 0);

    let frozen = read_topo(&conn, KEY_CHAIN_FROZEN_AT_TOPO).expect("read meta");
    assert_eq!(frozen, Some(2));
}

#[test]
fn reanchor_with_inconsistent_cache_freezes_chain() {
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();
    let secondary = new_keypair(fixture.path(), "secondary");
    let (_added_event, after_added) =
        append_secondary_key(&fixture, &primary, bootstrap_event, &secondary);

    // `config.toml` correctly pins the new bootstrap, but the
    // `.bootstrap-fingerprint` cache file is stale. Condition 2 requires
    // BOTH pinned files to agree; the verifier must refuse to authorize a
    // chain break while the doctor flow has not reconciled them.
    fixture.write_pin(&secondary.fingerprint, &secondary.public_openssh);
    std::fs::write(
        fixture.home().join(".bootstrap-fingerprint"),
        "SHA256:stale-cache\n",
    )
    .expect("overwrite cache");

    let reanchor_event = Uuid::now_v7();
    let with_reanchor = format!(
        "{after_added}  - event_id: {ev}\n    kind: BootstrapReanchor\n    old_fingerprint: \"{old}\"\n    new_fingerprint: \"{new}\"\n    reason: \"Bootstrap key lost\"\n",
        ev = reanchor_event,
        old = primary.fingerprint,
        new = secondary.fingerprint,
    );
    commit_events_yml(fixture.path(), &with_reanchor, &secondary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    let m = rebuild(&mut conn, fixture.path()).expect("rebuild succeeds");
    assert_eq!(m.events_count, 2);
    assert_eq!(m.tampering_count, 0);

    let frozen = read_topo(&conn, KEY_CHAIN_FROZEN_AT_TOPO).expect("read meta");
    assert_eq!(frozen, Some(2));
}
