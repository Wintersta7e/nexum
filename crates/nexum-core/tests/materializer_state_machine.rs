//! Integration tests covering the materializer's full state-machine
//! handling: `KeyAdded` / `KeyRotatedOut` / `KeyCompromised` events plus an
//! unauthorized-append tampering case. Each test builds a synthetic
//! notebook.git via the trust fixture builder and runs `rebuild` against a
//! freshly-created index database.

mod trust;

use nexum_core::trust::events_view::rebuild;
use trust::fixtures::{commit_events_yml, new_keypair};
use trust::{fresh_index_db, fresh_notebook_with_bootstrap};
use uuid::Uuid;

#[test]
fn bootstrap_plus_key_added_writes_two_trust_events_rows() {
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();

    let secondary = new_keypair(fixture.path(), "secondary");
    let added_event = Uuid::now_v7();
    let yaml = format!(
        "schema_version: 1\n\
         events:\n  \
         - event_id: {ev1}\n    kind: BootstrapKey\n    fingerprint: \"{fp1}\"\n    public_key: \"{pk1}\"\n    reason: \"Initial bootstrap\"\n  \
         - event_id: {ev2}\n    kind: KeyAdded\n    fingerprint: \"{fp2}\"\n    public_key: \"{pk2}\"\n    reason: \"Add secondary signer\"\n",
        ev1 = bootstrap_event,
        fp1 = primary.fingerprint,
        pk1 = primary.public_openssh.trim(),
        ev2 = added_event,
        fp2 = secondary.fingerprint,
        pk2 = secondary.public_openssh.trim(),
    );
    commit_events_yml(fixture.path(), &yaml, &primary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    let m = rebuild(&mut conn, fixture.path()).expect("rebuild succeeds");
    assert_eq!(m.events_count, 2, "bootstrap + KeyAdded → 2 rows");
    assert_eq!(m.tampering_count, 0);

    let validated_by: Option<String> = conn
        .query_row(
            "SELECT chain_validated_by FROM trust_events WHERE kind = 'KeyAdded'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        validated_by.as_deref(),
        Some(bootstrap_event.to_string().as_str()),
        "KeyAdded.chain_validated_by points at the bootstrap event_id"
    );
}

#[test]
fn key_rotated_out_writes_three_rows_and_marks_no_tampering() {
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();

    let secondary = new_keypair(fixture.path(), "secondary");
    let added_event = Uuid::now_v7();
    let rotated_event = Uuid::now_v7();
    let after_added = format!(
        "schema_version: 1\n\
         events:\n  \
         - event_id: {ev1}\n    kind: BootstrapKey\n    fingerprint: \"{fp1}\"\n    public_key: \"{pk1}\"\n    reason: \"Initial bootstrap\"\n  \
         - event_id: {ev2}\n    kind: KeyAdded\n    fingerprint: \"{fp2}\"\n    public_key: \"{pk2}\"\n    reason: \"Add secondary signer\"\n",
        ev1 = bootstrap_event,
        fp1 = primary.fingerprint,
        pk1 = primary.public_openssh.trim(),
        ev2 = added_event,
        fp2 = secondary.fingerprint,
        pk2 = secondary.public_openssh.trim(),
    );
    commit_events_yml(fixture.path(), &after_added, &primary.private_path);

    let after_rotation = format!(
        "{after_added}  - event_id: {ev3}\n    kind: KeyRotatedOut\n    fingerprint: \"{fp1}\"\n    reason: \"Routine rotation\"\n",
        ev3 = rotated_event,
        fp1 = primary.fingerprint,
    );
    // Rotation is signed by the secondary (still trusted, primary is not
    // yet rotated at the parent topo position).
    commit_events_yml(fixture.path(), &after_rotation, &secondary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    let m = rebuild(&mut conn, fixture.path()).expect("rebuild succeeds");
    assert_eq!(m.events_count, 3);
    assert_eq!(m.tampering_count, 0);

    let kinds: Vec<String> = conn
        .prepare("SELECT kind FROM trust_events ORDER BY effective_commit_topo_pos")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(kinds, ["BootstrapKey", "KeyAdded", "KeyRotatedOut"]);
}

#[test]
fn key_compromised_writes_compromised_row() {
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();

    let secondary = new_keypair(fixture.path(), "secondary");
    let added_event = Uuid::now_v7();
    let compromised_event = Uuid::now_v7();
    let after_added = format!(
        "schema_version: 1\n\
         events:\n  \
         - event_id: {ev1}\n    kind: BootstrapKey\n    fingerprint: \"{fp1}\"\n    public_key: \"{pk1}\"\n    reason: \"Initial bootstrap\"\n  \
         - event_id: {ev2}\n    kind: KeyAdded\n    fingerprint: \"{fp2}\"\n    public_key: \"{pk2}\"\n    reason: \"Add secondary signer\"\n",
        ev1 = bootstrap_event,
        fp1 = primary.fingerprint,
        pk1 = primary.public_openssh.trim(),
        ev2 = added_event,
        fp2 = secondary.fingerprint,
        pk2 = secondary.public_openssh.trim(),
    );
    commit_events_yml(fixture.path(), &after_added, &primary.private_path);

    let after_compromise = format!(
        "{after_added}  - event_id: {ev3}\n    kind: KeyCompromised\n    fingerprint: \"{fp1}\"\n    reason: \"Lost laptop\"\n",
        ev3 = compromised_event,
        fp1 = primary.fingerprint,
    );
    // Same reasoning: secondary is trusted at parent topo (1), primary has
    // not yet been compromised there.
    commit_events_yml(fixture.path(), &after_compromise, &secondary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    let m = rebuild(&mut conn, fixture.path()).expect("rebuild succeeds");
    assert_eq!(m.events_count, 3);
    assert_eq!(m.tampering_count, 0);

    let count: i64 = conn
        .query_row(
            "SELECT count(*) FROM trust_events WHERE kind = 'KeyCompromised'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn append_signed_by_untrusted_key_writes_tampering_row() {
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();

    // A freshly-generated key that has never been added to the trust set.
    // The repo's allowed_signers/historical_signers do not list it, but the
    // materializer reads only events.yml — the rejection happens because
    // ChainState does not contain the signer.
    let interloper = new_keypair(fixture.path(), "interloper");
    // Pre-trust the interloper's key in git's signer files so git itself
    // accepts the signature locally; the materializer is what catches the
    // chain-of-trust violation.
    let nb = fixture.path();
    let allowed = std::fs::read_to_string(nb.join(".trust/allowed_signers")).unwrap();
    let allowed = format!("{allowed}* {pk}\n", pk = interloper.public_openssh.trim());
    std::fs::write(nb.join(".trust/allowed_signers"), allowed).unwrap();

    let rogue_event = Uuid::now_v7();
    let yaml = format!(
        "schema_version: 1\n\
         events:\n  \
         - event_id: {ev1}\n    kind: BootstrapKey\n    fingerprint: \"{fp1}\"\n    public_key: \"{pk1}\"\n    reason: \"Initial bootstrap\"\n  \
         - event_id: {ev2}\n    kind: KeyAdded\n    fingerprint: \"{fp2}\"\n    public_key: \"{pk2}\"\n    reason: \"Backdoor\"\n",
        ev1 = bootstrap_event,
        fp1 = primary.fingerprint,
        pk1 = primary.public_openssh.trim(),
        ev2 = rogue_event,
        fp2 = interloper.fingerprint,
        pk2 = interloper.public_openssh.trim(),
    );
    // Sign with the interloper key — it's not in ChainState at parent
    // topo_pos, so the materializer must reject the append.
    commit_events_yml(nb, &yaml, &interloper.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    let m = rebuild(&mut conn, fixture.path()).expect("rebuild succeeds");
    assert_eq!(m.events_count, 1, "only the bootstrap row is appended");
    assert_eq!(m.tampering_count, 1);

    let (kind, event_id): (String, String) = conn
        .query_row(
            "SELECT kind, event_id FROM trust_chain_tampering",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(kind, "ReorderedDeleted");
    assert_eq!(event_id, rogue_event.to_string());
}
