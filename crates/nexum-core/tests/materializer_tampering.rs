//! Integration tests covering the materializer's append-only invariant
//! detection: reorder, delete, payload-mutate, duplicate `event_id`. Each
//! test builds a synthetic notebook.git via the trust fixture builder and
//! runs `rebuild` against a freshly-created index database. The bootstrap
//! commit is signed by the primary key in every fixture; the second
//! revision is what carries the tampering.
//!
//! The materializer compares deserialized [`EventLog`]s, so YAML formatting
//! differences (trailing whitespace, comments) collapse on the structural
//! side and surface as `Diff::NoOp` — the whitespace-only test below.

mod trust;

use nexum_core::trust::events_view::{TrustEventsView, rebuild};
use trust::fixtures::{KeyPair, NotebookFixture, commit_events_yml, new_keypair};
use trust::{fresh_index_db, fresh_notebook_with_bootstrap};
use uuid::Uuid;

/// Append-with-bootstrap-plus-secondary-key helper. Used by tests that need
/// a second event in the prior revision before they can mutate / reorder
/// it. Returns the full event log so tests can mutate the slice and pass
/// it back through `commit_events_yml`. The `(added_event_id,
/// secondary_key)` tuple lets the caller reference both.
fn append_secondary(
    fixture: &NotebookFixture,
    primary: &KeyPair,
    bootstrap_event: Uuid,
) -> (Uuid, KeyPair, String) {
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
    (added_event, secondary, yaml)
}

#[test]
fn reorder_in_second_revision_writes_tampering_row() {
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();
    let (added_event, secondary, _) = append_secondary(&fixture, &primary, bootstrap_event);

    // Third revision: swap the order of the two existing events. This is a
    // ReorderedDeleted forbidden mutation — both event_ids exist in `prev`
    // but the leading slot now holds a different one.
    let reordered = format!(
        "schema_version: 1\n\
         events:\n  \
         - event_id: {ev2}\n    kind: KeyAdded\n    fingerprint: \"{fp2}\"\n    public_key: \"{pk2}\"\n    reason: \"Add secondary signer\"\n  \
         - event_id: {ev1}\n    kind: BootstrapKey\n    fingerprint: \"{fp1}\"\n    public_key: \"{pk1}\"\n    reason: \"Initial bootstrap\"\n",
        ev1 = bootstrap_event,
        fp1 = primary.fingerprint,
        pk1 = primary.public_openssh.trim(),
        ev2 = added_event,
        fp2 = secondary.fingerprint,
        pk2 = secondary.public_openssh.trim(),
    );
    commit_events_yml(fixture.path(), &reordered, &primary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    let m = rebuild(&mut conn, fixture.path()).expect("rebuild succeeds");
    assert_eq!(m.events_count, 2, "bootstrap + KeyAdded → 2 rows");
    assert_eq!(m.tampering_count, 1);

    let (kind, event_id): (String, String) = conn
        .query_row(
            "SELECT kind, event_id FROM trust_chain_tampering",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(kind, "ReorderedDeleted");
    // The first slot's event_id flipped from bootstrap → added; the
    // classifier reports the prev-revision event that was displaced.
    assert_eq!(event_id, bootstrap_event.to_string());
}

#[test]
fn delete_in_second_revision_writes_tampering_row() {
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();
    let (added_event, _secondary, _) = append_secondary(&fixture, &primary, bootstrap_event);

    // Third revision: drop the KeyAdded event. The log shrinks; classifier
    // reports the missing event_id as ReorderedDeleted.
    let shrunk = format!(
        "schema_version: 1\nevents:\n  - event_id: {ev}\n    kind: BootstrapKey\n    fingerprint: \"{fp}\"\n    public_key: \"{pk}\"\n    reason: \"Initial bootstrap\"\n",
        ev = bootstrap_event,
        fp = primary.fingerprint,
        pk = primary.public_openssh.trim(),
    );
    commit_events_yml(fixture.path(), &shrunk, &primary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    let m = rebuild(&mut conn, fixture.path()).expect("rebuild succeeds");
    assert_eq!(m.events_count, 2);
    assert_eq!(m.tampering_count, 1);

    let (kind, event_id): (String, String) = conn
        .query_row(
            "SELECT kind, event_id FROM trust_chain_tampering",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(kind, "ReorderedDeleted");
    assert_eq!(event_id, added_event.to_string());
}

#[test]
fn payload_mutation_writes_mutated_payload_row() {
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();

    // Second revision: same event_id as bootstrap but with a different
    // fingerprint payload. Classifier reports MutatedPayload.
    let mutated = format!(
        "schema_version: 1\nevents:\n  - event_id: {ev}\n    kind: BootstrapKey\n    fingerprint: \"SHA256:tampered\"\n    public_key: \"{pk}\"\n    reason: \"Initial bootstrap\"\n",
        ev = bootstrap_event,
        pk = primary.public_openssh.trim(),
    );
    commit_events_yml(fixture.path(), &mutated, &primary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    let m = rebuild(&mut conn, fixture.path()).expect("rebuild succeeds");
    assert_eq!(m.events_count, 1, "bootstrap row only");
    assert_eq!(m.tampering_count, 1);

    let (kind, event_id): (String, String) = conn
        .query_row(
            "SELECT kind, event_id FROM trust_chain_tampering",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(kind, "MutatedPayload");
    assert_eq!(event_id, bootstrap_event.to_string());
}

#[test]
fn duplicate_event_id_writes_duplicate_id_row() {
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();

    // Second revision: append a new event but reuse the bootstrap event_id.
    // Classifier reports DuplicateId.
    let secondary = new_keypair(fixture.path(), "secondary");
    let yaml = format!(
        "schema_version: 1\n\
         events:\n  \
         - event_id: {ev}\n    kind: BootstrapKey\n    fingerprint: \"{fp1}\"\n    public_key: \"{pk1}\"\n    reason: \"Initial bootstrap\"\n  \
         - event_id: {ev}\n    kind: KeyAdded\n    fingerprint: \"{fp2}\"\n    public_key: \"{pk2}\"\n    reason: \"Add secondary signer\"\n",
        ev = bootstrap_event,
        fp1 = primary.fingerprint,
        pk1 = primary.public_openssh.trim(),
        fp2 = secondary.fingerprint,
        pk2 = secondary.public_openssh.trim(),
    );
    commit_events_yml(fixture.path(), &yaml, &primary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    let m = rebuild(&mut conn, fixture.path()).expect("rebuild succeeds");
    assert_eq!(m.events_count, 1, "bootstrap row only");
    assert_eq!(m.tampering_count, 1);

    let (kind, event_id): (String, String) = conn
        .query_row(
            "SELECT kind, event_id FROM trust_chain_tampering",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(kind, "DuplicateId");
    assert_eq!(event_id, bootstrap_event.to_string());
}

#[test]
fn whitespace_only_diff_writes_no_tampering() {
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();

    // Second revision: structurally identical YAML with extra trailing
    // whitespace and a comment. Both deserialize to the same EventLog, so
    // the classifier returns NoOp — no row in trust_chain_tampering.
    let whitespace_only = format!(
        "schema_version: 1\n# Reformatted comment\nevents:\n  - event_id: {ev}\n    kind: BootstrapKey\n    fingerprint: \"{fp}\"\n    public_key: \"{pk}\"\n    reason: \"Initial bootstrap\"\n\n",
        ev = bootstrap_event,
        fp = primary.fingerprint,
        pk = primary.public_openssh.trim(),
    );
    commit_events_yml(fixture.path(), &whitespace_only, &primary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    let m = rebuild(&mut conn, fixture.path()).expect("rebuild succeeds");
    assert_eq!(m.events_count, 1, "only the bootstrap row");
    assert_eq!(
        m.tampering_count, 0,
        "whitespace-only diff is allowed (Diff::NoOp)"
    );

    let count: i64 = conn
        .query_row("SELECT count(*) FROM trust_chain_tampering", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn has_tampering_at_or_before_returns_true_after_detection() {
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();

    // Capture the bootstrap commit SHA before the tampered revision lands.
    let bootstrap_sha = git_head(fixture.path());

    // Second revision: payload-mutate so we have a tampering row at
    // topo_pos = 1.
    let mutated = format!(
        "schema_version: 1\nevents:\n  - event_id: {ev}\n    kind: BootstrapKey\n    fingerprint: \"SHA256:tampered\"\n    public_key: \"{pk}\"\n    reason: \"Initial bootstrap\"\n",
        ev = bootstrap_event,
        pk = primary.public_openssh.trim(),
    );
    commit_events_yml(fixture.path(), &mutated, &primary.private_path);
    let tampered_sha = git_head(fixture.path());

    let (_db_dir, mut conn) = fresh_index_db();
    let m = rebuild(&mut conn, fixture.path()).expect("rebuild succeeds");
    assert_eq!(m.tampering_count, 1);

    let view = TrustEventsView::new(&conn);
    assert!(
        !view.has_tampering_at_or_before(&bootstrap_sha).unwrap(),
        "bootstrap commit precedes the tampering row"
    );
    // The tampered commit isn't in trust_events (the chain froze and no
    // new event row landed). The conservative answer is `false` — the
    // verifier consults this view at read time and only checks commits
    // that are in `trust_events`.
    assert!(
        !view.has_tampering_at_or_before(&tampered_sha).unwrap(),
        "tampered commit is not in trust_events; precondition is N/A"
    );
}

/// Read the current `HEAD` SHA from the notebook git working tree.
fn git_head(notebook_git: &std::path::Path) -> String {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(notebook_git)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("HOME", notebook_git)
        .env("XDG_CONFIG_HOME", notebook_git.join(".config"))
        .output()
        .expect("git rev-parse HEAD spawn");
    assert!(out.status.success(), "git rev-parse HEAD non-zero");
    String::from_utf8(out.stdout)
        .expect("HEAD sha is valid utf-8")
        .trim()
        .to_owned()
}
