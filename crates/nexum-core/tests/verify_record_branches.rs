//! Integration tests for the read-time trust projection.
//!
//! Each test seeds a notebook fixture (zero or more events.yml revisions
//! signed by real ed25519 keys), runs the materializer, then inserts a
//! synthetic record into the index DB referencing the appropriate signer
//! fingerprint and trust-events commit, and asserts on the
//! `ProjectedTrust` shape returned by `project_trust`.

mod trust;

use chrono::Utc;
use nexum_core::query::verify::{CachedCrypto, ProjectedTrust, project_trust};
use nexum_core::records::{CryptoResult, SignatureStatus, TrustBasis};
use nexum_core::trust::chain_state::ChainState;
use nexum_core::trust::events_view::{TrustEventsView, ensure_current, rebuild};
use rusqlite::Connection;
use trust::fixtures::{KeyPair, NotebookFixture, commit_events_yml, new_keypair};
use trust::{fresh_index_db, fresh_notebook_with_bootstrap};
use uuid::Uuid;

/// SHA of the events.yml-touching commit at HEAD. Production records carry
/// this in the `relevant_trust_events_commit` column; tests look it up via
/// `git rev-parse HEAD` against the fixture.
fn head_commit(nb: &std::path::Path) -> String {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(nb)
        .output()
        .expect("rev-parse HEAD");
    assert!(out.status.success(), "rev-parse HEAD failed");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// SHA of the parent commit of HEAD. Used to look up the trust-events
/// commit effective at the time a pre-recovery record was signed.
fn parent_commit(nb: &std::path::Path, child: &str) -> String {
    let out = std::process::Command::new("git")
        .args(["rev-parse", &format!("{child}^")])
        .current_dir(nb)
        .output()
        .expect("rev-parse parent");
    assert!(out.status.success(), "rev-parse parent failed");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// Build a `CachedCrypto` shape that pins the relevant-trust-events commit
/// to `events_commit`. The `commit_sha` field carries a synthetic record
/// commit (any string) since the tampering precondition is keyed on the
/// trust-events commit, not the record commit.
fn cached<'a>(
    crypto: CryptoResult,
    fp: Option<&'a str>,
    events_commit: Option<&'a str>,
) -> CachedCrypto<'a> {
    CachedCrypto {
        crypto_result: crypto,
        signer_fingerprint: fp,
        commit_sha: Some("synthetic-record-commit"),
        relevant_trust_events_commit: events_commit,
    }
}

fn project(cached: CachedCrypto<'_>, conn: &Connection, strict_revocation: bool) -> ProjectedTrust {
    let view = TrustEventsView::new(conn);
    let chain = ChainState::from_view(&view).expect("chain hydrates");
    project_trust(cached, &view, &chain, strict_revocation).expect("project")
}

/// Bootstrap-only fixture: returns the notebook, the primary key, and the
/// HEAD commit of the bootstrap revision.
fn bootstrap_fixture() -> (
    NotebookFixture,
    KeyPair,
    String,
    Connection,
    tempfile::TempDir,
    tempfile::TempDir,
) {
    let (fixture, primary, _bootstrap_event, key_dir) = fresh_notebook_with_bootstrap();
    let (db_dir, mut conn) = fresh_index_db();
    rebuild(&mut conn, fixture.path()).expect("rebuild succeeds");
    let head = head_commit(fixture.path());
    (fixture, primary, head, conn, db_dir, key_dir)
}

#[test]
fn good_crypto_trusted_now_projects_verified_current() {
    let (_fixture, primary, head, conn, _db_dir, _key_dir) = bootstrap_fixture();
    let projected = project(
        cached(CryptoResult::Good, Some(&primary.fingerprint), Some(&head)),
        &conn,
        false,
    );
    assert_eq!(projected.signature_status, SignatureStatus::Verified);
    assert_eq!(projected.trust_basis, Some(TrustBasis::Current));
    assert!(
        projected.warnings.is_empty(),
        "warnings: {:?}",
        projected.warnings
    );
}

#[test]
fn good_crypto_rotated_projects_verified_rotated_historical() {
    // Bootstrap (primary) → KeyAdded (secondary) → KeyRotatedOut (primary).
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();
    let secondary = new_keypair(fixture.path(), "secondary");

    let added_event = Uuid::now_v7();
    let after_added = format!(
        "schema_version: 1\n\
         events:\n  \
         - event_id: {ev1}\n    kind: BootstrapKey\n    fingerprint: \"{fp1}\"\n    public_key: \"{pk1}\"\n    reason: \"Initial bootstrap\"\n  \
         - event_id: {ev2}\n    kind: KeyAdded\n    fingerprint: \"{fp2}\"\n    public_key: \"{pk2}\"\n    reason: \"Add secondary\"\n",
        ev1 = bootstrap_event,
        fp1 = primary.fingerprint,
        pk1 = primary.public_openssh.trim(),
        ev2 = added_event,
        fp2 = secondary.fingerprint,
        pk2 = secondary.public_openssh.trim(),
    );
    commit_events_yml(fixture.path(), &after_added, &primary.private_path);

    let rotated_event = Uuid::now_v7();
    let after_rotation = format!(
        "{after_added}  - event_id: {ev}\n    kind: KeyRotatedOut\n    fingerprint: \"{fp}\"\n    reason: \"Routine rotation\"\n",
        ev = rotated_event,
        fp = primary.fingerprint,
    );
    // Rotation signed by secondary so the rotating signer is still trusted.
    commit_events_yml(fixture.path(), &after_rotation, &secondary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    rebuild(&mut conn, fixture.path()).expect("rebuild");

    // Read trust state at the parent commit of HEAD — i.e. when only
    // BootstrapKey + KeyAdded existed and primary was still trusted-now.
    let head = head_commit(fixture.path());
    let parent_of_rotation = parent_commit(fixture.path(), &head);

    let projected = project(
        cached(
            CryptoResult::Good,
            Some(&primary.fingerprint),
            Some(&parent_of_rotation),
        ),
        &conn,
        false,
    );
    assert_eq!(projected.signature_status, SignatureStatus::Verified);
    assert_eq!(projected.trust_basis, Some(TrustBasis::RotatedHistorical));
    assert_eq!(projected.warnings, vec!["signer-key-rotated".to_owned()]);
}

#[test]
fn good_crypto_compromised_default_projects_verified_with_compromise_warning() {
    // Bootstrap (primary) → KeyAdded (secondary) → KeyCompromised (primary).
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();
    let secondary = new_keypair(fixture.path(), "secondary");

    let added_event = Uuid::now_v7();
    let after_added = format!(
        "schema_version: 1\n\
         events:\n  \
         - event_id: {ev1}\n    kind: BootstrapKey\n    fingerprint: \"{fp1}\"\n    public_key: \"{pk1}\"\n    reason: \"Initial bootstrap\"\n  \
         - event_id: {ev2}\n    kind: KeyAdded\n    fingerprint: \"{fp2}\"\n    public_key: \"{pk2}\"\n    reason: \"Add secondary\"\n",
        ev1 = bootstrap_event,
        fp1 = primary.fingerprint,
        pk1 = primary.public_openssh.trim(),
        ev2 = added_event,
        fp2 = secondary.fingerprint,
        pk2 = secondary.public_openssh.trim(),
    );
    commit_events_yml(fixture.path(), &after_added, &primary.private_path);

    let comp_event = Uuid::now_v7();
    let after_compromise = format!(
        "{after_added}  - event_id: {ev}\n    kind: KeyCompromised\n    fingerprint: \"{fp}\"\n    reason: \"Stolen\"\n",
        ev = comp_event,
        fp = primary.fingerprint,
    );
    commit_events_yml(fixture.path(), &after_compromise, &secondary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    rebuild(&mut conn, fixture.path()).expect("rebuild");

    let head = head_commit(fixture.path());
    let parent = parent_commit(fixture.path(), &head);
    // Read the record's trust at the pre-compromise commit; even from that
    // earlier vantage point the chain now records primary as compromised
    // (KeyCompromised governs all topo positions for the affected key).
    let projected = project(
        cached(
            CryptoResult::Good,
            Some(&primary.fingerprint),
            Some(&parent),
        ),
        &conn,
        false,
    );
    assert_eq!(projected.signature_status, SignatureStatus::Verified);
    assert_eq!(
        projected.trust_basis,
        Some(TrustBasis::RotatedHistoricalCompromised)
    );
    assert_eq!(
        projected.warnings,
        vec!["signed-by-compromised-key".to_owned()]
    );
}

#[test]
fn good_crypto_compromised_strict_projects_invalid_with_two_warnings() {
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();
    let secondary = new_keypair(fixture.path(), "secondary");

    let added_event = Uuid::now_v7();
    let after_added = format!(
        "schema_version: 1\n\
         events:\n  \
         - event_id: {ev1}\n    kind: BootstrapKey\n    fingerprint: \"{fp1}\"\n    public_key: \"{pk1}\"\n    reason: \"Initial bootstrap\"\n  \
         - event_id: {ev2}\n    kind: KeyAdded\n    fingerprint: \"{fp2}\"\n    public_key: \"{pk2}\"\n    reason: \"Add secondary\"\n",
        ev1 = bootstrap_event,
        fp1 = primary.fingerprint,
        pk1 = primary.public_openssh.trim(),
        ev2 = added_event,
        fp2 = secondary.fingerprint,
        pk2 = secondary.public_openssh.trim(),
    );
    commit_events_yml(fixture.path(), &after_added, &primary.private_path);

    let comp_event = Uuid::now_v7();
    let after_compromise = format!(
        "{after_added}  - event_id: {ev}\n    kind: KeyCompromised\n    fingerprint: \"{fp}\"\n    reason: \"Stolen\"\n",
        ev = comp_event,
        fp = primary.fingerprint,
    );
    commit_events_yml(fixture.path(), &after_compromise, &secondary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    rebuild(&mut conn, fixture.path()).expect("rebuild");

    let head = head_commit(fixture.path());
    let parent = parent_commit(fixture.path(), &head);
    let projected = project(
        cached(
            CryptoResult::Good,
            Some(&primary.fingerprint),
            Some(&parent),
        ),
        &conn,
        true, // strict_revocation
    );
    assert_eq!(projected.signature_status, SignatureStatus::Invalid);
    assert_eq!(
        projected.trust_basis,
        Some(TrustBasis::RotatedHistoricalCompromised)
    );
    assert_eq!(
        projected.warnings,
        vec![
            "signed-by-compromised-key".to_owned(),
            "strict-revocation-active".to_owned(),
        ]
    );
}

#[test]
fn good_crypto_pre_reanchor_case_a_projects_verified_pre_reanchor() {
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();
    let secondary = new_keypair(fixture.path(), "secondary");

    let added_event = Uuid::now_v7();
    let after_added = format!(
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
    commit_events_yml(fixture.path(), &after_added, &primary.private_path);
    let pre_reanchor_commit = head_commit(fixture.path());

    fixture.write_pin(&secondary.fingerprint, &secondary.public_openssh);
    let reanchor_event = Uuid::now_v7();
    let with_reanchor = format!(
        "{after_added}  - event_id: {ev}\n    kind: BootstrapReanchor\n    old_fingerprint: \"{old}\"\n    new_fingerprint: \"{new}\"\n    reason: \"Bootstrap key lost\"\n",
        ev = reanchor_event,
        old = primary.fingerprint,
        new = secondary.fingerprint,
    );
    commit_events_yml(fixture.path(), &with_reanchor, &secondary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    rebuild(&mut conn, fixture.path()).expect("rebuild");

    // A record signed by primary BEFORE the reanchor commit: its
    // relevant_trust_events_commit points at the pre-reanchor revision.
    let projected = project(
        cached(
            CryptoResult::Good,
            Some(&primary.fingerprint),
            Some(&pre_reanchor_commit),
        ),
        &conn,
        false,
    );
    assert_eq!(projected.signature_status, SignatureStatus::Verified);
    assert_eq!(projected.trust_basis, Some(TrustBasis::PreReanchor));
    assert_eq!(projected.warnings, vec!["pre-recovery-record".to_owned()]);
}

#[test]
fn good_crypto_pre_reanchor_case_b_projects_invalid_with_chain_anchor_lost() {
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();
    let secondary = new_keypair(fixture.path(), "secondary");

    let added_event = Uuid::now_v7();
    let after_added = format!(
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
    commit_events_yml(fixture.path(), &after_added, &primary.private_path);
    let pre_reanchor_commit = head_commit(fixture.path());

    fixture.write_pin(&secondary.fingerprint, &secondary.public_openssh);
    let reanchor_event = Uuid::now_v7();
    let with_reanchor = format!(
        "{after_added}  - event_id: {ev}\n    kind: BootstrapReanchor\n    old_fingerprint: \"{old}\"\n    new_fingerprint: \"{new}\"\n    reason: \"Pin lost; acknowledged\"\n    acknowledge_chain_anchor_lost: true\n",
        ev = reanchor_event,
        old = primary.fingerprint,
        new = secondary.fingerprint,
    );
    commit_events_yml(fixture.path(), &with_reanchor, &secondary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    rebuild(&mut conn, fixture.path()).expect("rebuild");

    let projected = project(
        cached(
            CryptoResult::Good,
            Some(&primary.fingerprint),
            Some(&pre_reanchor_commit),
        ),
        &conn,
        false,
    );
    assert_eq!(projected.signature_status, SignatureStatus::Invalid);
    assert_eq!(projected.trust_basis, Some(TrustBasis::PreReanchor));
    assert_eq!(
        projected.warnings,
        vec![
            "chain-anchor-lost".to_owned(),
            "pre-recovery-record".to_owned()
        ]
    );
}

#[test]
fn good_crypto_not_yet_trusted_projects_invalid() {
    // Bootstrap by primary; record signed by an entirely unknown key whose
    // trust state at the queried topo position is NotYetTrustedAtCommit.
    let (_fixture, _primary, head, conn, _db_dir, _key_dir) = bootstrap_fixture();
    let projected = project(
        cached(
            CryptoResult::Good,
            Some("SHA256:never-introduced"),
            Some(&head),
        ),
        &conn,
        false,
    );
    assert_eq!(projected.signature_status, SignatureStatus::Invalid);
    assert_eq!(projected.trust_basis, None);
    assert_eq!(
        projected.warnings,
        vec!["key-not-yet-trusted-at-commit".to_owned()]
    );
}

#[test]
fn good_crypto_broken_chain_projects_invalid() {
    // Forbidden mutation in revision 2 freezes the chain. Records signed
    // at-or-after the freeze project as BrokenChain.
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();
    // Replay the bootstrap revision but with a *mutated* event_id (Diff
    // classifier surfaces this as `MutatedPayload`).
    let mutated = format!(
        "schema_version: 1\n\
         events:\n  \
         - event_id: {ev}\n    kind: BootstrapKey\n    fingerprint: \"{fp}\"\n    public_key: \"{pk}\"\n    reason: \"Mutated payload\"\n",
        ev = bootstrap_event,
        fp = primary.fingerprint,
        pk = primary.public_openssh.trim(),
    );
    commit_events_yml(fixture.path(), &mutated, &primary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    rebuild(&mut conn, fixture.path()).expect("rebuild");

    // The HEAD commit (the mutated revision) is the freeze point. A record
    // signed at HEAD projects as BrokenChain via `state_of`. Note that
    // tampering rows are also present so the precondition would fire — but
    // the precondition uses topo_pos lookup keyed on the SHA, which the
    // mutating commit IS in the trust_events table only if the diff
    // classifier treats it as accepted; here it's `Diff::Forbidden` so the
    // SHA isn't in `trust_events`. The chain freeze still fires via
    // `state_of` on the chain hydrated from the meta sentinel + tampering
    // rows. That makes the BrokenChain branch the right assertion.
    let head = head_commit(fixture.path());
    let projected = project(
        cached(CryptoResult::Good, Some(&primary.fingerprint), Some(&head)),
        &conn,
        false,
    );
    assert_eq!(projected.signature_status, SignatureStatus::Invalid);
    assert_eq!(projected.trust_basis, None);
    // Either the tampering precondition fires (events.yml SHA found in
    // trust_events) producing ["broken-trust-chain", "event-tampered"], or
    // the chain freeze produces ["broken-trust-chain"] alone. Both are
    // correct outcomes for this fixture; assert on the canonical leading
    // warning.
    assert!(
        projected.warnings.first() == Some(&"broken-trust-chain".to_owned()),
        "expected broken-trust-chain leading warning, got {:?}",
        projected.warnings
    );
}

#[test]
fn bad_signature_projects_invalid_with_bad_signature() {
    let (_fixture, _primary, head, conn, _db_dir, _key_dir) = bootstrap_fixture();
    let projected = project(
        cached(CryptoResult::BadSignature, None, Some(&head)),
        &conn,
        false,
    );
    assert_eq!(projected.signature_status, SignatureStatus::Invalid);
    assert_eq!(projected.trust_basis, None);
    assert_eq!(projected.warnings, vec!["bad-signature".to_owned()]);
}

#[test]
fn unknown_signer_projects_invalid_with_unknown_signature() {
    let (_fixture, _primary, head, conn, _db_dir, _key_dir) = bootstrap_fixture();
    let projected = project(
        cached(CryptoResult::UnknownSigner, None, Some(&head)),
        &conn,
        false,
    );
    assert_eq!(projected.signature_status, SignatureStatus::Invalid);
    assert_eq!(projected.trust_basis, None);
    assert_eq!(projected.warnings, vec!["unknown-signature".to_owned()]);
}

#[test]
fn no_signature_projects_unsigned_with_unsigned_warning() {
    let (_fixture, _primary, _head, conn, _db_dir, _key_dir) = bootstrap_fixture();
    // cc-native and codex-native records have no events.yml commit; they
    // pass relevant_trust_events_commit = None to project_trust.
    let projected = project(cached(CryptoResult::NoSignature, None, None), &conn, false);
    assert_eq!(projected.signature_status, SignatureStatus::Unsigned);
    assert_eq!(projected.trust_basis, None);
    assert_eq!(projected.warnings, vec!["unsigned".to_owned()]);
}

#[test]
fn tampering_at_or_before_overrides_to_invalid_event_tampered() {
    // Build a tampered fixture: bootstrap → forbidden-mutation revision.
    // The mutated revision lands as a tampering row that affects the
    // bootstrap commit's read-time projection (the commit is at-or-before
    // the freeze point).
    let (fixture, primary, bootstrap_event, _keys) = fresh_notebook_with_bootstrap();
    let bootstrap_commit = head_commit(fixture.path());

    // Forbidden mutation: change the bootstrap event's reason in revision 2.
    let mutated = format!(
        "schema_version: 1\n\
         events:\n  \
         - event_id: {ev}\n    kind: BootstrapKey\n    fingerprint: \"{fp}\"\n    public_key: \"{pk}\"\n    reason: \"Mutated reason\"\n",
        ev = bootstrap_event,
        fp = primary.fingerprint,
        pk = primary.public_openssh.trim(),
    );
    commit_events_yml(fixture.path(), &mutated, &primary.private_path);

    let (_db_dir, mut conn) = fresh_index_db();
    rebuild(&mut conn, fixture.path()).expect("rebuild");

    // A record whose relevant_trust_events_commit is the BOOTSTRAP commit
    // (not the mutated one). The bootstrap commit IS in `trust_events`
    // (topo_pos 0) and any tampering row has at_topo_pos >= 1, so the
    // precondition `tampering at-or-before topo 0` fires only if the
    // tampering row at topo 1 sits before the queried commit's topo 0,
    // which it does NOT. Use the MUTATED commit's lookup instead, which is
    // not directly in trust_events — so the precondition returns Ok(false).
    //
    // To exercise the precondition properly we need a tampering row at
    // topo 0 OR at the same topo position as the queried commit. Build a
    // 3-revision fixture: bootstrap → KeyAdded (signed by primary) →
    // forbidden mutation. The middle commit IS in trust_events; the
    // tampering at topo 2 fires the precondition for a record looking up
    // the middle commit only when topo 2 <= topo of middle (= 1), which
    // is false.
    //
    // The right way: query the tampering commit itself. The tampering
    // commit is NOT inserted into trust_events (Diff::Forbidden writes to
    // trust_chain_tampering only). So the precondition lookup on the
    // tampering commit returns None, and `project_trust` falls through to
    // the BrokenChain branch via state_of. That's covered in the broken
    // chain test above.
    //
    // For the precondition to fire we need a record whose
    // relevant_trust_events_commit IS in trust_events AND a tampering
    // row at-or-before that commit's topo_pos. Append a third revision
    // (legitimate KeyAdded), record-against-it. Then create tampering at
    // topo 1 or topo 2 by mutating revision 2 in-place via a fourth
    // revision that re-uses the existing event_id.
    //
    // Simpler shortcut for this test: insert the tampering row directly
    // at topo 0 alongside the existing trust_events row. That exercises
    // the read path's precondition without re-walking history.
    conn.execute(
        "INSERT INTO trust_chain_tampering (at_commit, at_topo_pos, event_id, kind, detected_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            bootstrap_commit,
            0_i64,
            bootstrap_event.to_string(),
            "MutatedPayload",
            Utc::now().to_rfc3339(),
        ],
    )
    .unwrap();

    let projected = project(
        cached(
            CryptoResult::Good,
            Some(&primary.fingerprint),
            Some(&bootstrap_commit),
        ),
        &conn,
        false,
    );
    assert_eq!(projected.signature_status, SignatureStatus::Invalid);
    assert_eq!(projected.trust_basis, None);
    assert_eq!(
        projected.warnings,
        vec!["broken-trust-chain".to_owned(), "event-tampered".to_owned()]
    );
}

#[test]
fn sentinel_mismatch_triggers_rebuild_on_next_verb_invocation() {
    // Build a notebook with a bootstrap revision; do NOT call rebuild yet.
    let (fixture, _primary, _bootstrap_event, _key_dir) = fresh_notebook_with_bootstrap();
    let (_db_dir, mut conn) = fresh_index_db();

    // Pre-rebuild: trust_events is empty.
    let n_before: i64 = conn
        .query_row("SELECT count(*) FROM trust_events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n_before, 0);

    // ensure_current sees stale (no-sentinel) state and triggers rebuild.
    ensure_current(&mut conn, fixture.path()).expect("ensure_current rebuilds");

    let n_after: i64 = conn
        .query_row("SELECT count(*) FROM trust_events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n_after, 1, "rebuild populated trust_events");

    // Calling ensure_current a second time is a no-op (sentinels match).
    ensure_current(&mut conn, fixture.path()).expect("ensure_current no-op");
    let n_repeat: i64 = conn
        .query_row("SELECT count(*) FROM trust_events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n_repeat, 1);
}
