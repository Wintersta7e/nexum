//! Project the `trust_events` materialized view into a per-key role
//! summary suitable for `nexum keys list` output and for
//! `nexum keys revoke` preflight #7 (signer-is-Active).
//!
//! Read-only. Does NOT call `events_view::ensure_current` — callers
//! that need fresh state must run `ensure_current` before invoking
//! `project()`.

use rusqlite::Connection;

use super::events::{EventKindTag, TrustError};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KeyStateView {
    pub fingerprint: String,
    pub public_key: String,
    pub role: KeyRole,
    pub introduced_event_id: String,
    pub introduced_commit: String,
    pub retired_event_id: Option<String>,
    pub retired_commit: Option<String>,
    pub introduced_reason: String,
    pub retired_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyRole {
    Active,
    Rotated,
    Compromised,
    Reanchored,
}

/// Project the `trust_events` rows currently in `conn` into the per-key
/// role summary.
///
/// # Errors
///
/// Returns `TrustError::Sqlite` if the SQL prepare, row iteration, or
/// column read fails.
// Single pass over the materialized view, then a second pass to apply
// retirements onto introducer rows. Splitting the two phases into
// separate helpers would not simplify either side and would force the
// retirement tuple to grow into a named type for the boundary.
#[allow(clippy::too_many_lines)]
pub fn project(conn: &Connection) -> Result<Vec<KeyStateView>, TrustError> {
    let mut stmt = conn.prepare(
        "SELECT event_id, kind, fingerprint, old_fingerprint, new_fingerprint,
                public_key, effective_commit, effective_commit_topo_pos, reason
         FROM trust_events
         ORDER BY effective_commit_topo_pos ASC",
    )?;

    let mut rows = stmt.query([])?;

    // Use a Vec maintained in SQL-query order (ORDER BY topo_pos ASC).
    // A BTreeMap keyed on topo_pos would silently clobber rows for degenerate
    // hand-crafted test inputs that share a topo_pos; the underlying
    // trust_events PRIMARY KEY is event_id, not topo_pos.
    let mut introducers: Vec<KeyStateView> = Vec::new();
    // (fingerprint, target_role, event_id, commit, reason) for retirement events.
    let mut retirements: Vec<(String, KeyRole, String, String, String)> = Vec::new();
    while let Some(row) = rows.next()? {
        let event_id: String = row.get(0)?;
        let kind: String = row.get(1)?;
        let fingerprint: Option<String> = row.get(2).ok();
        let old_fingerprint: Option<String> = row.get(3).ok();
        let new_fingerprint: Option<String> = row.get(4).ok();
        let public_key: Option<String> = row.get(5).ok();
        let effective_commit: String = row.get(6)?;
        // topo_pos is not read directly — we trust the SQL ORDER BY
        // ASC clause to deliver rows in topological order.
        let reason: Option<String> = row.get(8).ok();

        let Some(tag) = EventKindTag::from_db_str(&kind) else {
            tracing::warn!(
                target: "nexum::trust",
                kind = %kind,
                "trust_events row has unknown kind; skipping",
            );
            continue;
        };
        match tag {
            EventKindTag::BootstrapKey | EventKindTag::KeyAdded => {
                let fp = fingerprint.unwrap_or_default();
                let pk = public_key.unwrap_or_default();
                introducers.push(KeyStateView {
                    fingerprint: fp,
                    public_key: pk,
                    role: KeyRole::Active,
                    introduced_event_id: event_id,
                    introduced_commit: effective_commit,
                    retired_event_id: None,
                    retired_commit: None,
                    introduced_reason: reason.unwrap_or_default(),
                    retired_reason: None,
                });
            }
            EventKindTag::KeyRotatedOut => {
                let fp = fingerprint.unwrap_or_default();
                retirements.push((
                    fp,
                    KeyRole::Rotated,
                    event_id,
                    effective_commit,
                    reason.unwrap_or_default(),
                ));
            }
            EventKindTag::KeyCompromised => {
                let fp = fingerprint.unwrap_or_default();
                retirements.push((
                    fp,
                    KeyRole::Compromised,
                    event_id,
                    effective_commit,
                    reason.unwrap_or_default(),
                ));
            }
            EventKindTag::BootstrapReanchor => {
                // The old key gets Reanchored unless already Compromised
                // (compromise is the more severe terminal classification).
                // The retired_reason is the hard-coded literal pinned by DESIGN;
                // the reanchor event's own `reason` field is operator-supplied
                // prose intended for the chain-break audit, not the per-key
                // retirement record.
                if let Some(old_fp) = old_fingerprint {
                    retirements.push((
                        old_fp,
                        KeyRole::Reanchored,
                        event_id.clone(),
                        effective_commit.clone(),
                        "anchor moved by BootstrapReanchor".to_owned(),
                    ));
                }
                // The new_fingerprint is expected to already be in introducers
                // via a prior KeyAdded; if not, log a warning and skip.
                if let Some(new_fp) = new_fingerprint {
                    let known = introducers.iter().any(|k| k.fingerprint == new_fp);
                    if !known {
                        tracing::warn!(
                            target: "nexum::trust",
                            fingerprint = %new_fp,
                            "BootstrapReanchor.new_fingerprint has no preceding KeyAdded; skipping",
                        );
                    }
                }
                // The reason field is intentionally unused here — see comment above.
                let _ = reason;
            }
        }
    }

    // Apply retirements. Iterate in declaration order so KeyCompromised wins
    // over later KeyRotatedOut and over BootstrapReanchor (compromise is the
    // terminal classification).
    let mut out: Vec<KeyStateView> = introducers;
    for (fp, new_role, ret_event, ret_commit, ret_reason) in retirements {
        let Some(view) = out.iter_mut().find(|v| v.fingerprint == fp) else {
            tracing::warn!(
                target: "nexum::trust",
                fingerprint = %fp,
                role = ?new_role,
                "retirement event references unknown fingerprint; skipping",
            );
            continue;
        };
        // Compromise is terminal. If the key is already Compromised:
        //   - role does NOT change (no downgrade to Rotated/Reanchored).
        //   - retired_* fields stay as the compromise event's audit record
        //     (the compromise is the authoritative retirement; later events
        //     like BootstrapReanchor.old_fingerprint are visible via the
        //     events.yml history but do not overwrite the per-key audit).
        // The `continue` enforces both rules: skip the role swap AND skip
        // the retired_* update.
        if matches!(view.role, KeyRole::Compromised) && new_role != KeyRole::Compromised {
            continue;
        }
        view.role = new_role;
        view.retired_event_id = Some(ret_event);
        view.retired_commit = Some(ret_commit);
        view.retired_reason = Some(ret_reason);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test helper mirrors every column the projection reads from
    // trust_events; an args-struct would add ceremony without making
    // the individual call sites clearer.
    #[allow(clippy::too_many_arguments)]
    fn insert_event(
        conn: &Connection,
        event_id: &str,
        kind: &str,
        topo_pos: i64,
        fp: Option<&str>,
        pk: Option<&str>,
        old_fp: Option<&str>,
        new_fp: Option<&str>,
        reason: Option<&str>,
    ) {
        conn.execute(
            "INSERT INTO trust_events (event_id, kind, fingerprint, old_fingerprint,
                                       new_fingerprint, public_key, effective_commit,
                                       effective_commit_topo_pos, introduced_by_signer,
                                       reason, materialized_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, '2026-05-19T00:00:00Z')",
            rusqlite::params![
                event_id,
                kind,
                fp,
                old_fp,
                new_fp,
                pk,
                format!("commit_{topo_pos}"),
                topo_pos,
                fp.unwrap_or("introducer"),
                reason,
            ],
        )
        .expect("insert");
    }

    #[test]
    fn empty_events_yields_empty_projection() {
        let conn = test_helpers::open_with_trust_events_schema();
        let view = project(&conn).expect("project");
        assert_eq!(view, Vec::<KeyStateView>::new());
    }

    #[test]
    fn bootstrap_only_one_active_row() {
        let conn = test_helpers::open_with_trust_events_schema();
        insert_event(
            &conn,
            "ev1",
            "BootstrapKey",
            0,
            Some("SHA256:K1"),
            Some("ssh-ed25519 K1pub"),
            None,
            None,
            Some("init"),
        );
        let view = project(&conn).expect("project");
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].fingerprint, "SHA256:K1");
        assert_eq!(view[0].role, KeyRole::Active);
        assert_eq!(view[0].public_key, "ssh-ed25519 K1pub");
        assert_eq!(view[0].retired_event_id, None);
    }

    #[test]
    fn bootstrap_plus_keyadded_two_active_sorted_by_topo() {
        let conn = test_helpers::open_with_trust_events_schema();
        insert_event(
            &conn,
            "ev1",
            "BootstrapKey",
            0,
            Some("SHA256:K1"),
            Some("ssh-ed25519 K1pub"),
            None,
            None,
            Some("init"),
        );
        insert_event(
            &conn,
            "ev2",
            "KeyAdded",
            1,
            Some("SHA256:K2"),
            Some("ssh-ed25519 K2pub"),
            None,
            None,
            Some("rotate"),
        );
        let view = project(&conn).expect("project");
        assert_eq!(view.len(), 2);
        assert_eq!(view[0].fingerprint, "SHA256:K1");
        assert_eq!(view[1].fingerprint, "SHA256:K2");
        assert!(view.iter().all(|v| v.role == KeyRole::Active));
    }

    #[test]
    fn rotate_out_flips_first_to_rotated() {
        let conn = test_helpers::open_with_trust_events_schema();
        insert_event(
            &conn,
            "ev1",
            "BootstrapKey",
            0,
            Some("SHA256:K1"),
            Some("ssh-ed25519 K1pub"),
            None,
            None,
            Some("init"),
        );
        insert_event(
            &conn,
            "ev2",
            "KeyAdded",
            1,
            Some("SHA256:K2"),
            Some("ssh-ed25519 K2pub"),
            None,
            None,
            Some("rotate"),
        );
        insert_event(
            &conn,
            "ev3",
            "KeyRotatedOut",
            2,
            Some("SHA256:K1"),
            None,
            None,
            None,
            Some("hygiene"),
        );
        let view = project(&conn).expect("project");
        assert_eq!(view.len(), 2);
        let k1 = view.iter().find(|v| v.fingerprint == "SHA256:K1").unwrap();
        assert_eq!(k1.role, KeyRole::Rotated);
        assert_eq!(k1.retired_event_id.as_deref(), Some("ev3"));
        assert_eq!(k1.retired_reason.as_deref(), Some("hygiene"));
        let k2 = view.iter().find(|v| v.fingerprint == "SHA256:K2").unwrap();
        assert_eq!(k2.role, KeyRole::Active);
    }

    #[test]
    fn compromised_flips_first_to_compromised() {
        let conn = test_helpers::open_with_trust_events_schema();
        insert_event(
            &conn,
            "ev1",
            "BootstrapKey",
            0,
            Some("SHA256:K1"),
            Some("ssh-ed25519 K1pub"),
            None,
            None,
            Some("init"),
        );
        insert_event(
            &conn,
            "ev2",
            "KeyAdded",
            1,
            Some("SHA256:K2"),
            Some("ssh-ed25519 K2pub"),
            None,
            None,
            Some("rotate"),
        );
        insert_event(
            &conn,
            "ev3",
            "KeyCompromised",
            2,
            Some("SHA256:K1"),
            None,
            None,
            None,
            Some("suspected leak"),
        );
        let view = project(&conn).expect("project");
        let k1 = view.iter().find(|v| v.fingerprint == "SHA256:K1").unwrap();
        assert_eq!(k1.role, KeyRole::Compromised);
    }

    #[test]
    fn reanchor_marks_old_as_reanchored_new_stays_active() {
        let conn = test_helpers::open_with_trust_events_schema();
        insert_event(
            &conn,
            "ev1",
            "BootstrapKey",
            0,
            Some("SHA256:K1"),
            Some("ssh-ed25519 K1pub"),
            None,
            None,
            Some("init"),
        );
        insert_event(
            &conn,
            "ev2",
            "KeyAdded",
            1,
            Some("SHA256:K2"),
            Some("ssh-ed25519 K2pub"),
            None,
            None,
            Some("recover predecessor"),
        );
        insert_event(
            &conn,
            "ev3",
            "BootstrapReanchor",
            2,
            None,
            None,
            Some("SHA256:K1"),
            Some("SHA256:K2"),
            Some("operator-supplied chain-break note"),
        );
        let view = project(&conn).expect("project");
        assert_eq!(view.len(), 2);
        let k1 = view.iter().find(|v| v.fingerprint == "SHA256:K1").unwrap();
        assert_eq!(k1.role, KeyRole::Reanchored);
        assert_eq!(k1.retired_event_id.as_deref(), Some("ev3"));
        // Per the hard-coded literal — NOT the event's `reason` field.
        assert_eq!(
            k1.retired_reason.as_deref(),
            Some("anchor moved by BootstrapReanchor")
        );
        let k2 = view.iter().find(|v| v.fingerprint == "SHA256:K2").unwrap();
        assert_eq!(k2.role, KeyRole::Active);
    }

    #[test]
    fn reanchor_successor_can_later_be_rotated() {
        let conn = test_helpers::open_with_trust_events_schema();
        insert_event(
            &conn,
            "ev1",
            "BootstrapKey",
            0,
            Some("SHA256:K1"),
            Some("ssh-ed25519 K1pub"),
            None,
            None,
            Some("init"),
        );
        insert_event(
            &conn,
            "ev2",
            "KeyAdded",
            1,
            Some("SHA256:K2"),
            Some("ssh-ed25519 K2pub"),
            None,
            None,
            Some("recover predecessor"),
        );
        insert_event(
            &conn,
            "ev3",
            "BootstrapReanchor",
            2,
            None,
            None,
            Some("SHA256:K1"),
            Some("SHA256:K2"),
            Some("anchor moved"),
        );
        insert_event(
            &conn,
            "ev4",
            "KeyRotatedOut",
            3,
            Some("SHA256:K2"),
            None,
            None,
            None,
            Some("rotate successor"),
        );
        let view = project(&conn).expect("project");
        let k2 = view.iter().find(|v| v.fingerprint == "SHA256:K2").unwrap();
        assert_eq!(k2.role, KeyRole::Rotated);
    }

    #[test]
    fn compromised_before_reanchor_stays_compromised() {
        let conn = test_helpers::open_with_trust_events_schema();
        insert_event(
            &conn,
            "ev1",
            "BootstrapKey",
            0,
            Some("SHA256:K1"),
            Some("ssh-ed25519 K1pub"),
            None,
            None,
            Some("init"),
        );
        insert_event(
            &conn,
            "ev2",
            "KeyCompromised",
            1,
            Some("SHA256:K1"),
            None,
            None,
            None,
            Some("compromise"),
        );
        insert_event(
            &conn,
            "ev3",
            "KeyAdded",
            2,
            Some("SHA256:K2"),
            Some("ssh-ed25519 K2pub"),
            None,
            None,
            Some("recover predecessor"),
        );
        insert_event(
            &conn,
            "ev4",
            "BootstrapReanchor",
            3,
            None,
            None,
            Some("SHA256:K1"),
            Some("SHA256:K2"),
            Some("anchor moved"),
        );
        let view = project(&conn).expect("project");
        let k1 = view.iter().find(|v| v.fingerprint == "SHA256:K1").unwrap();
        // Compromise is terminal; not downgraded to Reanchored.
        assert_eq!(k1.role, KeyRole::Compromised);
        // retired_* fields point at the COMPROMISE event, not the reanchor.
        assert_eq!(k1.retired_event_id.as_deref(), Some("ev2"));
        let k2 = view.iter().find(|v| v.fingerprint == "SHA256:K2").unwrap();
        assert_eq!(k2.role, KeyRole::Active);
    }

    #[test]
    fn rotated_then_compromised_reclassifies_to_compromised() {
        let conn = test_helpers::open_with_trust_events_schema();
        insert_event(
            &conn,
            "ev1",
            "BootstrapKey",
            0,
            Some("SHA256:K1"),
            Some("ssh-ed25519 K1pub"),
            None,
            None,
            Some("init"),
        );
        insert_event(
            &conn,
            "ev2",
            "KeyAdded",
            1,
            Some("SHA256:K2"),
            Some("ssh-ed25519 K2pub"),
            None,
            None,
            Some("rotate"),
        );
        insert_event(
            &conn,
            "ev3",
            "KeyRotatedOut",
            2,
            Some("SHA256:K1"),
            None,
            None,
            None,
            Some("routine retirement"),
        );
        insert_event(
            &conn,
            "ev4",
            "KeyCompromised",
            3,
            Some("SHA256:K1"),
            None,
            None,
            None,
            Some("retroactive compromise"),
        );
        let view = project(&conn).expect("project");
        let k1 = view.iter().find(|v| v.fingerprint == "SHA256:K1").unwrap();
        // Rotated → Compromised reclassification: role becomes Compromised
        // and retired_event_id swaps to the compromise event.
        assert_eq!(k1.role, KeyRole::Compromised);
        assert_eq!(k1.retired_event_id.as_deref(), Some("ev4"));
        assert_eq!(k1.retired_reason.as_deref(), Some("retroactive compromise"));
    }

    #[test]
    fn reanchored_then_compromised_reclassifies_to_compromised() {
        let conn = test_helpers::open_with_trust_events_schema();
        insert_event(
            &conn,
            "ev1",
            "BootstrapKey",
            0,
            Some("SHA256:K1"),
            Some("ssh-ed25519 K1pub"),
            None,
            None,
            Some("init"),
        );
        insert_event(
            &conn,
            "ev2",
            "KeyAdded",
            1,
            Some("SHA256:K2"),
            Some("ssh-ed25519 K2pub"),
            None,
            None,
            Some("predecessor"),
        );
        insert_event(
            &conn,
            "ev3",
            "BootstrapReanchor",
            2,
            None,
            None,
            Some("SHA256:K1"),
            Some("SHA256:K2"),
            Some("anchor moved"),
        );
        insert_event(
            &conn,
            "ev4",
            "KeyCompromised",
            3,
            Some("SHA256:K1"),
            None,
            None,
            None,
            Some("retroactive compromise"),
        );
        let view = project(&conn).expect("project");
        let k1 = view.iter().find(|v| v.fingerprint == "SHA256:K1").unwrap();
        assert_eq!(k1.role, KeyRole::Compromised);
        assert_eq!(k1.retired_event_id.as_deref(), Some("ev4"));
    }

    #[test]
    fn retirement_event_on_unknown_fingerprint_skipped() {
        let conn = test_helpers::open_with_trust_events_schema();
        insert_event(
            &conn,
            "ev1",
            "BootstrapKey",
            0,
            Some("SHA256:K1"),
            Some("ssh-ed25519 K1pub"),
            None,
            None,
            Some("init"),
        );
        // KeyRotatedOut on a never-introduced fingerprint — exercise the
        // `out.iter_mut().find(...) else { warn; continue }` defensive branch.
        insert_event(
            &conn,
            "ev2",
            "KeyRotatedOut",
            1,
            Some("SHA256:UNKNOWN"),
            None,
            None,
            None,
            Some("orphan retirement"),
        );
        let view = project(&conn).expect("project");
        // The introducer (K1) is unaffected; the orphan retirement is silently dropped.
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].fingerprint, "SHA256:K1");
        assert_eq!(view[0].role, KeyRole::Active);
    }

    #[test]
    fn degenerate_reanchor_without_preceding_keyadded_skips_new_fp() {
        let conn = test_helpers::open_with_trust_events_schema();
        insert_event(
            &conn,
            "ev1",
            "BootstrapKey",
            0,
            Some("SHA256:K1"),
            Some("ssh-ed25519 K1pub"),
            None,
            None,
            Some("init"),
        );
        // No KeyAdded(K2) — hand-edited events.yml degenerate case.
        insert_event(
            &conn,
            "ev2",
            "BootstrapReanchor",
            1,
            None,
            None,
            Some("SHA256:K1"),
            Some("SHA256:K2"),
            Some("anchor moved"),
        );
        let view = project(&conn).expect("project");
        // K1 is Reanchored.
        let k1 = view.iter().find(|v| v.fingerprint == "SHA256:K1").unwrap();
        assert_eq!(k1.role, KeyRole::Reanchored);
        // K2 is absent from the projection (no introducer).
        assert!(view.iter().all(|v| v.fingerprint != "SHA256:K2"));
    }
}

#[cfg(test)]
mod test_helpers {
    use rusqlite::Connection;

    pub fn open_with_trust_events_schema() -> Connection {
        let conn = Connection::open_in_memory().expect("open");
        conn.execute_batch(
            "CREATE TABLE trust_events (
                event_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                fingerprint TEXT,
                old_fingerprint TEXT,
                new_fingerprint TEXT,
                public_key TEXT,
                effective_commit TEXT NOT NULL,
                effective_commit_topo_pos INTEGER NOT NULL,
                introduced_by_signer TEXT NOT NULL,
                chain_validated_by TEXT,
                reason TEXT,
                chain_anchor_lost INTEGER,
                materialized_at TEXT NOT NULL
            );",
        )
        .expect("schema");
        conn
    }
}
