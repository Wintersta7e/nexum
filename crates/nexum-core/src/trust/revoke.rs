//! Append `KeyRotatedOut` / `KeyCompromised` events to events.yml,
//! then regenerate the three derived signer files. Mirrors the shape
//! of `trust::rotate::append_key_added`.

use std::path::Path;

use uuid::Uuid;

use super::events::{Event, EventKind, EventKindTag, EventLog, TrustError, load_events_yml};
use super::regenerate::{RegenerateOutcome, regenerate_files};

/// Append a `KeyRotatedOut` event for `fingerprint` to events.yml, then
/// regenerate the three signer files. Returns the bare file names the caller
/// should stage with the `.trust/` prefix.
///
/// # Errors
///
/// - `TrustError::DuplicateEvent { kind: "KeyRotatedOut", fingerprint }`
///   if a `KeyRotatedOut` event for `fingerprint` already exists.
/// - `TrustError::DuplicateEvent { kind: "KeyCompromised", fingerprint }`
///   if a `KeyCompromised` event for `fingerprint` already exists.
///   Compromise is the terminal classification, so once a fingerprint
///   has been marked compromised it cannot be re-routed through
///   `KeyRotatedOut`.
/// - `TrustError::FingerprintNotKnown { fingerprint }` if `fingerprint`
///   has never been introduced by a `BootstrapKey` or `KeyAdded` event.
/// - `TrustError::Parse` / `TrustError::Io` / `TrustError::Serialize`
///   on filesystem or YAML failures.
pub fn append_key_rotated_out(
    events_yml: &Path,
    trust_dir: &Path,
    fingerprint: &str,
    reason: &str,
) -> Result<Vec<String>, TrustError> {
    append_revoke_event(
        events_yml,
        trust_dir,
        fingerprint,
        EventKind::KeyRotatedOut {
            fingerprint: fingerprint.to_owned(),
            reason: reason.to_owned(),
        },
        EventKindTag::KeyRotatedOut,
    )
}

/// Append a `KeyCompromised` event for `fingerprint` to events.yml, then
/// regenerate the three signer files.
///
/// # Errors
///
/// Same as `append_key_rotated_out`, except a prior `KeyRotatedOut` is no
/// longer a duplicate-causing precondition. Reclassification from rotated
/// to compromised is permitted: the upgrade strengthens the audit trail
/// because compromise is the more severe classification.
pub fn append_key_compromised(
    events_yml: &Path,
    trust_dir: &Path,
    fingerprint: &str,
    reason: &str,
) -> Result<Vec<String>, TrustError> {
    append_revoke_event(
        events_yml,
        trust_dir,
        fingerprint,
        EventKind::KeyCompromised {
            fingerprint: fingerprint.to_owned(),
            reason: reason.to_owned(),
        },
        EventKindTag::KeyCompromised,
    )
}

fn append_revoke_event(
    events_yml: &Path,
    trust_dir: &Path,
    fingerprint: &str,
    new_event: EventKind,
    revoke_kind: EventKindTag,
) -> Result<Vec<String>, TrustError> {
    let mut log: EventLog = load_events_yml(events_yml)?;

    // Knownness: a BootstrapKey or KeyAdded introducer for this fingerprint
    // must exist. BootstrapReanchor is NOT an introducer; reanchor
    // successors are known via their preceding KeyAdded event.
    let introduced = log.events.iter().any(|e| match &e.payload {
        EventKind::BootstrapKey {
            fingerprint: fp, ..
        }
        | EventKind::KeyAdded {
            fingerprint: fp, ..
        } => fp == fingerprint,
        _ => false,
    });
    if !introduced {
        return Err(TrustError::FingerprintNotKnown {
            fingerprint: fingerprint.to_owned(),
        });
    }

    // Duplicate-event check, ordered by severity so the most-severe terminal
    // classification wins when multiple historic events apply.
    //   - A prior KeyCompromised for this fp always refuses, regardless of
    //     which event we are trying to append. Compromise is the terminal
    //     classification: no downgrade path, no re-marking, no rotation
    //     after compromise.
    //   - Otherwise, a prior KeyRotatedOut refuses only when we are trying
    //     to append another KeyRotatedOut. Reclassification from rotated
    //     to compromised is the asymmetric upgrade path that strengthens
    //     the audit trail.
    let prior_compromised = log.events.iter().any(|e| {
        matches!(&e.payload, EventKind::KeyCompromised { fingerprint: fp, .. } if fp == fingerprint)
    });
    if prior_compromised {
        return Err(TrustError::DuplicateEvent {
            kind: "KeyCompromised",
            fingerprint: fingerprint.to_owned(),
        });
    }
    if matches!(revoke_kind, EventKindTag::KeyRotatedOut) {
        let prior_rotated = log.events.iter().any(|e| {
            matches!(&e.payload, EventKind::KeyRotatedOut { fingerprint: fp, .. } if fp == fingerprint)
        });
        if prior_rotated {
            return Err(TrustError::DuplicateEvent {
                kind: revoke_kind.as_db_str(),
                fingerprint: fingerprint.to_owned(),
            });
        }
    }

    log.events.push(Event {
        event_id: Uuid::now_v7(),
        payload: new_event,
    });

    let yaml = serde_yaml::to_string(&log).map_err(TrustError::Serialize)?;
    std::fs::write(events_yml, yaml).map_err(|e| TrustError::Io {
        path: events_yml.display().to_string(),
        source: e,
    })?;

    // Regenerate the three derived signer files. events.yml is always
    // staged (we just appended an event); the signer-file names are only
    // appended when `regenerate_files` reports them rewritten.
    let regen = regenerate_files(events_yml, trust_dir)?;
    let mut files = vec!["events.yml".to_owned()];
    if let RegenerateOutcome::Updated { files: extra } = regen {
        for f in extra {
            files.push((*f).to_owned());
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_bootstrap(events_yml: &Path) {
        let yaml = r#"schema_version: 1
events:
  - event_id: 019e0a14-7000-7c00-a000-000000000001
    kind: BootstrapKey
    fingerprint: SHA256:K1
    public_key: "ssh-ed25519 K1pub user@host"
    reason: "Initial bootstrap"
"#;
        std::fs::write(events_yml, yaml).expect("seed");
    }

    fn seed_bootstrap_plus_added(events_yml: &Path) {
        let yaml = r#"schema_version: 1
events:
  - event_id: 019e0a14-7000-7c00-a000-000000000001
    kind: BootstrapKey
    fingerprint: SHA256:K1
    public_key: "ssh-ed25519 K1pub user@host"
    reason: "Initial bootstrap"
  - event_id: 019e0a14-7100-7c00-a000-000000000002
    kind: KeyAdded
    fingerprint: SHA256:K2
    public_key: "ssh-ed25519 K2pub user@host"
    reason: "Rotation predecessor"
"#;
        std::fs::write(events_yml, yaml).expect("seed");
    }

    fn fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let dir = tempfile::TempDir::new().expect("tmp");
        let trust_dir = dir.path().join(".trust");
        std::fs::create_dir_all(&trust_dir).expect("mkdir");
        let events_yml = trust_dir.join("events.yml");
        (dir, trust_dir, events_yml)
    }

    #[test]
    fn rotated_out_on_unknown_fp_is_fingerprint_not_known() {
        let (_dir, trust_dir, events_yml) = fixture();
        seed_bootstrap(&events_yml);
        let err = append_key_rotated_out(&events_yml, &trust_dir, "SHA256:Unknown", "hygiene")
            .expect_err("should refuse unknown fp");
        match err {
            TrustError::FingerprintNotKnown { fingerprint } => {
                assert_eq!(fingerprint, "SHA256:Unknown");
            }
            other => panic!("expected FingerprintNotKnown, got {other:?}"),
        }
    }

    #[test]
    fn rotated_out_on_already_rotated_is_duplicate_event() {
        let (_dir, trust_dir, events_yml) = fixture();
        seed_bootstrap_plus_added(&events_yml);
        append_key_rotated_out(&events_yml, &trust_dir, "SHA256:K1", "first rotation")
            .expect("first rotation succeeds");
        let err = append_key_rotated_out(&events_yml, &trust_dir, "SHA256:K1", "second")
            .expect_err("second should refuse");
        match err {
            TrustError::DuplicateEvent { kind, fingerprint } => {
                assert_eq!(kind, "KeyRotatedOut");
                assert_eq!(fingerprint, "SHA256:K1");
            }
            other => panic!("expected DuplicateEvent, got {other:?}"),
        }
    }

    #[test]
    fn rotated_out_on_already_compromised_is_duplicate_event() {
        let (_dir, trust_dir, events_yml) = fixture();
        seed_bootstrap_plus_added(&events_yml);
        append_key_compromised(&events_yml, &trust_dir, "SHA256:K1", "leak")
            .expect("compromise succeeds");
        let err = append_key_rotated_out(&events_yml, &trust_dir, "SHA256:K1", "downgrade attempt")
            .expect_err(
                "compromise is terminal: rotating out an already-compromised key must refuse",
            );
        match err {
            TrustError::DuplicateEvent { kind, fingerprint } => {
                assert_eq!(kind, "KeyCompromised");
                assert_eq!(fingerprint, "SHA256:K1");
            }
            other => panic!("expected DuplicateEvent KeyCompromised, got {other:?}"),
        }
    }

    #[test]
    fn rotated_out_on_active_fp_succeeds() {
        let (_dir, trust_dir, events_yml) = fixture();
        seed_bootstrap_plus_added(&events_yml);
        let touched = append_key_rotated_out(&events_yml, &trust_dir, "SHA256:K1", "hygiene")
            .expect("rotate succeeds");
        assert!(touched.contains(&"events.yml".to_owned()));
        // events.yml now contains the new event.
        let body = std::fs::read_to_string(&events_yml).expect("read");
        assert!(body.contains("KeyRotatedOut"));
        assert!(body.contains("SHA256:K1"));
        // allowed_signers excludes K1 (K2 remains).
        let allowed = std::fs::read_to_string(trust_dir.join("allowed_signers")).expect("allowed");
        assert!(allowed.contains("K2pub"));
        assert!(!allowed.contains("K1pub"));
        // revoked_signers includes K1.
        let revoked = std::fs::read_to_string(trust_dir.join("revoked_signers")).expect("revoked");
        assert!(revoked.contains("K1pub"));
    }

    #[test]
    fn compromised_on_unknown_fp_is_fingerprint_not_known() {
        let (_dir, trust_dir, events_yml) = fixture();
        seed_bootstrap(&events_yml);
        let err = append_key_compromised(&events_yml, &trust_dir, "SHA256:Unknown", "leak")
            .expect_err("should refuse");
        assert!(matches!(err, TrustError::FingerprintNotKnown { .. }));
    }

    #[test]
    fn compromised_on_already_compromised_is_duplicate() {
        let (_dir, trust_dir, events_yml) = fixture();
        seed_bootstrap_plus_added(&events_yml);
        append_key_compromised(&events_yml, &trust_dir, "SHA256:K1", "first")
            .expect("first compromise");
        let err = append_key_compromised(&events_yml, &trust_dir, "SHA256:K1", "second")
            .expect_err("idempotent refused");
        assert!(matches!(
            err,
            TrustError::DuplicateEvent {
                kind: "KeyCompromised",
                ..
            }
        ));
    }

    #[test]
    fn compromised_on_already_rotated_succeeds_reclassification() {
        let (_dir, trust_dir, events_yml) = fixture();
        seed_bootstrap_plus_added(&events_yml);
        append_key_rotated_out(&events_yml, &trust_dir, "SHA256:K1", "hygiene").expect("rotate");
        let touched = append_key_compromised(&events_yml, &trust_dir, "SHA256:K1", "leak retro")
            .expect("reclassification permitted");
        assert!(touched.contains(&"events.yml".to_owned()));
        let body = std::fs::read_to_string(&events_yml).expect("read");
        assert!(body.contains("KeyRotatedOut"));
        assert!(body.contains("KeyCompromised"));
    }

    #[test]
    fn revoke_reanchor_successor_succeeds() {
        // Reanchor successor is introduced by a preceding KeyAdded
        // (production invariant). Revoking it is fine.
        let (_dir, trust_dir, events_yml) = fixture();
        let yaml = r#"schema_version: 1
events:
  - event_id: 019e0a14-7000-7c00-a000-000000000001
    kind: BootstrapKey
    fingerprint: SHA256:K1
    public_key: "ssh-ed25519 K1pub user@host"
    reason: "Initial bootstrap"
  - event_id: 019e0a14-7100-7c00-a000-000000000002
    kind: KeyAdded
    fingerprint: SHA256:K2
    public_key: "ssh-ed25519 K2pub user@host"
    reason: "Recovery predecessor"
  - event_id: 019e0a14-7400-7c00-a000-000000000003
    kind: BootstrapReanchor
    old_fingerprint: SHA256:K1
    new_fingerprint: SHA256:K2
    reason: "Anchor moved"
"#;
        std::fs::write(&events_yml, yaml).expect("seed");
        let touched =
            append_key_rotated_out(&events_yml, &trust_dir, "SHA256:K2", "rotate successor")
                .expect("revoke reanchor successor permitted");
        assert!(touched.contains(&"events.yml".to_owned()));
    }

    #[test]
    fn rotate_then_compromise_then_rotate_again_refuses() {
        let (_dir, trust_dir, events_yml) = fixture();
        seed_bootstrap_plus_added(&events_yml);
        append_key_rotated_out(&events_yml, &trust_dir, "SHA256:K1", "hygiene").expect("rotate");
        append_key_compromised(&events_yml, &trust_dir, "SHA256:K1", "leak retro")
            .expect("reclassify");
        let err = append_key_rotated_out(&events_yml, &trust_dir, "SHA256:K1", "third")
            .expect_err("compromise terminal");
        assert!(matches!(
            err,
            TrustError::DuplicateEvent {
                kind: "KeyCompromised",
                ..
            }
        ));
    }
}
