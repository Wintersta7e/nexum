//! `nexum keys rotate` — events.yml mutation helper.
//!
//! Splits the trust-state work (duplicate check, append, regenerate) from the
//! git-operation work (sign / verify / config update), which lives in the api
//! facade.

use std::path::Path;

use uuid::Uuid;

use super::events::{Event, EventKind, EventLog, TrustError, load_events_yml};
use super::regenerate::{RegenerateOutcome, regenerate_files};

/// Inputs derived from the supplied `--new-key` path: the fingerprint and the
/// full SSH public-key blob.
#[derive(Debug, Clone)]
pub struct NewKey {
    pub fingerprint: String,
    pub public_key: String,
}

/// True if `payload` references `fp` in any fingerprint field.
///
/// The duplicate-key invariant treats every fingerprint slot as load-bearing:
/// `BootstrapKey` / `KeyAdded` / `KeyRotatedOut` / `KeyCompromised` carry a
/// single `fingerprint`; `BootstrapReanchor` carries both `old_fingerprint`
/// and `new_fingerprint`. A match in any of these slots means the rotation
/// candidate is not a fresh key and must be refused.
fn event_mentions(payload: &EventKind, fp: &str) -> bool {
    match payload {
        EventKind::BootstrapKey { fingerprint, .. }
        | EventKind::KeyAdded { fingerprint, .. }
        | EventKind::KeyRotatedOut { fingerprint, .. }
        | EventKind::KeyCompromised { fingerprint, .. } => fingerprint == fp,
        EventKind::BootstrapReanchor {
            old_fingerprint,
            new_fingerprint,
            ..
        } => old_fingerprint == fp || new_fingerprint == fp,
    }
}

/// Append a `KeyAdded` event for `new_key` to `events_yml`, then regenerate
/// the three derived signer files. Returns the bare file names that the caller
/// should stage with a `.trust/` prefix (`"events.yml"` is always included;
/// the regenerated signer-file names are appended when they changed).
///
/// # Errors
///
/// Returns `TrustError::DuplicateKey` if `new_key.fingerprint` already appears
/// in events.yml in any role: `BootstrapKey`, `KeyAdded`, `KeyRotatedOut`,
/// `KeyCompromised`, or either field of `BootstrapReanchor`.
/// Returns `TrustError::Parse` / `TrustError::Io` / `TrustError::Serialize`
/// on filesystem or YAML failures.
pub fn append_key_added(
    events_yml: &Path,
    trust_dir: &Path,
    new_key: &NewKey,
    reason: &str,
) -> Result<Vec<String>, TrustError> {
    let mut log: EventLog = load_events_yml(events_yml)?;

    let fp = &new_key.fingerprint;
    if log.events.iter().any(|e| event_mentions(&e.payload, fp)) {
        return Err(TrustError::DuplicateKey {
            fingerprint: fp.clone(),
        });
    }

    log.events.push(Event {
        event_id: Uuid::now_v7(),
        payload: EventKind::KeyAdded {
            fingerprint: fp.clone(),
            public_key: new_key.public_key.clone(),
            reason: reason.to_owned(),
        },
    });

    let yaml = serde_yaml::to_string(&log).map_err(TrustError::Serialize)?;
    std::fs::write(events_yml, yaml).map_err(|e| TrustError::Io {
        path: events_yml.display().to_string(),
        source: e,
    })?;

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
    use tempfile::TempDir;
    use uuid::Uuid;

    use crate::trust::events::{EventKind, write_seed_yaml};

    fn fake_fingerprint(tag: &str) -> String {
        format!("SHA256:{tag}AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    }

    fn fake_pubkey(tag: &str) -> String {
        format!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA{tag} test@example.invalid")
    }

    fn seed_events(dir: &TempDir) -> (std::path::PathBuf, std::path::PathBuf) {
        let trust_dir = dir.path().join(".trust");
        std::fs::create_dir_all(&trust_dir).unwrap();
        let events_yml = trust_dir.join("events.yml");
        write_seed_yaml(&events_yml, &fake_fingerprint("A"), &fake_pubkey("A")).unwrap();
        (events_yml, trust_dir)
    }

    #[test]
    fn append_key_added_writes_event_and_returns_files() {
        let dir = TempDir::new().unwrap();
        let (events_yml, trust_dir) = seed_events(&dir);

        let new_key = NewKey {
            fingerprint: fake_fingerprint("B"),
            public_key: fake_pubkey("B"),
        };
        let files = append_key_added(&events_yml, &trust_dir, &new_key, "test rotation").unwrap();

        assert!(files.contains(&"events.yml".to_owned()));
        let raw = std::fs::read_to_string(&events_yml).unwrap();
        assert!(raw.contains("KeyAdded"));
        assert!(raw.contains(&fake_fingerprint("B")));
    }

    #[test]
    fn duplicate_bootstrap_fingerprint_returns_error() {
        let dir = TempDir::new().unwrap();
        let (events_yml, trust_dir) = seed_events(&dir);

        let dup = NewKey {
            fingerprint: fake_fingerprint("A"), // same as bootstrap
            public_key: fake_pubkey("A"),
        };
        let result = append_key_added(&events_yml, &trust_dir, &dup, "dupe");
        assert!(
            matches!(result, Err(TrustError::DuplicateKey { .. })),
            "expected DuplicateKey, got {result:?}"
        );
    }

    #[test]
    fn duplicate_keyadded_fingerprint_returns_error() {
        let dir = TempDir::new().unwrap();
        let (events_yml, trust_dir) = seed_events(&dir);

        // Add once successfully.
        let key_b = NewKey {
            fingerprint: fake_fingerprint("B"),
            public_key: fake_pubkey("B"),
        };
        append_key_added(&events_yml, &trust_dir, &key_b, "first add").unwrap();

        // Attempt to add again with the same fingerprint.
        let result = append_key_added(&events_yml, &trust_dir, &key_b, "second add");
        assert!(
            matches!(result, Err(TrustError::DuplicateKey { .. })),
            "expected DuplicateKey on re-add"
        );
    }

    #[test]
    fn duplicate_rotated_out_fingerprint_is_refused() {
        let dir = TempDir::new().unwrap();
        let trust_dir = dir.path().join(".trust");
        std::fs::create_dir_all(&trust_dir).unwrap();
        let events_yml = trust_dir.join("events.yml");

        // Seed manually with a KeyRotatedOut event for fingerprint C.
        let fp_a = fake_fingerprint("A");
        let fp_c = fake_fingerprint("C");
        let log = crate::trust::events::EventLog {
            schema_version: 1,
            events: vec![
                Event {
                    event_id: Uuid::now_v7(),
                    payload: EventKind::BootstrapKey {
                        fingerprint: fp_a.clone(),
                        public_key: fake_pubkey("A"),
                        reason: "Initial bootstrap".into(),
                    },
                },
                Event {
                    event_id: Uuid::now_v7(),
                    payload: EventKind::KeyRotatedOut {
                        fingerprint: fp_c.clone(),
                        reason: "Routine rotation".into(),
                    },
                },
            ],
        };
        let yaml = serde_yaml::to_string(&log).unwrap();
        std::fs::write(&events_yml, yaml).unwrap();

        let key_c = NewKey {
            fingerprint: fp_c.clone(),
            public_key: fake_pubkey("C"),
        };
        let result = append_key_added(&events_yml, &trust_dir, &key_c, "re-add");
        assert!(
            matches!(result, Err(TrustError::DuplicateKey { .. })),
            "expected DuplicateKey for KeyRotatedOut fingerprint"
        );
    }

    #[test]
    fn duplicate_reanchor_old_fingerprint_is_refused() {
        let dir = TempDir::new().unwrap();
        let trust_dir = dir.path().join(".trust");
        std::fs::create_dir_all(&trust_dir).unwrap();
        let events_yml = trust_dir.join("events.yml");

        let fp_old = fake_fingerprint("OLD");
        let fp_new = fake_fingerprint("NEW");
        let log = crate::trust::events::EventLog {
            schema_version: 1,
            events: vec![
                Event {
                    event_id: Uuid::now_v7(),
                    payload: EventKind::BootstrapKey {
                        fingerprint: fake_fingerprint("A"),
                        public_key: fake_pubkey("A"),
                        reason: "Initial bootstrap".into(),
                    },
                },
                Event {
                    event_id: Uuid::now_v7(),
                    payload: EventKind::BootstrapReanchor {
                        old_fingerprint: fp_old.clone(),
                        new_fingerprint: fp_new.clone(),
                        reason: "Bootstrap key lost".into(),
                        acknowledge_chain_anchor_lost: false,
                    },
                },
            ],
        };
        let yaml = serde_yaml::to_string(&log).unwrap();
        std::fs::write(&events_yml, yaml).unwrap();

        // Try adding the old_fingerprint.
        let key_old = NewKey {
            fingerprint: fp_old.clone(),
            public_key: fake_pubkey("OLD"),
        };
        let r = append_key_added(&events_yml, &trust_dir, &key_old, "re-add old");
        assert!(
            matches!(r, Err(TrustError::DuplicateKey { .. })),
            "expected DuplicateKey for BootstrapReanchor.old_fingerprint"
        );

        // Try adding the new_fingerprint.
        let key_new = NewKey {
            fingerprint: fp_new.clone(),
            public_key: fake_pubkey("NEW"),
        };
        let r2 = append_key_added(&events_yml, &trust_dir, &key_new, "re-add new");
        assert!(
            matches!(r2, Err(TrustError::DuplicateKey { .. })),
            "expected DuplicateKey for BootstrapReanchor.new_fingerprint"
        );
    }
}
