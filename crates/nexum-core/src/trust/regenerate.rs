//! Project the canonical `events.yml` event log into the three derived
//! OpenSSH-format signer files (§9 trust file storage).
//!
//! Rules (§9):
//! - `historical_signers` — monotonic union of every `public_key` ever added
//!   (`BootstrapKey`, `KeyAdded`, `BootstrapReanchor`.`new_fingerprint`). Never removes keys.
//! - `allowed_signers` — current active signers: those present in historical
//!   that have NOT been removed by `KeyRotatedOut` or `KeyCompromised` as of the
//!   last event.
//! - `revoked_signers` — keys with a `KeyRotatedOut` or `KeyCompromised` event.
//!
//! Format of each line in historical/allowed signer files (`OpenSSH` `allowed_signers`):
//!   `* <key_type> <base64pubkey>`
//! Format of each line in `revoked_signers`:
//!   `<key_type> <base64pubkey>`
//!
//! `regenerate_files` is idempotent: if all three files already match the
//! projection, it returns `RegenerateOutcome::NoChange` without writing.

use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use super::events::{load_events_yml, EventKind, TrustError};

/// Outcome of `regenerate_files`.
#[derive(Debug, Clone, PartialEq)]
pub enum RegenerateOutcome {
    /// All files were already consistent; nothing written.
    NoChange,
    /// One or more files were (re)written.
    Updated { files: Vec<&'static str> },
}

/// Compute and write the three derived `OpenSSH`-format signer files from `events_yml_path`.
///
/// `trust_dir` is the directory into which the three projection files are written
/// (`historical_signers`, `allowed_signers`, `revoked_signers`).
///
/// Returns `RegenerateOutcome::NoChange` when all files already match the projection.
///
/// # Errors
///
/// Returns `TrustError::Io` on read/write failures.
/// Returns `TrustError::Parse` if `events.yml` is malformed.
pub fn regenerate_files(
    events_yml_path: &Path,
    trust_dir: &Path,
) -> Result<RegenerateOutcome, TrustError> {
    let log = load_events_yml(events_yml_path)?;

    // Maps fingerprint → public_key_blob for every key ever added (monotonic).
    let mut historical: HashMap<String, String> = HashMap::new();
    // Fingerprints currently revoked (KeyRotatedOut or KeyCompromised).
    let mut revoked_fps: HashSet<String> = HashSet::new();

    for event in &log.events {
        match &event.payload {
            EventKind::BootstrapKey {
                fingerprint,
                public_key,
                ..
            }
            | EventKind::KeyAdded {
                fingerprint,
                public_key,
                ..
            } => {
                historical.insert(fingerprint.clone(), public_key.clone());
            }
            EventKind::BootstrapReanchor {
                new_fingerprint, ..
            } => {
                // The new key's public_key blob is not inline in this event variant.
                // Per §9 M1b flow, the reanchor is always preceded by a KeyAdded event
                // that carries the new public_key, so historical already contains it.
                // Nothing to insert here; silently skip unknown new_fingerprint.
                let _ = new_fingerprint;
            }
            EventKind::KeyRotatedOut { fingerprint, .. }
            | EventKind::KeyCompromised { fingerprint, .. } => {
                revoked_fps.insert(fingerprint.clone());
            }
        }
    }

    // historical_signers: all keys ever added.
    let historical_content = build_allowed_signers_content(&historical);

    // allowed_signers: historical minus revoked.
    let active: HashMap<&String, &String> = historical
        .iter()
        .filter(|(fp, _)| !revoked_fps.contains(*fp))
        .collect();
    let allowed_content = build_allowed_signers_content_ref(&active);

    // revoked_signers: keys that are rotated or compromised.
    let revoked: HashMap<&String, &String> = historical
        .iter()
        .filter(|(fp, _)| revoked_fps.contains(*fp))
        .collect();
    let revoked_content = build_revoked_content_ref(&revoked);

    let hist_path = trust_dir.join("historical_signers");
    let allow_path = trust_dir.join("allowed_signers");
    let revoked_path = trust_dir.join("revoked_signers");

    let mut written: Vec<&'static str> = Vec::new();

    if needs_write(&hist_path, &historical_content)? {
        write_file(&hist_path, &historical_content)?;
        written.push("historical_signers");
    }
    if needs_write(&allow_path, &allowed_content)? {
        write_file(&allow_path, &allowed_content)?;
        written.push("allowed_signers");
    }
    if needs_write(&revoked_path, &revoked_content)? {
        write_file(&revoked_path, &revoked_content)?;
        written.push("revoked_signers");
    }

    if written.is_empty() {
        Ok(RegenerateOutcome::NoChange)
    } else {
        Ok(RegenerateOutcome::Updated { files: written })
    }
}

/// Format a `HashMap<fingerprint, public_key_blob>` as an `OpenSSH` `allowed_signers` file.
///
/// Each line: `* <public_key_blob>` (the `*` is the principal/namespace wildcard).
/// Lines are sorted by `public_key` for deterministic output.
fn build_allowed_signers_content(keys: &HashMap<String, String>) -> String {
    let mut lines: Vec<String> = keys.values().map(|pubkey| format!("* {pubkey}")).collect();
    lines.sort();
    let mut out = lines.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    out
}

/// Same as `build_allowed_signers_content` but accepts borrowed references.
fn build_allowed_signers_content_ref(keys: &HashMap<&String, &String>) -> String {
    let mut lines: Vec<String> = keys.values().map(|pubkey| format!("* {pubkey}")).collect();
    lines.sort();
    let mut out = lines.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    out
}

/// Format a `HashMap<fingerprint, public_key_blob>` as an `OpenSSH` revoked keys file.
///
/// Each line: `<public_key_blob>` (no principal prefix). Lines sorted for determinism.
fn build_revoked_content_ref(keys: &HashMap<&String, &String>) -> String {
    let mut lines: Vec<&str> = keys.values().map(|s| s.as_str()).collect();
    lines.sort_unstable();
    let mut out = lines.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    out
}

/// Returns `true` if `path` does not exist or its content differs from `expected`.
fn needs_write(path: &Path, expected: &str) -> Result<bool, TrustError> {
    match std::fs::read_to_string(path) {
        Ok(existing) => Ok(existing != expected),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(TrustError::Io {
            path: path.display().to_string(),
            source: e,
        }),
    }
}

fn write_file(path: &Path, content: &str) -> Result<(), TrustError> {
    std::fs::write(path, content).map_err(|e| TrustError::Io {
        path: path.display().to_string(),
        source: e,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::events::{write_seed_yaml, Event, EventKind, EventLog};
    use tempfile::tempdir;
    use uuid::Uuid;

    const FAKE_FP: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const FAKE_PK: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting test@example.invalid";

    #[test]
    fn seed_generates_three_files() {
        let dir = tempdir().unwrap();
        let events_path = dir.path().join("events.yml");
        write_seed_yaml(&events_path, FAKE_FP, FAKE_PK).unwrap();
        let outcome = regenerate_files(&events_path, dir.path()).unwrap();
        assert!(matches!(outcome, RegenerateOutcome::Updated { .. }));
        assert!(dir.path().join("historical_signers").exists());
        assert!(dir.path().join("allowed_signers").exists());
        assert!(dir.path().join("revoked_signers").exists());
    }

    #[test]
    fn seed_historical_contains_bootstrap_key() {
        let dir = tempdir().unwrap();
        let events_path = dir.path().join("events.yml");
        write_seed_yaml(&events_path, FAKE_FP, FAKE_PK).unwrap();
        regenerate_files(&events_path, dir.path()).unwrap();
        let hist = std::fs::read_to_string(dir.path().join("historical_signers")).unwrap();
        assert!(
            hist.contains(FAKE_PK),
            "historical_signers must contain bootstrap pubkey"
        );
    }

    #[test]
    fn seed_revoked_signers_is_empty() {
        let dir = tempdir().unwrap();
        let events_path = dir.path().join("events.yml");
        write_seed_yaml(&events_path, FAKE_FP, FAKE_PK).unwrap();
        regenerate_files(&events_path, dir.path()).unwrap();
        let revoked = std::fs::read_to_string(dir.path().join("revoked_signers")).unwrap();
        assert!(
            revoked.trim().is_empty(),
            "revoked_signers must be empty after seed"
        );
    }

    #[test]
    fn rerun_returns_no_change() {
        let dir = tempdir().unwrap();
        let events_path = dir.path().join("events.yml");
        write_seed_yaml(&events_path, FAKE_FP, FAKE_PK).unwrap();
        regenerate_files(&events_path, dir.path()).unwrap();
        let second = regenerate_files(&events_path, dir.path()).unwrap();
        assert_eq!(second, RegenerateOutcome::NoChange);
    }

    #[test]
    fn deleted_file_is_restored() {
        let dir = tempdir().unwrap();
        let events_path = dir.path().join("events.yml");
        write_seed_yaml(&events_path, FAKE_FP, FAKE_PK).unwrap();
        regenerate_files(&events_path, dir.path()).unwrap();
        std::fs::remove_file(dir.path().join("allowed_signers")).unwrap();
        let outcome = regenerate_files(&events_path, dir.path()).unwrap();
        assert!(
            matches!(&outcome, RegenerateOutcome::Updated { files } if files.contains(&"allowed_signers"))
        );
        assert!(dir.path().join("allowed_signers").exists());
    }

    #[test]
    fn rotated_key_moves_from_allowed_to_revoked() {
        let dir = tempdir().unwrap();
        let events_path = dir.path().join("events.yml");

        let log = EventLog {
            schema_version: 1,
            events: vec![
                Event {
                    event_id: Uuid::now_v7(),
                    payload: EventKind::BootstrapKey {
                        fingerprint: FAKE_FP.into(),
                        public_key: FAKE_PK.into(),
                        reason: "Bootstrap".into(),
                    },
                },
                Event {
                    event_id: Uuid::now_v7(),
                    payload: EventKind::KeyRotatedOut {
                        fingerprint: FAKE_FP.into(),
                        reason: "Rotation test".into(),
                    },
                },
            ],
        };
        let yaml = serde_yaml::to_string(&log).unwrap();
        std::fs::write(&events_path, yaml).unwrap();

        regenerate_files(&events_path, dir.path()).unwrap();

        let allowed = std::fs::read_to_string(dir.path().join("allowed_signers")).unwrap();
        let revoked = std::fs::read_to_string(dir.path().join("revoked_signers")).unwrap();
        assert!(
            !allowed.contains(FAKE_PK),
            "rotated key must not be in allowed_signers"
        );
        assert!(
            revoked.contains(FAKE_PK),
            "rotated key must be in revoked_signers"
        );
    }
}
