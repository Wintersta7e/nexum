//! `nexum keys recover` — events.yml mutation helper.
//!
//! Splits the trust-state work (validate, append, regenerate) from the
//! git-operation work (sign / verify / pin update / sentinel state),
//! which lives in the api facade.

use std::path::Path;

use uuid::Uuid;

use super::events::{Event, EventKind, EventLog, TrustError, load_events_yml};
use super::regenerate::{RegenerateOutcome, regenerate_files};

/// Inputs for a reanchor: the supplied new key's fingerprint, pubkey,
/// and case-discriminator flag.
#[derive(Debug, Clone)]
pub struct ReanchorInputs {
    pub old_fingerprint: String,
    pub new_fingerprint: String,
    pub new_public_key: String,
    pub acknowledge_chain_anchor_lost: bool,
}

/// Append a `BootstrapReanchor` event for `inputs` to `events_yml`, then
/// regenerate the three derived signer files. Returns the bare file
/// names the caller should stage with a `.trust/` prefix
/// (`"events.yml"` is always included; regenerated signer-file names
/// are appended when they changed).
///
/// # Errors
///
/// `TrustError::RecoverOldFpMismatch` when `inputs.old_fingerprint`
/// isn't the chain's most recent prior bootstrap.
/// `TrustError::RecoverDuplicateChain` when a `BootstrapReanchor` event
/// for the same `(old, new)` pair already exists.
/// `TrustError::Io` / `TrustError::Parse` / `TrustError::Serialize` on
/// filesystem or YAML failures.
pub fn append_bootstrap_reanchor(
    events_yml: &Path,
    trust_dir: &Path,
    inputs: &ReanchorInputs,
    reason: &str,
) -> Result<Vec<String>, TrustError> {
    let mut log: EventLog = load_events_yml(events_yml)?;

    // Duplicate-chain check first: refuse if a BootstrapReanchor with
    // the same (old, new) pair already exists. This fires before the
    // mismatch check so that re-emitting an identical pair always
    // returns RecoverDuplicateChain, even if the chain has since
    // advanced past old_fingerprint.
    let duplicate = log.events.iter().any(|e| match &e.payload {
        EventKind::BootstrapReanchor {
            old_fingerprint,
            new_fingerprint,
            ..
        } => {
            *old_fingerprint == inputs.old_fingerprint && *new_fingerprint == inputs.new_fingerprint
        }
        _ => false,
    });
    if duplicate {
        return Err(TrustError::RecoverDuplicateChain {
            old_fp: inputs.old_fingerprint.clone(),
            new_fp: inputs.new_fingerprint.clone(),
        });
    }

    // Compute the chain's current bootstrap fingerprint. Walk events
    // backward, finding the latest BootstrapKey or BootstrapReanchor
    // new_fp.
    let current_bootstrap = log
        .events
        .iter()
        .rev()
        .find_map(|e| match &e.payload {
            EventKind::BootstrapKey { fingerprint, .. } => Some(fingerprint.clone()),
            EventKind::BootstrapReanchor {
                new_fingerprint, ..
            } => Some(new_fingerprint.clone()),
            _ => None,
        })
        .ok_or(TrustError::MalformedBootstrap)?;

    if current_bootstrap != inputs.old_fingerprint {
        return Err(TrustError::RecoverOldFpMismatch {
            expected: current_bootstrap,
            supplied: inputs.old_fingerprint.clone(),
        });
    }

    log.events.push(Event {
        event_id: Uuid::now_v7(),
        payload: EventKind::BootstrapReanchor {
            old_fingerprint: inputs.old_fingerprint.clone(),
            new_fingerprint: inputs.new_fingerprint.clone(),
            new_public_key: inputs.new_public_key.clone(),
            reason: reason.to_owned(),
            acknowledge_chain_anchor_lost: inputs.acknowledge_chain_anchor_lost,
        },
    });

    let yaml = serde_yaml::to_string(&log).map_err(TrustError::Serialize)?;
    // Atomic write: temp file in the same directory + rename.
    let tmp = events_yml.with_extension("yml.tmp");
    std::fs::write(&tmp, yaml).map_err(|e| TrustError::Io {
        path: tmp.display().to_string(),
        source: e,
    })?;
    std::fs::rename(&tmp, events_yml).map_err(|e| TrustError::Io {
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

    use crate::trust::events::{Event, EventKind, write_seed_yaml};

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
    fn append_reanchor_on_clean_chain_succeeds() {
        let dir = TempDir::new().unwrap();
        let (events_yml, trust_dir) = seed_events(&dir);

        let inputs = ReanchorInputs {
            old_fingerprint: fake_fingerprint("A"),
            new_fingerprint: fake_fingerprint("B"),
            new_public_key: fake_pubkey("B"),
            acknowledge_chain_anchor_lost: false,
        };
        let files = append_bootstrap_reanchor(&events_yml, &trust_dir, &inputs, "test").unwrap();

        assert!(files.contains(&"events.yml".to_owned()));
        assert!(
            files.contains(&"historical_signers".to_owned()),
            "B's pubkey must land in historical_signers"
        );

        let yaml = std::fs::read_to_string(&events_yml).unwrap();
        assert!(yaml.contains("BootstrapReanchor"));
        assert!(yaml.contains(&fake_pubkey("B")));
    }

    #[test]
    fn append_reanchor_with_mismatched_old_fp_refuses() {
        let dir = TempDir::new().unwrap();
        let (events_yml, trust_dir) = seed_events(&dir);

        let inputs = ReanchorInputs {
            old_fingerprint: fake_fingerprint("WRONG"),
            new_fingerprint: fake_fingerprint("B"),
            new_public_key: fake_pubkey("B"),
            acknowledge_chain_anchor_lost: false,
        };
        let result = append_bootstrap_reanchor(&events_yml, &trust_dir, &inputs, "test");
        assert!(
            matches!(result, Err(TrustError::RecoverOldFpMismatch { .. })),
            "expected RecoverOldFpMismatch, got {result:?}"
        );
    }

    #[test]
    fn append_reanchor_with_duplicate_chain_refuses() {
        let dir = TempDir::new().unwrap();
        let (events_yml, trust_dir) = seed_events(&dir);

        let inputs = ReanchorInputs {
            old_fingerprint: fake_fingerprint("A"),
            new_fingerprint: fake_fingerprint("B"),
            new_public_key: fake_pubkey("B"),
            acknowledge_chain_anchor_lost: false,
        };
        append_bootstrap_reanchor(&events_yml, &trust_dir, &inputs, "first").unwrap();

        let result = append_bootstrap_reanchor(&events_yml, &trust_dir, &inputs, "second");
        assert!(
            matches!(result, Err(TrustError::RecoverDuplicateChain { .. })),
            "expected RecoverDuplicateChain on re-emit, got {result:?}"
        );
    }

    #[test]
    fn append_reanchor_chains_after_prior_reanchor() {
        // A -> B -> C. After the first, the chain's current bootstrap
        // is B. A second reanchor must have old_fp=B.
        let dir = TempDir::new().unwrap();
        let (events_yml, trust_dir) = seed_events(&dir);

        let a_to_b = ReanchorInputs {
            old_fingerprint: fake_fingerprint("A"),
            new_fingerprint: fake_fingerprint("B"),
            new_public_key: fake_pubkey("B"),
            acknowledge_chain_anchor_lost: false,
        };
        append_bootstrap_reanchor(&events_yml, &trust_dir, &a_to_b, "first reanchor").unwrap();

        let b_to_c = ReanchorInputs {
            old_fingerprint: fake_fingerprint("B"),
            new_fingerprint: fake_fingerprint("C"),
            new_public_key: fake_pubkey("C"),
            acknowledge_chain_anchor_lost: false,
        };
        let result = append_bootstrap_reanchor(&events_yml, &trust_dir, &b_to_c, "second reanchor");
        assert!(
            result.is_ok(),
            "B->C should succeed after A->B; got {result:?}"
        );
    }

    #[test]
    fn append_reanchor_with_old_fp_pointing_at_an_inner_event_refuses() {
        // BootstrapKey(A) + KeyAdded(B). The chain's current bootstrap
        // is still A; old_fp=B should refuse even though B exists in
        // events.yml (B isn't a bootstrap, it's an added signer).
        let dir = TempDir::new().unwrap();
        let (events_yml, trust_dir) = seed_events(&dir);

        let mut log = load_events_yml(&events_yml).unwrap();
        log.events.push(Event {
            event_id: Uuid::now_v7(),
            payload: EventKind::KeyAdded {
                fingerprint: fake_fingerprint("B"),
                public_key: fake_pubkey("B"),
                reason: "rotation".into(),
            },
        });
        std::fs::write(&events_yml, serde_yaml::to_string(&log).unwrap()).unwrap();

        let inputs = ReanchorInputs {
            old_fingerprint: fake_fingerprint("B"),
            new_fingerprint: fake_fingerprint("C"),
            new_public_key: fake_pubkey("C"),
            acknowledge_chain_anchor_lost: false,
        };
        let result = append_bootstrap_reanchor(&events_yml, &trust_dir, &inputs, "test");
        assert!(
            matches!(result, Err(TrustError::RecoverOldFpMismatch { .. })),
            "expected RecoverOldFpMismatch when old_fp is an inner KeyAdded"
        );
    }

    #[test]
    fn append_reanchor_sets_acknowledge_chain_anchor_lost_from_inputs() {
        let dir = TempDir::new().unwrap();
        let (events_yml, trust_dir) = seed_events(&dir);

        let inputs = ReanchorInputs {
            old_fingerprint: fake_fingerprint("A"),
            new_fingerprint: fake_fingerprint("B"),
            new_public_key: fake_pubkey("B"),
            acknowledge_chain_anchor_lost: true,
        };
        append_bootstrap_reanchor(&events_yml, &trust_dir, &inputs, "case B").unwrap();

        let log = load_events_yml(&events_yml).unwrap();
        let reanchor = log
            .events
            .iter()
            .find_map(|e| match &e.payload {
                EventKind::BootstrapReanchor {
                    acknowledge_chain_anchor_lost,
                    ..
                } => Some(*acknowledge_chain_anchor_lost),
                _ => None,
            })
            .expect("must find the BootstrapReanchor event");
        assert!(reanchor, "ack flag must propagate");
    }

    #[test]
    fn append_reanchor_excludes_old_fp_from_allowed_signers() {
        let dir = TempDir::new().unwrap();
        let (events_yml, trust_dir) = seed_events(&dir);

        let inputs = ReanchorInputs {
            old_fingerprint: fake_fingerprint("A"),
            new_fingerprint: fake_fingerprint("B"),
            new_public_key: fake_pubkey("B"),
            acknowledge_chain_anchor_lost: false,
        };
        append_bootstrap_reanchor(&events_yml, &trust_dir, &inputs, "test").unwrap();

        let allowed = std::fs::read_to_string(trust_dir.join("allowed_signers")).unwrap();
        assert!(
            !allowed.contains(&fake_pubkey("A")),
            "A excluded from allowed: {allowed}"
        );
        assert!(
            allowed.contains(&fake_pubkey("B")),
            "B in allowed: {allowed}"
        );
    }

    #[test]
    fn append_reanchor_writes_uuidv7_event_id() {
        let dir = TempDir::new().unwrap();
        let (events_yml, trust_dir) = seed_events(&dir);

        let inputs = ReanchorInputs {
            old_fingerprint: fake_fingerprint("A"),
            new_fingerprint: fake_fingerprint("B"),
            new_public_key: fake_pubkey("B"),
            acknowledge_chain_anchor_lost: false,
        };
        append_bootstrap_reanchor(&events_yml, &trust_dir, &inputs, "test").unwrap();

        let log = load_events_yml(&events_yml).unwrap();
        let reanchor_event = log
            .events
            .iter()
            .find(|e| matches!(e.payload, EventKind::BootstrapReanchor { .. }))
            .expect("must find reanchor event");
        // UUIDv7 has version field = 7; byte 6's high nibble.
        let bytes = reanchor_event.event_id.as_bytes();
        assert_eq!(
            bytes[6] >> 4,
            7,
            "event_id must be UUIDv7, got version {}",
            bytes[6] >> 4
        );
    }
}
