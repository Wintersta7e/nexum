//! `~/.nexum/.reanchor_pending` sentinel detection.
//!
//! When this file exists, every nexum command refuses with
//! `TrustError::ReanchorPending` (exit 8). Detection ships now to surface a
//! clear error if the sentinel is encountered (e.g., importing a
//! `notebook.git` from another machine mid-recovery); the resolution flow
//! itself lives in `nexum doctor --resolve-pending-reanchor`.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::trust::events::TrustError;

/// Reanchor case: the previous bootstrap state when the sentinel was written.
///
/// Wire form is the bare letter (`"A"` / `"B"`); deserialization rejects
/// every other value, routing through the malformed-sentinel branch.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum Case {
    /// Existing pin known; reanchor is rotating from a known-good fingerprint.
    A,
    /// Pin lost or unverifiable; reanchor proceeds without an old fingerprint.
    B,
}

impl Case {
    /// Wire string for this case (`"A"` or `"B"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Case::A => "A",
            Case::B => "B",
        }
    }
}

/// Reanchor phase reached at the moment the sentinel was last written.
///
/// Wire form is `snake_case` (`"init"` / `"events_committed"` / `"pin_updated"`);
/// deserialization rejects every other value.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Sentinel created; no events committed yet.
    Init,
    /// Trust events for the new pin have been committed; pin file not yet rotated.
    EventsCommitted,
    /// New pin file in place; sentinel awaiting cleanup.
    PinUpdated,
}

impl Phase {
    /// Wire string for this phase (`"init"`, `"events_committed"`, or `"pin_updated"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Init => "init",
            Phase::EventsCommitted => "events_committed",
            Phase::PinUpdated => "pin_updated",
        }
    }
}

/// Parsed contents of the `.reanchor_pending` sentinel file.
///
/// `case == Case::B` indicates the previous pin was lost; `old_pin_fp` is
/// `None` in that case. Unknown values for `case` or `phase_completed` fail
/// deserialization, which routes through the malformed-sentinel branch in
/// [`check`].
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReanchorPending {
    case: Case,
    /// Previous bootstrap fingerprint, `None` for case B.
    old_pin_fp: Option<String>,
    /// New bootstrap fingerprint being installed.
    new_pin_fp: String,
    /// New bootstrap public key (SSH `authorized_keys` line).
    #[serde(default)]
    new_pubkey: String,
    /// RFC3339 timestamp when the reanchor was started.
    pub started_at: String,
    /// Optional PID of the process that wrote the sentinel.
    #[serde(default)]
    pub pid: Option<u64>,
    phase_completed: Phase,
    /// The `user.signingkey` value recorded when the sentinel was written.
    /// Used on rollback paths so the keys-recover flow can revert (or
    /// unset, when `None`) the signingkey change.
    #[serde(default)]
    prior_signingkey: Option<String>,
}

impl ReanchorPending {
    /// The phase last durably observed.
    #[must_use]
    pub fn phase_completed(&self) -> Phase {
        self.phase_completed
    }

    #[must_use]
    pub fn case(&self) -> Case {
        self.case
    }

    #[must_use]
    pub fn old_pin_fp(&self) -> Option<&str> {
        self.old_pin_fp.as_deref()
    }

    /// New bootstrap fingerprint being installed.
    #[must_use]
    pub fn new_pin_fp(&self) -> &str {
        &self.new_pin_fp
    }

    /// New bootstrap public key (SSH `authorized_keys` line).
    #[must_use]
    pub fn new_pubkey(&self) -> &str {
        &self.new_pubkey
    }

    /// The `user.signingkey` value recorded when the sentinel was
    /// written. Read on rollback paths so the keys-recover flow can
    /// revert (or unset, when None) the signingkey change.
    #[must_use]
    pub fn prior_signingkey(&self) -> Option<&str> {
        self.prior_signingkey.as_deref()
    }
}

/// Serialize a sentinel to pretty JSON and write it to `home/.reanchor_pending`.
///
/// Shared by [`write_sentinel`] and [`update_sentinel_phase`] so both paths
/// produce identical on-disk shape and surface identical error wrapping.
fn persist_sentinel(home: &Path, sentinel: &ReanchorPending) -> Result<(), TrustError> {
    let json = serde_json::to_string_pretty(sentinel).map_err(|e| TrustError::ReanchorPending {
        message: format!("could not serialize .reanchor_pending: {e}"),
    })?;
    let path = home.join(".reanchor_pending");
    std::fs::write(&path, json).map_err(|e| TrustError::Io {
        path: path.display().to_string(),
        source: e,
    })
}

/// Write a fresh `.reanchor_pending` sentinel with phase Init.
///
/// # Errors
///
/// Returns `TrustError::Io` on write failure, `TrustError::ReanchorPending`
/// on JSON serialization failure.
pub fn write_sentinel(
    home: &Path,
    case: Case,
    old_pin_fp: Option<&str>,
    new_pin_fp: &str,
    new_pubkey: &str,
    prior_signingkey: Option<&str>,
) -> Result<(), TrustError> {
    let sentinel = ReanchorPending {
        case,
        old_pin_fp: old_pin_fp.map(str::to_owned),
        new_pin_fp: new_pin_fp.to_owned(),
        new_pubkey: new_pubkey.to_owned(),
        started_at: chrono::Utc::now().to_rfc3339(),
        pid: Some(u64::from(std::process::id())),
        phase_completed: Phase::Init,
        prior_signingkey: prior_signingkey.map(str::to_owned),
    };
    persist_sentinel(home, &sentinel)
}

/// Update the `phase_completed` field of an existing sentinel.
///
/// # Errors
///
/// `TrustError::ReanchorPending` if the sentinel is missing or
/// malformed.
pub fn update_sentinel_phase(home: &Path, new_phase: Phase) -> Result<(), TrustError> {
    let Some(mut sentinel) = read_sentinel(home)? else {
        return Err(TrustError::ReanchorPending {
            message: format!(
                ".reanchor_pending missing when attempting phase update to {}",
                new_phase.as_str()
            ),
        });
    };
    sentinel.phase_completed = new_phase;
    persist_sentinel(home, &sentinel)
}

/// Returns `Ok(())` when no `.reanchor_pending` sentinel is present.
///
/// # Errors
///
/// - `TrustError::Io` when the sentinel exists but cannot be read.
/// - `TrustError::ReanchorPending` when the sentinel exists, including the
///   case where it is malformed (callers must refuse to proceed either way).
pub(crate) fn check(home: &Path) -> Result<(), TrustError> {
    let path = home.join(".reanchor_pending");
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(TrustError::Io {
                path: path.display().to_string(),
                source: e,
            });
        }
    };
    let parsed: ReanchorPending =
        serde_json::from_str(&raw).map_err(|e| TrustError::ReanchorPending {
            message: format!(
                ".reanchor_pending exists but is malformed: {e}. \
                 Resolution requires the recovery flow \
                 (`nexum doctor --resolve-pending-reanchor`). \
                 If you know the reanchor was abandoned, delete .reanchor_pending."
            ),
        })?;

    Err(TrustError::ReanchorPending {
        message: format!(
            "Pending reanchor detected (case {}, phase {}). \
             Resolution requires the recovery flow \
             (`nexum doctor --resolve-pending-reanchor`). \
             Either upgrade the binary, or delete .reanchor_pending if the reanchor was abandoned.",
            parsed.case.as_str(),
            parsed.phase_completed.as_str(),
        ),
    })
}

/// Read and parse the `.reanchor_pending` sentinel, returning `None` when
/// absent.
///
/// # Errors
///
/// - `TrustError::Io` when the file exists but cannot be read.
/// - `TrustError::ReanchorPending` when the file is malformed JSON (callers
///   that encounter a malformed sentinel must still refuse to proceed).
pub fn read_sentinel(home: &Path) -> Result<Option<ReanchorPending>, TrustError> {
    let path = home.join(".reanchor_pending");
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(TrustError::Io {
                path: path.display().to_string(),
                source: e,
            });
        }
    };
    let parsed: ReanchorPending =
        serde_json::from_str(&raw).map_err(|e| TrustError::ReanchorPending {
            message: format!(".reanchor_pending is malformed: {e}"),
        })?;
    Ok(Some(parsed))
}

/// Delete the `.reanchor_pending` sentinel. Idempotent: returns `Ok(())` when
/// the file does not exist.
///
/// # Errors
///
/// Returns `TrustError::Io` when deletion fails for any reason other than the
/// file being absent.
pub fn delete_sentinel(home: &Path) -> Result<(), TrustError> {
    let path = home.join(".reanchor_pending");
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(TrustError::Io {
            path: path.display().to_string(),
            source: e,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{TrustError, check};
    use std::path::Path;
    use tempfile::tempdir;

    fn write(home: &Path, name: &str, body: &str) {
        std::fs::write(home.join(name), body).unwrap();
    }

    #[test]
    fn check_returns_ok_when_sentinel_absent() {
        let dir = tempdir().unwrap();
        assert!(check(dir.path()).is_ok());
    }

    #[test]
    fn check_returns_reanchor_pending_when_sentinel_present_phase_init() {
        let dir = tempdir().unwrap();
        write(
            dir.path(),
            ".reanchor_pending",
            r#"{
                "case": "A",
                "old_pin_fp": "SHA256:abc",
                "new_pin_fp": "SHA256:def",
                "new_pubkey": "ssh-ed25519 BBBB",
                "started_at": "2026-05-04T12:00:00Z",
                "pid": 12345,
                "phase_completed": "init"
            }"#,
        );
        let err = check(dir.path()).unwrap_err();
        match err {
            TrustError::ReanchorPending { message } => {
                assert!(message.contains("case A"));
                assert!(message.contains("phase init"));
                assert!(message.contains("nexum doctor --resolve-pending-reanchor"));
            }
            other => panic!("expected ReanchorPending, got {other:?}"),
        }
    }

    #[test]
    fn check_returns_reanchor_pending_when_sentinel_malformed() {
        let dir = tempdir().unwrap();
        write(dir.path(), ".reanchor_pending", "{ bad json");
        let err = check(dir.path()).unwrap_err();
        match err {
            TrustError::ReanchorPending { message } => {
                assert!(message.contains("malformed"));
            }
            other => panic!("expected ReanchorPending, got {other:?}"),
        }
    }

    #[test]
    fn check_returns_reanchor_pending_for_case_b() {
        let dir = tempdir().unwrap();
        write(
            dir.path(),
            ".reanchor_pending",
            r#"{
                "case": "B",
                "old_pin_fp": null,
                "new_pin_fp": "SHA256:def",
                "started_at": "2026-05-04T12:00:00Z",
                "phase_completed": "events_committed"
            }"#,
        );
        let err = check(dir.path()).unwrap_err();
        match err {
            TrustError::ReanchorPending { message } => {
                assert!(message.contains("case B"));
                assert!(message.contains("phase events_committed"));
            }
            other => panic!("expected ReanchorPending, got {other:?}"),
        }
    }

    #[test]
    fn check_returns_reanchor_pending_when_sentinel_empty() {
        let dir = tempdir().unwrap();
        write(dir.path(), ".reanchor_pending", "");
        let err = check(dir.path()).unwrap_err();
        match err {
            TrustError::ReanchorPending { message } => {
                assert!(message.contains("malformed"));
            }
            other => panic!("expected ReanchorPending, got {other:?}"),
        }
    }

    #[test]
    fn check_returns_reanchor_pending_for_unknown_case() {
        let dir = tempdir().unwrap();
        write(
            dir.path(),
            ".reanchor_pending",
            r#"{
                "case": "C",
                "old_pin_fp": "SHA256:abc",
                "new_pin_fp": "SHA256:def",
                "started_at": "2026-05-04T12:00:00Z",
                "phase_completed": "init"
            }"#,
        );
        let err = check(dir.path()).unwrap_err();
        match err {
            TrustError::ReanchorPending { message } => {
                assert!(message.contains("malformed"));
            }
            other => panic!("expected ReanchorPending, got {other:?}"),
        }
    }

    #[test]
    fn check_returns_reanchor_pending_for_unknown_phase() {
        let dir = tempdir().unwrap();
        write(
            dir.path(),
            ".reanchor_pending",
            r#"{
                "case": "A",
                "old_pin_fp": "SHA256:abc",
                "new_pin_fp": "SHA256:def",
                "started_at": "2026-05-04T12:00:00Z",
                "phase_completed": "rolled_back"
            }"#,
        );
        let err = check(dir.path()).unwrap_err();
        match err {
            TrustError::ReanchorPending { message } => {
                assert!(message.contains("malformed"));
            }
            other => panic!("expected ReanchorPending, got {other:?}"),
        }
    }

    #[test]
    fn write_sentinel_round_trips_with_prior_signingkey() {
        use super::{Case, Phase, read_sentinel, write_sentinel};
        let dir = tempdir().unwrap();
        write_sentinel(
            dir.path(),
            Case::A,
            Some("SHA256:old"),
            "SHA256:new",
            "ssh-ed25519 AAAA test",
            Some("/home/user/.ssh/id_ed25519"),
        )
        .unwrap();
        let s = read_sentinel(dir.path()).unwrap().unwrap();
        assert_eq!(s.phase_completed(), Phase::Init);
        assert_eq!(s.case(), Case::A);
        assert_eq!(s.old_pin_fp(), Some("SHA256:old"));
        assert_eq!(s.new_pin_fp(), "SHA256:new");
        assert_eq!(
            s.prior_signingkey(),
            Some("/home/user/.ssh/id_ed25519"),
            "prior_signingkey must survive round-trip"
        );
    }

    #[test]
    fn update_sentinel_phase_advances_then_back() {
        use super::{Case, Phase, read_sentinel, update_sentinel_phase, write_sentinel};
        let dir = tempdir().unwrap();
        write_sentinel(
            dir.path(),
            Case::B,
            None,
            "SHA256:fp",
            "ssh-ed25519 BBBB test",
            None,
        )
        .unwrap();

        // Advance to EventsCommitted.
        update_sentinel_phase(dir.path(), Phase::EventsCommitted).unwrap();
        assert_eq!(
            read_sentinel(dir.path())
                .unwrap()
                .unwrap()
                .phase_completed(),
            Phase::EventsCommitted
        );

        // Advance to PinUpdated.
        update_sentinel_phase(dir.path(), Phase::PinUpdated).unwrap();
        assert_eq!(
            read_sentinel(dir.path())
                .unwrap()
                .unwrap()
                .phase_completed(),
            Phase::PinUpdated
        );
    }
}
