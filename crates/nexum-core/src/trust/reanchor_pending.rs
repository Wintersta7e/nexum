//! `~/.nexum/.reanchor_pending` sentinel detection.
//!
//! When this file exists, every nexum command refuses with
//! `TrustError::ReanchorPending` (exit 8). Detection ships now to surface a
//! clear error if the sentinel is encountered (e.g., importing a
//! `notebook.git` from another machine mid-recovery); the resolution flow
//! itself lives in `nexum doctor --resolve-pending-reanchor`.

use std::path::Path;

use serde::Deserialize;

use crate::trust::events::TrustError;

/// Reanchor case: the previous bootstrap state when the sentinel was written.
///
/// Wire form is the bare letter (`"A"` / `"B"`); deserialization rejects
/// every other value, routing through the malformed-sentinel branch.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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
}

impl ReanchorPending {
    /// The phase at which the reanchor was last checkpointed.
    #[must_use]
    pub fn phase_completed(&self) -> Phase {
        self.phase_completed
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
}
