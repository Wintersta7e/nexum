//! Project events.yml into the three derived OpenSSH-format signer files.

use std::path::Path;

use super::events::TrustError;

/// Outcome of `regenerate_files`.
#[derive(Debug, Clone, PartialEq)]
pub enum RegenerateOutcome {
    /// All files were already consistent; nothing written.
    NoChange,
    /// One or more files were written.
    Updated { files: Vec<&'static str> },
}

/// Regenerate `historical_signers`, `allowed_signers`, and `revoked_signers`
/// from `events_yml_path`.
///
/// Full implementation in Task 7.
///
/// # Errors
///
/// Returns `TrustError` variants on I/O or parse failure.
pub fn regenerate_files(
    events_yml_path: &Path,
    trust_dir: &Path,
) -> Result<RegenerateOutcome, TrustError> {
    let _ = (events_yml_path, trust_dir);
    unimplemented!("regenerate_files — Task 7")
}
