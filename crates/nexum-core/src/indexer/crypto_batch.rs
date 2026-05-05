//! Per-commit crypto resolution for the indexer's local-adapter pass.
//!
//! `verify_and_resolve` runs `git verify-commit` (via the env-scrubbed
//! `--format=%G?%x00%GF` shell-out) and looks up
//! `relevant_trust_events_commit` in one call. The indexer caches the
//! result in a `RefCell<HashMap>` keyed by `commit_sha`, so every unique
//! record commit pays the verify cost exactly once per pass; commits are
//! immutable in git so the cache stays correct across reads.
//!
//! When `<notebook_git>/.trust/historical_signers` is absent (notebook not
//! initialized yet) the helper short-circuits to a `NoSignature` outcome —
//! the local-adapter contract for an uninitialized trust state.

use std::path::Path;

use crate::init::git_ops::{VerifyExit, git_verify_commit_outcome};
use crate::records::types::CryptoResult;
use crate::trust::events::TrustError;
use crate::trust::git_history::git;

/// One commit's resolved crypto state. Cached per `commit_sha` by the
/// indexer's local-pass closure.
#[derive(Debug, Clone)]
pub(crate) struct CryptoOutcome {
    pub crypto_result: CryptoResult,
    pub signer_fingerprint: Option<String>,
    /// SHA of the `.trust/events.yml` commit effective at this record's
    /// commit time. `None` when no events.yml commit precedes the record
    /// (e.g., the record was committed before init, or the notebook has
    /// no events.yml history yet).
    pub relevant_trust_events_commit: Option<String>,
}

impl CryptoOutcome {
    /// Conservative fallback for verify shell-outs that error out (corrupt
    /// git binary, fork ENOMEM, transient FS hiccup). Surfacing
    /// `BadSignature` keeps a possibly-signed record from silently
    /// projecting as `Unsigned` at read time — the spec wants
    /// unrecognized verifier outcomes to land in the `Invalid` bucket so
    /// the warning fires.
    pub(crate) fn bad_signature_fallback() -> Self {
        Self {
            crypto_result: CryptoResult::BadSignature,
            signer_fingerprint: None,
            relevant_trust_events_commit: None,
        }
    }

    /// Outcome for an uninitialized notebook (no `.trust/historical_signers`
    /// on disk). Local records still index but with a no-signature crypto
    /// state.
    pub(crate) fn no_signature() -> Self {
        Self {
            crypto_result: CryptoResult::NoSignature,
            signer_fingerprint: None,
            relevant_trust_events_commit: None,
        }
    }
}

/// Resolve `commit_sha`'s crypto state and the events.yml commit
/// effective at it. Single shell-out for verify (signature status +
/// signer fingerprint) plus one for the events.yml lookup.
///
/// # Errors
///
/// Returns `TrustError::GitCommand` for any verify or events.yml
/// shell-out that exits non-zero, and `TrustError::Io` for spawn
/// failures.
pub(crate) fn verify_and_resolve(
    notebook_git: &Path,
    commit_sha: &str,
) -> Result<CryptoOutcome, TrustError> {
    let historical_signers = notebook_git.join(".trust").join("historical_signers");
    if !historical_signers.exists() {
        return Ok(CryptoOutcome::no_signature());
    }
    let outcome = git_verify_commit_outcome(notebook_git, commit_sha, &historical_signers)
        .map_err(|e| match e {
            // Preserve the io::Error `#[source]` chain instead of
            // collapsing the wrapper's Display string.
            crate::init::InitError::Io { path, source } => TrustError::Io { path, source },
            // Preserve the actual stderr text from the `git` invocation.
            crate::init::InitError::Git { stderr, .. } => {
                TrustError::GitCommand { stderr }
            }
            // Other `InitError` variants don't surface from
            // `git_verify_commit_outcome` (it only returns `Io` or
            // `Git`), but stringify defensively if they ever do.
            other => TrustError::GitCommand {
                stderr: other.to_string(),
            },
        })?;
    let (crypto_result, signer_fingerprint) = match outcome.exit {
        VerifyExit::Good => (CryptoResult::Good, outcome.signer_fingerprint),
        VerifyExit::BadSignature => (CryptoResult::BadSignature, None),
        VerifyExit::UnknownSigner => (CryptoResult::UnknownSigner, None),
        VerifyExit::NoSignature => (CryptoResult::NoSignature, None),
    };
    let relevant_trust_events_commit = relevant_trust_events_commit_at(notebook_git, commit_sha)?;
    Ok(CryptoOutcome {
        crypto_result,
        signer_fingerprint,
        relevant_trust_events_commit,
    })
}

/// Return the SHA of the `.trust/events.yml` commit effective at
/// `record_commit_sha`. Walks `git log -1 --format=%H <record_commit_sha>
/// -- .trust/events.yml`: the latest events.yml commit reachable from the
/// record commit. `None` when no events.yml commit precedes the record.
fn relevant_trust_events_commit_at(
    notebook_git: &Path,
    record_commit_sha: &str,
) -> Result<Option<String>, TrustError> {
    let out = git(notebook_git)
        .args([
            "log",
            "-1",
            "--format=%H",
            record_commit_sha,
            "--",
            ".trust/events.yml",
        ])
        .output()
        .map_err(|e| TrustError::Io {
            path: notebook_git.display().to_string(),
            source: e,
        })?;
    if !out.status.success() {
        return Err(TrustError::GitCommand {
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    let sha = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    Ok(if sha.is_empty() { None } else { Some(sha) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn verify_and_resolve_with_no_historical_signers_returns_no_signature() {
        let dir = tempdir().unwrap();
        let outcome = verify_and_resolve(dir.path(), "abc").expect("ok");
        assert_eq!(outcome.crypto_result, CryptoResult::NoSignature);
        assert!(outcome.signer_fingerprint.is_none());
        assert!(outcome.relevant_trust_events_commit.is_none());
    }
}
