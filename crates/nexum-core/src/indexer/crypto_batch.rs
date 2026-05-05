//! Batched `git verify-commit` pass for local records.
//!
//! The verify shell-out is the expensive bit (~50–200 ms per commit on
//! a warm filesystem). Records collected from `adapter::local::discover`
//! reference some number of unique commits; the batcher dedupes by
//! `commit_sha` and runs verify once per unique sha. Result is stable
//! per commit (commits are immutable) so the cache is correct across
//! arbitrary numbers of subsequent reads.
//!
//! For each commit the batcher also computes the
//! `relevant_trust_events_commit` — the latest `.trust/events.yml`
//! commit reachable from the record commit. This drives the read-time
//! trust-state projection: the verifier asks "what trust state was
//! active when this record was signed?" and the answer is exactly
//! `trust_events.effective_commit = relevant_trust_events_commit`,
//! without depending on global topo position arithmetic.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use crate::init::git_ops::{VerifyExit, git_verify_commit_outcome};
use crate::records::types::CryptoResult;
use crate::trust::events::TrustError;

/// Per-commit cache entry produced by [`run_batch`]. Empty fields are
/// the legitimate result for unsigned / non-verifiable commits — they
/// are not error states.
#[derive(Debug, Clone)]
pub struct BatchEntry {
    /// Cached G/B/U/N outcome, mapped from `git log -1 --format=%G?`.
    pub crypto_result: CryptoResult,
    /// Signer fingerprint captured by `--format=%GF` when the outcome
    /// was Good. `None` otherwise.
    pub signer_fingerprint: Option<String>,
    /// SHA of the `.trust/events.yml` commit effective at this record's
    /// commit time. `None` when no events.yml commit precedes the
    /// record (e.g., the record was committed before init or the
    /// notebook has no events.yml history yet).
    pub relevant_trust_events_commit: Option<String>,
}

/// Output of [`run_batch`]: a deduped map keyed by `commit_sha`.
pub struct CryptoBatch {
    by_commit: HashMap<String, BatchEntry>,
}

impl CryptoBatch {
    /// Look up the cache entry for `commit_sha`. Returns a synthetic
    /// `NoSignature` entry when the sha was not part of the batch input
    /// — callers should not normally hit this path because every
    /// `record_commit_sha` they pass in should produce a populated
    /// entry.
    #[must_use]
    pub fn lookup(&self, commit_sha: &str) -> BatchEntry {
        self.by_commit
            .get(commit_sha)
            .cloned()
            .unwrap_or(BatchEntry {
                crypto_result: CryptoResult::NoSignature,
                signer_fingerprint: None,
                relevant_trust_events_commit: None,
            })
    }

    /// Number of unique commits that produced an entry. Exposed for
    /// tests.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_commit.len()
    }
}

/// Run the batch over `commit_shas`. Deduplicates internally, so
/// callers may pass duplicates. When `notebook_git/.trust/historical_signers`
/// is absent (notebook not initialized yet, or the notebook's trust
/// directory was removed), every entry is filled with `NoSignature` and
/// no shell-outs run.
///
/// # Errors
///
/// Surfaces `TrustError::GitCommand` for any `git verify` / `git log`
/// failure that is not a recognized signature-status return code.
pub fn run_batch(notebook_git: &Path, commit_shas: &[String]) -> Result<CryptoBatch, TrustError> {
    let mut by_commit: HashMap<String, BatchEntry> = HashMap::new();
    let historical_signers = notebook_git.join(".trust").join("historical_signers");
    if !historical_signers.exists() {
        // No notebook-trust state on disk; cache every commit as
        // unsigned. This matches the local-adapter contract: the
        // record might be in git history, but without a signer set the
        // verifier has nothing to check against.
        for sha in commit_shas {
            by_commit.entry(sha.clone()).or_insert(BatchEntry {
                crypto_result: CryptoResult::NoSignature,
                signer_fingerprint: None,
                relevant_trust_events_commit: None,
            });
        }
        return Ok(CryptoBatch { by_commit });
    }
    for sha in commit_shas {
        if by_commit.contains_key(sha) {
            continue;
        }
        let outcome =
            git_verify_commit_outcome(notebook_git, sha, &historical_signers).map_err(|e| {
                TrustError::GitCommand {
                    stderr: format!("{e}"),
                }
            })?;
        let crypto_result = match outcome.exit {
            VerifyExit::Good => CryptoResult::Good,
            VerifyExit::BadSignature => CryptoResult::BadSignature,
            VerifyExit::UnknownSigner => CryptoResult::UnknownSigner,
            VerifyExit::NoSignature => CryptoResult::NoSignature,
        };
        let relevant = relevant_trust_events_commit_at(notebook_git, sha)?;
        by_commit.insert(
            sha.clone(),
            BatchEntry {
                crypto_result,
                signer_fingerprint: outcome.signer_fingerprint,
                relevant_trust_events_commit: relevant,
            },
        );
    }
    Ok(CryptoBatch { by_commit })
}

/// Return the SHA of the `.trust/events.yml` commit effective at
/// `record_commit_sha`. Walks `git log -1 --format=%H <record_commit_sha> --
/// .trust/events.yml`: the latest events.yml commit reachable from the
/// record commit. `None` when no events.yml commit precedes the record.
fn relevant_trust_events_commit_at(
    notebook_git: &Path,
    record_commit_sha: &str,
) -> Result<Option<String>, TrustError> {
    let out = Command::new("git")
        .current_dir(notebook_git)
        .env("GIT_TERMINAL_PROMPT", "0")
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
    fn run_batch_with_no_historical_signers_returns_no_signature_for_all() {
        let dir = tempdir().unwrap();
        let shas = vec!["abc".to_owned(), "def".to_owned()];
        let batch = run_batch(dir.path(), &shas).expect("batch ok");
        assert_eq!(batch.lookup("abc").crypto_result, CryptoResult::NoSignature);
        assert_eq!(batch.lookup("def").crypto_result, CryptoResult::NoSignature);
        assert!(batch.lookup("abc").signer_fingerprint.is_none());
        assert!(batch.lookup("abc").relevant_trust_events_commit.is_none());
    }

    #[test]
    fn run_batch_dedupes_repeated_commit_shas() {
        // Without a real notebook, the no-historical-signers path returns
        // NoSignature for every sha. The dedup property here is
        // structural: by_commit map size equals unique input count.
        let dir = tempdir().unwrap();
        let shas = vec!["abc".to_owned(), "abc".to_owned(), "def".to_owned()];
        let batch = run_batch(dir.path(), &shas).expect("batch ok");
        assert_eq!(batch.len(), 2);
    }
}
