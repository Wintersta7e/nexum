//! Read-time trust projection — implements the verifier's state-machine
//! projection (steps 5-6 of the `verify_record` pseudocode) on top of the
//! cached crypto-only outcome captured at index time.
//!
//! The crypto check (steps 1-4) ran at index time and is cached per record
//! in `crypto_result` + `signer_fingerprint`. This module reads that cache
//! and joins it with the materialized `trust_events` view to produce the
//! API contract: `signature_status`, `trust_basis`, `warnings`.

use crate::records::{CryptoResult, SignatureStatus, TrustBasis};
use crate::trust::chain_state::{ChainState, ReanchorCase, TrustState};
use crate::trust::events::TrustError;
use crate::trust::events_view::TrustEventsView;

/// Read-time projection of a record's trust shape. Carries the API
/// contract's three pieces: status, basis, and the per-row warning codes
/// from the canonical taxonomy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedTrust {
    pub signature_status: SignatureStatus,
    pub trust_basis: Option<TrustBasis>,
    pub warnings: Vec<String>,
}

impl ProjectedTrust {
    /// Project an unsigned record (cc-native, codex-native, or local
    /// without signature). Carries the canonical `unsigned` warning so
    /// downstream policy can surface it without re-deriving from status.
    fn unsigned() -> Self {
        Self {
            signature_status: SignatureStatus::Unsigned,
            trust_basis: None,
            warnings: vec!["unsigned".into()],
        }
    }

    /// Project an invalid record with no associated trust basis. `codes`
    /// are the canonical warnings that explain why the record is invalid
    /// (e.g. `["bad-signature"]`, `["unknown-signature"]`,
    /// `["broken-trust-chain"]`).
    fn invalid(codes: &[&str]) -> Self {
        Self {
            signature_status: SignatureStatus::Invalid,
            trust_basis: None,
            warnings: codes.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    /// Project an invalid record that retains a trust basis (e.g. a
    /// strict-revocation hit on a compromised key, or a Case-B
    /// pre-reanchor record).
    fn invalid_with_basis(basis: TrustBasis, codes: &[&str]) -> Self {
        Self {
            signature_status: SignatureStatus::Invalid,
            trust_basis: Some(basis),
            warnings: codes.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    /// Project a verified record. `codes` are informational warnings the
    /// verifier surfaces alongside an otherwise-trusted record (e.g.
    /// `["signer-key-rotated"]`).
    fn verified(basis: TrustBasis, codes: &[&str]) -> Self {
        Self {
            signature_status: SignatureStatus::Verified,
            trust_basis: Some(basis),
            warnings: codes.iter().map(|s| (*s).to_string()).collect(),
        }
    }
}

/// Per-record cached crypto state read straight from the `records` table.
/// The verb-side row reader populates this for every row before delegating
/// to [`project_trust`].
#[derive(Debug, Clone, Copy)]
pub struct CachedCrypto<'a> {
    /// SHA of the record's last-touching commit. Forwarded onto the
    /// projected `record_commit_sha` field; the projection itself does
    /// not consult it directly.
    pub commit_sha: Option<&'a str>,
    /// Signing key fingerprint extracted from `git verify-commit`. `None`
    /// for records whose `crypto_result` is anything other than `Good`.
    pub signer_fingerprint: Option<&'a str>,
    /// Cached `git verify-commit` outcome. Drives the steps-1-4 dispatch.
    pub crypto_result: CryptoResult,
    /// SHA of the `.trust/events.yml` commit effective at the record's
    /// commit time. Used as the lookup key for both the tampering
    /// precondition and the state-machine `topo_pos_of` resolution.
    /// `None` for adapters with no events.yml correlation (cc-native,
    /// codex-native).
    pub relevant_trust_events_commit: Option<&'a str>,
}

/// Project a record's cached crypto state plus the materialized chain into
/// the API contract (`signature_status`, `trust_basis`, `warnings`).
///
/// Decision tree:
/// 1. Tampering precondition — if the record's events.yml commit is at or
///    before any tampering row, force Invalid + `["broken-trust-chain",
///    "event-tampered"]`.
/// 2. Crypto-only outcomes — `NoSignature` -> Unsigned;
///    `BadSignature` -> Invalid + `["bad-signature"]`;
///    `UnknownSigner` -> Invalid + `["unknown-signature"]`.
/// 3. State-machine projection (only for `Good` crypto) — read the trust
///    state from [`ChainState::state_of`] at the events.yml topo position
///    effective at the record's commit and map to the canonical
///    `(SignatureStatus, TrustBasis, warnings)` triple.
///
/// `strict_revocation` flips the compromised-key branch from Verified
/// (default) to Invalid. The Case-A vs Case-B pre-reanchor branches read
/// from the persisted `chain_anchor_lost` column and are independent of
/// `strict_revocation`.
///
/// # Errors
///
/// Returns `TrustError::Sqlite` if the tampering or topo-position lookup
/// fails (other than missing rows, which are handled in-band).
pub fn project_trust(
    cached: CachedCrypto<'_>,
    view: &TrustEventsView<'_>,
    chain: &ChainState,
    strict_revocation: bool,
) -> Result<ProjectedTrust, TrustError> {
    let trust_commit = cached.relevant_trust_events_commit;

    // Step 0: tampering precondition. If the record's events.yml commit
    // is at-or-before any tampering row, force Invalid regardless of
    // crypto_result.
    if let Some(c) = trust_commit
        && view.has_tampering_at_or_before(c)?
    {
        return Ok(ProjectedTrust::invalid(&[
            "broken-trust-chain",
            "event-tampered",
        ]));
    }

    // Steps 1-4: cached-crypto-only outcomes.
    match cached.crypto_result {
        CryptoResult::NoSignature => return Ok(ProjectedTrust::unsigned()),
        CryptoResult::BadSignature => {
            return Ok(ProjectedTrust::invalid(&["bad-signature"]));
        }
        CryptoResult::UnknownSigner => {
            return Ok(ProjectedTrust::invalid(&["unknown-signature"]));
        }
        CryptoResult::Good => {}
    }

    // Steps 5-6: state-machine projection. Look up the events.yml commit's
    // topological position; that's the trust state effective when the
    // record was signed.
    let signer_fp = cached.signer_fingerprint.unwrap_or("");
    let Some(topo_pos) = trust_commit
        .map(|c| view.topo_pos_of(c))
        .transpose()?
        .flatten()
    else {
        // No events.yml commit reachable from this record (or commit not
        // recorded by the materializer). Conservative: Invalid +
        // broken-trust-chain.
        return Ok(ProjectedTrust::invalid(&["broken-trust-chain"]));
    };

    Ok(match chain.state_of(signer_fp, topo_pos) {
        TrustState::TrustedNow => ProjectedTrust::verified(TrustBasis::Current, &[]),
        TrustState::Rotated => {
            ProjectedTrust::verified(TrustBasis::RotatedHistorical, &["signer-key-rotated"])
        }
        TrustState::Compromised if !strict_revocation => ProjectedTrust::verified(
            TrustBasis::RotatedHistoricalCompromised,
            &["signed-by-compromised-key"],
        ),
        TrustState::Compromised => {
            ProjectedTrust::invalid(&["signed-by-compromised-key", "strict-revocation-active"])
        }
        TrustState::PreReanchor {
            case: ReanchorCase::A,
        } => ProjectedTrust::verified(TrustBasis::PreReanchor, &["pre-recovery-record"]),
        TrustState::PreReanchor {
            case: ReanchorCase::B,
        } => ProjectedTrust::invalid_with_basis(
            TrustBasis::PreReanchor,
            &["chain-anchor-lost", "pre-recovery-record"],
        ),
        TrustState::NotYetTrustedAtCommit => {
            ProjectedTrust::invalid(&["key-not-yet-trusted-at-commit"])
        }
        TrustState::BrokenChain => ProjectedTrust::invalid(&["broken-trust-chain"]),
    })
}
