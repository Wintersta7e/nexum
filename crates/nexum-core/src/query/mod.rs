//! Query layer — FTS-only `search`, plus `get` / `list` / `recent` /
//! `by_session` against `index.db`.

pub mod by_session;

use crate::records::{CryptoResult, SignatureStatus, TrustBasis};

/// Map a `CryptoResult` (the cached `git verify-commit` outcome) to the
/// API-facing `SignatureStatus`. The mapping is direct: `Good` -> `Verified`,
/// `BadSignature` / `UnknownSigner` -> `Invalid`, `NoSignature` -> `Unsigned`.
///
/// This is the read-side counterpart of the indexer's
/// `CryptoResult::as_db_str` write. The full read-time verifier projection
/// (which consults `trust_events`) lands later; until then the projected
/// status is a function of `crypto_result` alone, and this helper centralizes
/// the mapping.
pub(crate) fn signature_status_for(crypto_result: CryptoResult) -> SignatureStatus {
    match crypto_result {
        CryptoResult::Good => SignatureStatus::Verified,
        CryptoResult::NoSignature => SignatureStatus::Unsigned,
        CryptoResult::BadSignature | CryptoResult::UnknownSigner => SignatureStatus::Invalid,
    }
}

/// Map a `CryptoResult` to an `Option<TrustBasis>` for the read-time
/// projection. In the bootstrap-only world (no rotation / reanchor / tampering
/// events yet), only `Good` produces a basis (`Current`); everything else
/// maps to `None`. The full projection that consults `trust_events` lands
/// later.
pub(crate) fn trust_basis_for(crypto_result: CryptoResult) -> Option<TrustBasis> {
    match crypto_result {
        CryptoResult::Good => Some(TrustBasis::Current),
        CryptoResult::BadSignature | CryptoResult::UnknownSigner | CryptoResult::NoSignature => {
            None
        }
    }
}

/// Bootstrap-only projection of a `CryptoResult` into the read-time trust
/// shape: the API-facing `SignatureStatus`, the `Option<TrustBasis>` (only
/// `Good` produces `Current`; everything else is `None`), and the per-row
/// warnings vector (always empty until the read-time verifier projection
/// consults `trust_events`).
///
/// Returning the three pieces together centralizes the projection so each
/// query verb folds them in one call rather than duplicating the
/// `signature_status_for` / `trust_basis_for` / empty-warnings trio at
/// every projection site. The empty `Vec::new()` does not allocate
/// (capacity 0) — adding the slot up-front keeps the helper's shape stable
/// when the verifier projection starts populating warnings.
pub(crate) fn project_trust(
    crypto_result: CryptoResult,
) -> (SignatureStatus, Option<TrustBasis>, Vec<String>) {
    (
        signature_status_for(crypto_result),
        trust_basis_for(crypto_result),
        Vec::new(),
    )
}

pub mod get;
pub mod list;
pub(crate) mod meta;
pub mod recent;
pub mod search;
#[cfg(test)]
pub(crate) mod test_util;
pub mod types;

pub use by_session::{SessionLookup, by_session};
pub use get::{GetOpts, get};
pub use list::list;
pub use recent::recent;
pub use search::{SearchOpts, search};
pub use types::{
    Cursor, Filters, Meta, MetaSourceCounts, MetaTrustBasisSummary, MetaTrustSummary, QueryError,
    ResultSet, SearchResult,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_status_for_maps_all_crypto_results() {
        assert_eq!(
            signature_status_for(CryptoResult::Good),
            SignatureStatus::Verified
        );
        assert_eq!(
            signature_status_for(CryptoResult::NoSignature),
            SignatureStatus::Unsigned
        );
        assert_eq!(
            signature_status_for(CryptoResult::BadSignature),
            SignatureStatus::Invalid
        );
        assert_eq!(
            signature_status_for(CryptoResult::UnknownSigner),
            SignatureStatus::Invalid
        );
    }

    #[test]
    fn trust_basis_for_only_good_yields_basis() {
        assert_eq!(
            trust_basis_for(CryptoResult::Good),
            Some(TrustBasis::Current)
        );
        assert_eq!(trust_basis_for(CryptoResult::NoSignature), None);
        assert_eq!(trust_basis_for(CryptoResult::BadSignature), None);
        assert_eq!(trust_basis_for(CryptoResult::UnknownSigner), None);
    }

    #[test]
    fn project_trust_returns_aligned_triple() {
        for (input, want_status, want_basis) in [
            (
                CryptoResult::Good,
                SignatureStatus::Verified,
                Some(TrustBasis::Current),
            ),
            (CryptoResult::NoSignature, SignatureStatus::Unsigned, None),
            (CryptoResult::BadSignature, SignatureStatus::Invalid, None),
            (CryptoResult::UnknownSigner, SignatureStatus::Invalid, None),
        ] {
            let (status, basis, warnings) = project_trust(input);
            assert_eq!(status, want_status, "status for {input:?}");
            assert_eq!(basis, want_basis, "basis for {input:?}");
            assert!(warnings.is_empty(), "warnings for {input:?}");
        }
    }
}
