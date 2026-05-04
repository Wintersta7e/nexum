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
