//! Query layer — FTS-only `search`, plus `get` / `list` / `recent` /
//! `by_session` against `index.db`.

pub mod by_session;

use crate::records::{SignatureStatus, TrustBasis};

/// Resolve `trust_basis` for a row: prefer the persisted column value;
/// fall back to `Current` iff the row is `Verified`. Rows written before
/// the verifier-provenance column existed, or by adapters that do not
/// track basis, land here and get the correct default without any
/// special-case logic at each call site.
pub(crate) fn resolve_trust_basis(
    persisted: Option<&str>,
    sig: SignatureStatus,
) -> Option<TrustBasis> {
    persisted.map(TrustBasis::from_db_str).or_else(|| {
        if sig == SignatureStatus::Verified {
            Some(TrustBasis::Current)
        } else {
            None
        }
    })
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
