//! Query layer — FTS-only `search`, plus `get` / `list` / `recent` /
//! `by_session` against `index.db`.

pub mod by_session;
pub mod get;
pub mod list;
pub mod recent;
pub mod search;
pub mod types;

pub use search::{SearchOpts, search};
pub use types::{
    Cursor, Filters, Meta, MetaSourceCounts, MetaTrustBasisSummary, MetaTrustSummary, QueryError,
    ResultSet, SearchResult,
};
// Uncommented when each downstream task lands its identifiers:
// pub use by_session::{SessionLookup, by_session};
// pub use get::{GetOpts, get};
// pub use list::list;
// pub use recent::recent;
