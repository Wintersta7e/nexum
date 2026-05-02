//! Query layer — FTS-only `search`, plus `get` / `list` / `recent` /
//! `by_session` against `index.db`. The vector branch of §7 hybrid ranking
//! lands in a later phase; Phase 3 ranks via FTS bm25 + the unsigned penalty.

pub mod by_session;
pub mod get;
pub mod list;
pub mod recent;
pub mod search;
pub mod types;

// Uncommented when each downstream task lands its identifiers:
// pub use by_session::{SessionLookup, by_session};
// pub use get::{GetOpts, get};
// pub use list::list;
// pub use recent::recent;
// pub use search::{SearchOpts, search};
// pub use types::{
//     Cursor, Filters, Meta, MetaSourceCounts, MetaTrustSummary, MetaTrustBasisSummary,
//     QueryError, ResultSet, SearchResult,
// };
