//! Index database schema and indexer-side helpers.
//!
//! `schema::apply(conn)` lands the §7 DDL (post-patch3, with `tags_fts`) onto a
//! fresh `SQLite` connection. `tag_normalization::normalize_tags_for_fts(json)` is the
//! pure function the indexer calls when it writes a record — the §7 "FTS5 tag
//! tokenization quirk" rule from spike S1's finding.

pub mod schema;
pub mod tag_normalization;
