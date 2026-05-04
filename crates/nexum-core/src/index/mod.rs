//! Index database schema and indexer-side helpers.
//!
//! `schema::apply(conn)` lands the DDL (including the `tags_fts` column) onto a
//! fresh `SQLite` connection. `tag_normalization::normalize_tags_for_fts(json)` is the
//! pure function the indexer calls when it writes a record — it applies the FTS5
//! tokenization rule for tags so multi-character punctuation (e.g., hyphens, dots)
//! survives indexing intact.

pub mod meta;
pub mod schema;
pub mod tag_normalization;
