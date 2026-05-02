//! `content_hash` — sha256 over the normalized `title|summary|body` triple.
//!
//! The indexer in `crate::indexer::run` compares this hash against the cached
//! `records.content_hash` column to decide between upsert and skip per the
//! reindex algorithm. A `RecordSummary` is the `(id, content_hash)` tuple that
//! `AdapterPass.records` carries — adapters return one per record without
//! re-reading bodies on every list pass.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::types::{ContentHash, RecordId};

/// Deterministic sha256 of `title`, `summary` (or empty), and `body`, joined
/// with `\n`. Output is lowercase hex (64 chars).
#[must_use]
pub fn content_hash(title: &str, summary: Option<&str>, body: &str) -> ContentHash {
    let summary = summary.unwrap_or("");
    let mut hasher = Sha256::new();
    hasher.update(title.as_bytes());
    hasher.update(b"\n");
    hasher.update(summary.as_bytes());
    hasher.update(b"\n");
    hasher.update(body.as_bytes());
    let bytes = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// `(id, content_hash)` tuple — the lightweight row `AdapterPass.records`
/// carries. The indexer joins these against the cached `records` table to
/// compute the new / changed / gone sets per the reindex algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordSummary {
    pub id: RecordId,
    pub content_hash: ContentHash,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_summary_is_treated_as_empty_string() {
        let with_none = content_hash("t", None, "b");
        let with_empty = content_hash("t", Some(""), "b");
        assert_eq!(with_none, with_empty);
    }

    #[test]
    fn output_is_64_lowercase_hex_chars() {
        let h = content_hash("t", Some("s"), "b");
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn deterministic_for_same_input() {
        let a = content_hash("hello", Some("world"), "body");
        let b = content_hash("hello", Some("world"), "body");
        assert_eq!(a, b);
    }

    #[test]
    fn differs_on_title_change() {
        let a = content_hash("hello", Some("s"), "b");
        let b = content_hash("HELLO", Some("s"), "b");
        assert_ne!(a, b);
    }

    #[test]
    fn differs_on_summary_change() {
        let a = content_hash("t", Some("alpha"), "b");
        let b = content_hash("t", Some("beta"), "b");
        assert_ne!(a, b);
    }

    #[test]
    fn differs_on_body_change() {
        let a = content_hash("t", Some("s"), "b1");
        let b = content_hash("t", Some("s"), "b2");
        assert_ne!(a, b);
    }

    #[test]
    fn distinguishes_concat_collisions_via_separator() {
        // Without a separator, ("abc","","de") and ("ab","c","de") would
        // collide on the concatenation. With `\n` separators they don't.
        let a = content_hash("abc", Some(""), "de");
        let b = content_hash("ab", Some("c"), "de");
        assert_ne!(a, b);
    }

    #[test]
    fn record_summary_round_trips_via_serde_json() {
        let s = RecordSummary {
            id: "rec-1".into(),
            content_hash: "deadbeef".into(),
        };
        let j = serde_json::to_string(&s).unwrap();
        let back: RecordSummary = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }
}
