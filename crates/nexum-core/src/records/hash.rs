//! `content_hash` — sha256 over the normalized `title|summary|body` triple.
//!
//! The indexer in `crate::indexer::run` compares this hash against the cached
//! `records.content_hash` column to decide between upsert and skip per the
//! reindex algorithm. A `RecordSummary` is the `(id, content_hash)` tuple that
//! `AdapterPass.records` carries — adapters return one per record without
//! re-reading bodies on every list pass.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::types::{ContentHash, RecordId, UnifiedRecord};

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

/// Hash over every load-bearing field stored by the indexer.
/// Stable serialization (tags sorted; JSON for list/map fields) so the same
/// field set produces an identical hash across runs.
///
/// Distinct from [`content_hash`], which covers only (title, summary, body)
/// for the user-visible "did the content change" signal.  The indexer's
/// "unchanged, skip upsert" path requires BOTH hashes to match.
///
/// # Panics
/// Panics if `serde_json::to_string` fails on `session_refs`, `commits`,
/// `files`, or any value in `extras`. Every variant in the involved types
/// derives `Serialize` over JSON-safe primitives, so the panic is
/// effectively unreachable; the `expect` calls document the invariant.
#[must_use]
pub fn compute_index_hash(r: &UnifiedRecord) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"v1\x00"); // version prefix; bump when the field set changes
    hasher.update(r.id.as_bytes());
    hasher.update(b"\x00");
    hasher.update(r.record_type.as_db_str().as_bytes());
    hasher.update(b"\x00");
    hasher.update(r.title.as_bytes());
    hasher.update(b"\x00");
    hasher.update(r.summary.as_deref().unwrap_or("").as_bytes());
    hasher.update(b"\x00");
    hasher.update(r.body.as_bytes());
    hasher.update(b"\x00");
    hasher.update(r.source.as_db_str().as_bytes());
    hasher.update(b"\x00");
    hasher.update(r.project_id.as_bytes());
    hasher.update(b"\x00");
    hasher.update(r.agent.as_db_str().as_bytes());
    hasher.update(b"\x00");
    hasher.update(r.confidence.as_db_str().as_bytes());
    hasher.update(b"\x00");
    hasher.update(r.outcome.as_db_str().as_bytes());
    hasher.update(b"\x00");
    hasher.update(r.provenance.signature_status.as_db_str().as_bytes());
    hasher.update(b"\x00");
    // Tags are sorted so insertion order doesn't affect the hash.
    // Collect &str references to avoid cloning the owned strings for sorting.
    let mut tag_refs: Vec<&str> = r.tags.iter().map(String::as_str).collect();
    tag_refs.sort_unstable();
    for tag in &tag_refs {
        hasher.update(tag.as_bytes());
        hasher.update(b"\x01");
    }
    hasher.update(b"\x00");
    // Lists serialized as JSON for deterministic encoding of nested types.
    let session_refs_json =
        serde_json::to_string(&r.session_refs).expect("session_refs is serializable");
    hasher.update(session_refs_json.as_bytes());
    hasher.update(b"\x00");
    let commits_json = serde_json::to_string(&r.commits).expect("commits serializable");
    hasher.update(commits_json.as_bytes());
    hasher.update(b"\x00");
    let files_json = serde_json::to_string(&r.files).expect("files serializable");
    hasher.update(files_json.as_bytes());
    hasher.update(b"\x00");
    // extras: top-level keys sorted so map iteration order doesn't matter.
    let mut extra_keys: Vec<&String> = r.extras.keys().collect();
    extra_keys.sort();
    for k in extra_keys {
        hasher.update(k.as_bytes());
        hasher.update(b"\x02");
        let v = serde_json::to_string(&r.extras[k]).expect("extra value serializable");
        hasher.update(v.as_bytes());
        hasher.update(b"\x03");
    }
    hasher.update(b"\x00");
    hasher.update(r.updated.to_rfc3339().as_bytes());
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
///
/// The summary deliberately omits `project_id`: adapters cannot always
/// resolve it without doing the read-full work (e.g., Codex resolves it
/// from the threads index in `build_record`). The composite identity is
/// still enforced at upsert / delete time via the records-table
/// `UNIQUE (source, project_id, id)` and the `read_full` `project_id` is
/// authoritative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordSummary {
    pub id: RecordId,
    pub content_hash: ContentHash,
}

#[cfg(test)]
mod index_hash_tests {
    use super::*;
    use crate::records::types::{
        Agent, Confidence, FileEvidence, FileEvidenceKind, Outcome, Provenance, RecordType,
        SessionRef, SignatureStatus, Source, UnifiedRecord,
    };
    use std::path::PathBuf;

    fn make_record_with_tags(tags: Vec<&str>) -> UnifiedRecord {
        let ch = content_hash("t", None, "b");
        UnifiedRecord {
            id: "x".into(),
            record_type: RecordType::Failure,
            source: Source::Local,
            project_id: "git:abc".into(),
            title: "t".into(),
            summary: None,
            body: "b".into(),
            body_origin_path: None,
            tags: tags.into_iter().map(str::to_owned).collect(),
            agent: Agent::Manual,
            session_refs: vec![SessionRef::Manual],
            files: vec![],
            commits: vec![],
            created: chrono::DateTime::parse_from_rfc3339("2026-05-04T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            updated: chrono::DateTime::parse_from_rfc3339("2026-05-04T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            confidence: Confidence::Medium,
            outcome: Outcome::Attempted,
            provenance: Provenance {
                source: Source::Local,
                signature_status: SignatureStatus::Unsigned,
                trust_basis: None,
                extractor: None,
                digest_hash: None,
                record_commit_sha: None,
                signer_fingerprint: None,
                warning_code: None,
            },
            extras: std::collections::HashMap::new(),
            content_hash: ch,
        }
    }

    fn make_file_evidence(path: &str) -> FileEvidence {
        FileEvidence {
            path: PathBuf::from(path),
            kind: FileEvidenceKind::ParsedFromMemoryBody,
        }
    }

    #[test]
    fn index_hash_changes_when_tags_change() {
        let r1 = make_record_with_tags(vec!["a", "b"]);
        let r2 = make_record_with_tags(vec!["a", "b", "c"]);
        assert_ne!(compute_index_hash(&r1), compute_index_hash(&r2));
    }

    #[test]
    fn index_hash_stable_for_same_record() {
        let r = make_record_with_tags(vec!["x", "y"]);
        assert_eq!(compute_index_hash(&r), compute_index_hash(&r));
    }

    #[test]
    fn index_hash_changes_when_signature_status_changes() {
        let mut r = make_record_with_tags(vec!["a"]);
        let h1 = compute_index_hash(&r);
        r.provenance.signature_status = SignatureStatus::Verified;
        let h2 = compute_index_hash(&r);
        assert_ne!(h1, h2);
    }

    #[test]
    fn index_hash_changes_when_outcome_changes() {
        let mut r = make_record_with_tags(vec!["a"]);
        let h1 = compute_index_hash(&r);
        r.outcome = Outcome::NotApplicable;
        let h2 = compute_index_hash(&r);
        assert_ne!(h1, h2);
    }

    #[test]
    fn index_hash_independent_of_content_hash() {
        // Different tags => different index_hash even though content_hash matches.
        let r1 = make_record_with_tags(vec!["a"]);
        let r2 = make_record_with_tags(vec!["b"]);
        assert_eq!(r1.content_hash, r2.content_hash);
        assert_ne!(compute_index_hash(&r1), compute_index_hash(&r2));
    }

    #[test]
    fn index_hash_changes_when_files_change() {
        let mut r = make_record_with_tags(vec!["a"]);
        let h1 = compute_index_hash(&r);
        r.files.push(make_file_evidence("src/foo.rs"));
        let h2 = compute_index_hash(&r);
        assert_ne!(h1, h2);
    }

    #[test]
    fn index_hash_tags_order_independent() {
        // Tags are sorted before hashing, so order must not matter.
        let r1 = make_record_with_tags(vec!["b", "a"]);
        let r2 = make_record_with_tags(vec!["a", "b"]);
        assert_eq!(compute_index_hash(&r1), compute_index_hash(&r2));
    }

    #[test]
    fn index_hash_output_is_64_lowercase_hex_chars() {
        let r = make_record_with_tags(vec!["a"]);
        let h = compute_index_hash(&r);
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }
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
