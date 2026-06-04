//! Correlation signals: check whether a commit plausibly relates to a record.
//!
//! Both functions are pure (no I/O, no git). They are consumed by the
//! promotion facade.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::records::types::UnifiedRecord;

/// True iff the commit message plausibly references this recommendation:
/// the rec's slug (id minus the `YYYY-MM-DD-` date prefix) appears in the
/// message, OR a majority of the rec's title words (len >= 4) appear.
/// Case-insensitive.
///
/// `file_overlap` assumes repo-relative paths for both `rec.files` and
/// `changed`; absolute-path records are a known limitation flagged for
/// future benchmark tuning.
pub(crate) fn message_reference(rec: &UnifiedRecord, commit_message: &str) -> bool {
    let msg = commit_message.to_lowercase();
    // Strip YYYY-MM-DD- prefix (4 splits of '-' gives the 4th segment onward).
    let slug = rec
        .id
        .splitn(4, '-')
        .nth(3)
        .unwrap_or(&rec.id)
        .to_lowercase();
    if !slug.is_empty() && msg.contains(&slug) {
        return true;
    }
    let words: Vec<String> = rec
        .title
        .to_lowercase()
        .split_whitespace()
        .filter(|w| w.len() >= 4)
        .map(str::to_owned)
        .collect();
    if words.is_empty() {
        return false;
    }
    let hits = words.iter().filter(|w| msg.contains(w.as_str())).count();
    hits * 2 >= words.len() // majority
}

/// Fraction of the rec's files whose path appears in `changed`.
/// Matches on full repo-relative path. Returns `0.0` when the rec lists no
/// files.
pub(crate) fn file_overlap(rec: &UnifiedRecord, changed: &[PathBuf]) -> f64 {
    if rec.files.is_empty() {
        return 0.0;
    }
    let changed_set: HashSet<&Path> = changed.iter().map(AsRef::as_ref).collect();
    let hit = rec
        .files
        .iter()
        .filter(|f| changed_set.contains(f.path.as_path()))
        .count();
    // Record file counts are tiny (never near 2^52); precision loss is not
    // reachable in practice.
    #[allow(clippy::cast_precision_loss)]
    let ratio = hit as f64 / rec.files.len() as f64;
    ratio
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use chrono::{TimeZone, Utc};

    use super::{file_overlap, message_reference};
    use crate::records::types::{
        Agent, Confidence, CryptoResult, FileEvidence, FileEvidenceKind, Outcome, Provenance,
        RecordType, SessionRef, SignatureStatus, Source, UnifiedRecord,
    };

    fn make_rec(id: &str, title: &str, files: Vec<FileEvidence>) -> UnifiedRecord {
        UnifiedRecord {
            id: id.into(),
            record_type: RecordType::Recommendation,
            source: Source::Local,
            project_id: "git:abc123".into(),
            title: title.into(),
            summary: None,
            body: String::new(),
            body_origin_path: None,
            tags: vec![],
            agent: Agent::Manual,
            session_refs: vec![SessionRef::Manual],
            files,
            commits: vec![],
            created: Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
            updated: Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
            confidence: Confidence::Medium,
            outcome: Outcome::Proposed,
            provenance: Provenance {
                source: Source::Local,
                signature_status: SignatureStatus::Unsigned,
                extractor: None,
                digest_hash: None,
                record_commit_sha: None,
                signer_fingerprint: None,
                crypto_result: CryptoResult::NoSignature,
                relevant_trust_events_commit: None,
                trust_basis: None,
                warnings: vec![],
                commit_evidence: None,
                promoted_from: None,
                inherited_warnings: vec![],
            },
            extras: HashMap::new(),
            content_hash: "deadbeef".into(),
        }
    }

    fn fe(path: &str) -> FileEvidence {
        FileEvidence {
            path: PathBuf::from(path),
            kind: FileEvidenceKind::ParsedFromMemoryBody,
        }
    }

    // ── message_reference ──────────────────────────────────────────────────

    #[test]
    fn slug_in_message_returns_true() {
        let rec = make_rec("2026-05-01-use-jwt-auth", "Use JWT for auth", vec![]);
        // slug = "use-jwt-auth"
        assert!(message_reference(
            &rec,
            "feat: implement use-jwt-auth middleware"
        ));
    }

    #[test]
    fn unrelated_message_returns_false() {
        let rec = make_rec("2026-05-01-use-jwt-auth", "Use JWT for auth", vec![]);
        assert!(!message_reference(&rec, "fix: typo in README"));
    }

    #[test]
    fn majority_title_words_match() {
        // Title words len>=4: "switch", "redis", "sessions" → 3 words.
        // Majority = at least 2. Message contains "switch" and "sessions" → 2/3 ≥ majority.
        let rec = make_rec("2026-05-01-no-match-slug", "Switch redis sessions", vec![]);
        assert!(message_reference(
            &rec,
            "refactor: switch to in-memory sessions cache"
        ));
    }

    #[test]
    fn minority_title_words_returns_false() {
        // Title words len>=4: "switch", "redis", "sessions" → 3 words.
        // Message contains only "switch" → 1/3 < majority.
        let rec = make_rec("2026-05-01-no-match-slug", "Switch redis sessions", vec![]);
        assert!(!message_reference(&rec, "chore: switch build system"));
    }

    #[test]
    fn slug_match_is_case_insensitive() {
        let rec = make_rec("2026-05-01-use-jwt-auth", "Use JWT for auth", vec![]);
        assert!(message_reference(
            &rec,
            "feat: implement USE-JWT-AUTH handler"
        ));
    }

    // ── file_overlap ───────────────────────────────────────────────────────

    #[test]
    fn full_overlap_returns_one() {
        let rec = make_rec(
            "2026-05-01-full",
            "Full overlap",
            vec![fe("src/a.rs"), fe("src/b.rs")],
        );
        let changed = vec![PathBuf::from("src/a.rs"), PathBuf::from("src/b.rs")];
        // Comparing against known constant 1.0; exact equality is correct.
        #[allow(clippy::float_cmp)]
        let ok = file_overlap(&rec, &changed) == 1.0;
        assert!(ok);
    }

    #[test]
    fn partial_overlap_returns_correct_fraction() {
        let rec = make_rec(
            "2026-05-01-partial",
            "Partial",
            vec![fe("src/a.rs"), fe("src/b.rs"), fe("src/c.rs")],
        );
        // Only a.rs and b.rs changed; c.rs not touched → 2/3.
        let changed = vec![PathBuf::from("src/a.rs"), PathBuf::from("src/b.rs")];
        let ratio = file_overlap(&rec, &changed);
        // 2/3 ≈ 0.666…; use approximate comparison.
        assert!((ratio - 2.0 / 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn disjoint_files_returns_zero() {
        let rec = make_rec(
            "2026-05-01-disjoint",
            "Disjoint",
            vec![fe("src/a.rs"), fe("src/b.rs")],
        );
        let changed = vec![PathBuf::from("src/c.rs"), PathBuf::from("src/d.rs")];
        // Comparing against known constant 0.0; exact equality is correct.
        #[allow(clippy::float_cmp)]
        let ok = file_overlap(&rec, &changed) == 0.0;
        assert!(ok);
    }

    #[test]
    fn no_files_in_rec_returns_zero() {
        let rec = make_rec("2026-05-01-empty", "Empty files list", vec![]);
        let changed = vec![PathBuf::from("src/a.rs")];
        // Comparing against known constant 0.0; exact equality is correct.
        #[allow(clippy::float_cmp)]
        let ok = file_overlap(&rec, &changed) == 0.0;
        assert!(ok);
    }
}
