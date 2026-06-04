//! Stale-recommendation identification.
//!
//! Identifies proposed local recommendations whose age exceeds the configured
//! correlation window. The caller (`api::promote_suggestions`) composes this
//! with the suggestion scan to exclude records that still have a candidate
//! commit.

use crate::config::Config;
use crate::records::types::{Outcome, RecordKey, Source, UnifiedRecord};

/// Return the keys of proposed local recommendations whose age exceeds
/// `cfg.promote.correlation_window_days`.
///
/// Pure age-based filter — no repo access. The caller composes the result
/// with the suggestion scan to skip records that still have a candidate.
pub(crate) fn find_stale(
    cfg: &Config,
    recs: &[UnifiedRecord],
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<RecordKey> {
    let window = chrono::Duration::days(i64::from(cfg.promote.correlation_window_days));
    recs.iter()
        .filter(|r| r.outcome == Outcome::Proposed && r.source == Source::Local)
        .filter(|r| now.signed_duration_since(r.created) > window)
        .map(|r| RecordKey {
            source: Some(Source::Local),
            project_id: Some(r.project_id.clone()),
            id: r.id.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::{Duration, TimeZone, Utc};

    use super::find_stale;
    use crate::config::Config;
    use crate::records::types::{
        Agent, Confidence, CryptoResult, Outcome, Provenance, RecordType, SessionRef,
        SignatureStatus, Source, UnifiedRecord,
    };

    fn make_rec(id: &str, project_id: &str, outcome: Outcome, source: Source) -> UnifiedRecord {
        let created = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        UnifiedRecord {
            id: id.into(),
            record_type: RecordType::Recommendation,
            source,
            project_id: project_id.into(),
            title: "test rec".into(),
            summary: None,
            body: String::new(),
            body_origin_path: None,
            tags: vec![],
            agent: Agent::Manual,
            session_refs: vec![SessionRef::Manual],
            files: vec![],
            commits: vec![],
            created,
            updated: created,
            confidence: Confidence::Medium,
            outcome,
            provenance: Provenance {
                source,
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

    fn make_cfg_with_window(days: u32) -> Config {
        let mut cfg = Config::seed();
        cfg.promote.correlation_window_days = days;
        cfg
    }

    /// A proposed local rec created 60 days before `now` is flagged when the
    /// window is 30 days.
    #[test]
    fn proposed_local_older_than_window_is_flagged() {
        let cfg = make_cfg_with_window(30);
        let rec = make_rec("rec-old", "proj-a", Outcome::Proposed, Source::Local);
        // now = created + 60 days → age (60d) > window (30d)
        let now = rec.created + Duration::days(60);
        let stale = find_stale(&cfg, &[rec], now);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].id, "rec-old");
        assert_eq!(stale[0].source, Some(Source::Local));
        assert_eq!(stale[0].project_id, Some("proj-a".into()));
    }

    /// A proposed local rec within the window is not flagged.
    #[test]
    fn proposed_local_within_window_is_not_flagged() {
        let cfg = make_cfg_with_window(30);
        let rec = make_rec("rec-recent", "proj-a", Outcome::Proposed, Source::Local);
        // now = created + 10 days → age (10d) ≤ window (30d)
        let now = rec.created + Duration::days(10);
        let stale = find_stale(&cfg, &[rec], now);
        assert!(stale.is_empty());
    }

    /// A record that is not Proposed is not flagged even if old.
    #[test]
    fn non_proposed_record_is_not_flagged() {
        let cfg = make_cfg_with_window(30);
        let rec = make_rec("rec-promoted", "proj-a", Outcome::Promoted, Source::Local);
        let now = rec.created + Duration::days(60);
        let stale = find_stale(&cfg, &[rec], now);
        assert!(stale.is_empty());
    }

    /// A non-Local proposed record is not flagged even if old.
    #[test]
    fn non_local_proposed_record_is_not_flagged() {
        let cfg = make_cfg_with_window(30);
        let rec = make_rec("rec-cc", "proj-a", Outcome::Proposed, Source::CcNative);
        let now = rec.created + Duration::days(60);
        let stale = find_stale(&cfg, &[rec], now);
        assert!(stale.is_empty());
    }

    /// Mixed slice: only the qualifying (old, proposed, local) rec is returned.
    #[test]
    fn mixed_recs_only_qualifying_flagged() {
        let cfg = make_cfg_with_window(30);
        let old_local = make_rec("rec-old-local", "proj-a", Outcome::Proposed, Source::Local);
        let recent_local = make_rec(
            "rec-recent-local",
            "proj-a",
            Outcome::Proposed,
            Source::Local,
        );
        let old_cc = make_rec("rec-old-cc", "proj-a", Outcome::Proposed, Source::CcNative);
        let old_promoted = make_rec(
            "rec-old-promoted",
            "proj-a",
            Outcome::Promoted,
            Source::Local,
        );

        let now = old_local.created + Duration::days(60);
        // recent_local was "created" 55 days after old_local for test purposes —
        // use a slightly different created time by constructing it directly.
        let mut recent = recent_local.clone();
        recent.created = now - Duration::days(5); // 5 days old → within window
        recent.updated = recent.created;

        let recs = [old_local, recent, old_cc, old_promoted];
        let stale = find_stale(&cfg, &recs, now);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].id, "rec-old-local");
    }
}
