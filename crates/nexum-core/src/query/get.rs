//! `get(conn, key, opts)` — fetch one full record by composite key; honors
//! the hide-policy invariant (an unsigned record under `trust_policy = Hide`
//! returns `HiddenByPolicy` unless `include_unsigned` is set).
//!
//! A `RecordKey` may be exact (`source` + `project_id` + `id`), partial
//! (one qualifier present), or bare (id only). Partial / bare keys may match
//! multiple rows; in that case `QueryError::Ambiguous` is returned with the
//! list of fully-qualified candidates the caller can pick from.

use rusqlite::{Connection, Row, ToSql};
use serde::{Deserialize, Serialize};

use crate::records::{
    Agent, Confidence, CryptoResult, FileEvidence, GetOutcome, Outcome, Provenance, RecordKey,
    RecordType, SessionRef, Source, TrustPolicy, UnifiedRecord,
};

use super::meta::build_meta_listing;
use super::policy::{PolicyOpts, apply as apply_policy};
use super::types::QueryError;
use super::verify::{CachedCrypto, ProjectedTrust, ProjectionContext};

/// `get` options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetOpts {
    /// `include_unsigned: true` returns the record regardless of policy
    /// (escape hatch for agents that need to inspect deliberately).
    pub include_unsigned: bool,
    /// Current trust policy from `[trust] unsigned_default`. When `Hide`
    /// AND `include_unsigned == false`, an unverified record is returned
    /// as `GetOutcome::HiddenByPolicy`.
    pub trust_policy: TrustPolicy,
    /// Mirrors `[trust] strict_revocation` from `config.toml`. When `true`,
    /// records signed by a key that has since been marked compromised
    /// project as `Invalid` (with both `signed-by-compromised-key` and
    /// `strict-revocation-active` warnings). The api facade fills this from
    /// `cfg.trust.strict_revocation`.
    #[serde(default)]
    pub strict_revocation: bool,
}

impl Default for GetOpts {
    fn default() -> Self {
        Self {
            include_unsigned: false,
            trust_policy: TrustPolicy::WarnButShow,
            strict_revocation: false,
        }
    }
}

/// Serializable `get` success envelope — `{ record, _meta }`. The CLI and
/// MCP `get` success paths serialize this straight from a
/// `GetOutcome::Found`; neither layer hand-builds the `_meta` wrapper.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GetSuccess {
    pub record: Box<UnifiedRecord>,
    #[serde(rename = "_meta")]
    pub meta: super::Meta,
}

/// Fetch the full `UnifiedRecord` for `key`.
///
/// Returns:
/// - `Ok(GetOutcome::Found { record, meta })` — record found and visible;
///   `meta` is the shared `_meta` envelope built over the same connection.
/// - `Ok(GetOutcome::NotFound)` — no record matches the key.
/// - `Ok(GetOutcome::HiddenByPolicy { signature_status })` — exactly one
///   record matches but is suppressed by `trust_policy = Hide` with
///   `include_unsigned = false`.
/// - `Err(QueryError::Ambiguous { matches })` — partial / bare key matches
///   multiple rows; the `matches` list is the set of fully-qualified
///   candidate keys the caller can pick from.
///
/// # Errors
/// Returns `QueryError::Rusqlite` on rusqlite failure,
/// `QueryError::Json` on JSON column deserialization failure,
/// `QueryError::Ambiguous` when the key under-specifies and matches >1 row,
/// or `QueryError::Trust` if the chain-state hydration fails.
pub fn get(conn: &Connection, key: &RecordKey, opts: &GetOpts) -> Result<GetOutcome, QueryError> {
    let mut candidates = fetch_candidates(conn, key)?;

    if candidates.is_empty() {
        return Ok(GetOutcome::NotFound);
    }
    if candidates.len() > 1 {
        let matches = candidates
            .into_iter()
            .map(|raw| RecordKey::exact(Source::from_db_str(&raw.source), raw.project_id, raw.id))
            .collect();
        return Err(QueryError::Ambiguous { matches });
    }
    // Exactly one candidate — project trust then apply policy.
    let raw = candidates.swap_remove(0);
    let crypto_result = CryptoResult::from_db_str(&raw.crypto_result);
    let ctx = ProjectionContext::new(conn)?;
    let mut projected =
        ctx.project_rows(vec![raw], opts.strict_revocation, |raw| CachedCrypto {
            crypto_result,
            signer_fingerprint: raw.signer_fingerprint.as_deref(),
            commit_sha: raw.record_commit_sha.as_deref(),
            relevant_trust_events_commit: raw.relevant_trust_events_commit.as_deref(),
        })?;
    let (raw, projected) = projected.swap_remove(0);

    // `include_unsigned` is the per-call escape hatch for agents that
    // need to inspect a record regardless of trust state. When set, we
    // bypass the centralized policy filter and surface the full
    // projection. `_meta` still ships — the success contract is uniform —
    // but with the hide-bucket counters at their `build_meta_listing`
    // defaults since no policy filtering ran.
    if opts.include_unsigned {
        let meta = build_meta_listing(conn, opts.trust_policy)?;
        let record = build_record(raw, crypto_result, projected)?;
        return Ok(GetOutcome::Found {
            record: Box::new(record),
            meta,
        });
    }

    // Route the single row through the same warn/hide/strict policy
    // helper that the listing verbs use, then translate the policy
    // outcome into the `Found` / `HiddenByPolicy` variants.
    let policy_opts = PolicyOpts {
        policy: opts.trust_policy,
        require_signed: false,
    };
    let signature_status = projected.signature_status;
    let outcome = apply_policy(vec![(raw, projected)], policy_opts, |row| &row.1);
    // `build_meta_listing` + `apply_policy_outcome`: the same `_meta`
    // sequence the listing verbs run.
    let mut meta = build_meta_listing(conn, opts.trust_policy)?;
    meta.apply_policy_outcome(&outcome);
    match outcome.visible.into_iter().next() {
        Some((raw, projected)) => {
            let record = build_record(raw, crypto_result, projected)?;
            Ok(GetOutcome::Found {
                record: Box::new(record),
                meta,
            })
        }
        None => Ok(GetOutcome::HiddenByPolicy { signature_status }),
    }
}

/// Run the appropriate `SELECT` for the key shape and collect the rows.
fn fetch_candidates(conn: &Connection, key: &RecordKey) -> Result<Vec<RawRow>, QueryError> {
    const COLUMNS: &str = "id, source, project_id, record_type, title, summary, body, \
                           body_origin_path, tags, confidence, outcome, agent, session_refs, \
                           files, commits, created, updated, content_hash, crypto_result, \
                           extras, record_commit_sha, signer_fingerprint, \
                           relevant_trust_events_commit, \
                           commit_evidence, promoted_from, inherited_warnings";

    let (where_clause, params): (&str, Vec<Box<dyn ToSql>>) =
        match (key.source, key.project_id.as_deref()) {
            (Some(source), Some(project_id)) => (
                "WHERE source = ?1 AND project_id = ?2 AND id = ?3",
                vec![
                    Box::new(source.as_db_str().to_owned()),
                    Box::new(project_id.to_owned()),
                    Box::new(key.id.clone()),
                ],
            ),
            (Some(source), None) => (
                "WHERE source = ?1 AND id = ?2",
                vec![
                    Box::new(source.as_db_str().to_owned()),
                    Box::new(key.id.clone()),
                ],
            ),
            (None, Some(project_id)) => (
                "WHERE project_id = ?1 AND id = ?2",
                vec![Box::new(project_id.to_owned()), Box::new(key.id.clone())],
            ),
            (None, None) => ("WHERE id = ?1", vec![Box::new(key.id.clone())]),
        };

    let sql = format!("SELECT {COLUMNS} FROM records {where_clause}");
    let mut stmt = conn.prepare(&sql)?;
    let param_refs: Vec<&dyn ToSql> = params.iter().map(|p| &**p as &dyn ToSql).collect();
    let rows = stmt.query_map(rusqlite::params_from_iter(param_refs.iter()), row_to_raw)?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(QueryError::from)
}

fn row_to_raw(r: &Row<'_>) -> rusqlite::Result<RawRow> {
    Ok(RawRow {
        id: r.get(0)?,
        source: r.get::<_, String>(1)?,
        project_id: r.get(2)?,
        record_type: r.get::<_, String>(3)?,
        title: r.get(4)?,
        summary: r.get::<_, Option<String>>(5)?,
        body: r.get(6)?,
        body_origin_path: r.get::<_, Option<String>>(7)?,
        tags: r.get::<_, String>(8)?,
        confidence: r.get::<_, String>(9)?,
        outcome: r.get::<_, Option<String>>(10)?,
        agent: r.get::<_, String>(11)?,
        session_refs: r.get::<_, String>(12)?,
        files: r.get::<_, String>(13)?,
        commits: r.get::<_, String>(14)?,
        created: r.get::<_, String>(15)?,
        updated: r.get::<_, String>(16)?,
        content_hash: r.get(17)?,
        crypto_result: r.get::<_, String>(18)?,
        extras: r.get::<_, Option<String>>(19)?,
        record_commit_sha: r.get::<_, Option<String>>(20)?,
        signer_fingerprint: r.get::<_, Option<String>>(21)?,
        relevant_trust_events_commit: r.get::<_, Option<String>>(22)?,
        commit_evidence: r.get::<_, Option<String>>(23)?,
        promoted_from: r.get::<_, Option<String>>(24)?,
        inherited_warnings: r.get::<_, Option<String>>(25)?,
    })
}

fn build_record(
    raw: RawRow,
    crypto_result: CryptoResult,
    projected: ProjectedTrust,
) -> Result<UnifiedRecord, QueryError> {
    let extras: std::collections::HashMap<String, serde_json::Value> =
        serde_json::from_str(raw.extras.as_deref().unwrap_or("{}"))?;
    let tags: Vec<String> = serde_json::from_str(&raw.tags)?;
    let session_refs: Vec<SessionRef> = serde_json::from_str(&raw.session_refs)?;
    let files: Vec<FileEvidence> = serde_json::from_str(&raw.files)?;
    let commits: Vec<String> = serde_json::from_str(&raw.commits)?;
    let created = chrono::DateTime::parse_from_rfc3339(&raw.created)
        .map_err(|e| QueryError::InvalidFilter {
            detail: format!("created: {e}"),
        })?
        .with_timezone(&chrono::Utc);
    let updated = chrono::DateTime::parse_from_rfc3339(&raw.updated)
        .map_err(|e| QueryError::InvalidFilter {
            detail: format!("updated: {e}"),
        })?
        .with_timezone(&chrono::Utc);
    let body_origin_path = raw.body_origin_path.map(std::path::PathBuf::from);
    let confidence = Confidence::from_db_str(&raw.confidence);
    // `outcome` is `Option<String>`; `Outcome::from_db_str` already collapses
    // unknown values to `NotApplicable`, so a `None` cell maps to the same
    // sentinel via `map_or`.
    let outcome = raw
        .outcome
        .as_deref()
        .map_or(Outcome::NotApplicable, Outcome::from_db_str);
    let agent = Agent::from_db_str(&raw.agent);
    let record_type = RecordType::from_db_str(&raw.record_type);
    let source = Source::from_db_str(&raw.source);

    let commit_evidence = raw
        .commit_evidence
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|e| QueryError::InvalidFilter {
            detail: format!("commit_evidence: {e}"),
        })?;
    let promoted_from = raw
        .promoted_from
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|e| QueryError::InvalidFilter {
            detail: format!("promoted_from: {e}"),
        })?;
    let inherited_warnings: Vec<String> = raw
        .inherited_warnings
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|e| QueryError::InvalidFilter {
            detail: format!("inherited_warnings: {e}"),
        })?
        .unwrap_or_default();

    // Merge inherited warnings into the surfaced warnings without duplicating.
    let mut warnings = projected.warnings;
    for w in &inherited_warnings {
        if !warnings.contains(w) {
            warnings.push(w.clone());
        }
    }

    Ok(UnifiedRecord {
        id: raw.id,
        record_type,
        source,
        project_id: raw.project_id,
        title: raw.title,
        summary: raw.summary,
        body: raw.body,
        body_origin_path,
        tags,
        agent,
        session_refs,
        files,
        commits,
        created,
        updated,
        confidence,
        outcome,
        provenance: Provenance {
            source,
            signature_status: projected.signature_status,
            extractor: None,
            digest_hash: None,
            record_commit_sha: raw.record_commit_sha,
            signer_fingerprint: raw.signer_fingerprint,
            crypto_result,
            relevant_trust_events_commit: raw.relevant_trust_events_commit,
            trust_basis: projected.trust_basis,
            warnings,
            commit_evidence,
            promoted_from,
            inherited_warnings,
        },
        extras,
        content_hash: raw.content_hash,
    })
}

#[derive(Debug)]
struct RawRow {
    id: String,
    source: String,
    project_id: String,
    record_type: String,
    title: String,
    summary: Option<String>,
    body: String,
    body_origin_path: Option<String>,
    tags: String,
    confidence: String,
    outcome: Option<String>,
    agent: String,
    session_refs: String,
    files: String,
    commits: String,
    created: String,
    updated: String,
    content_hash: String,
    /// `records.crypto_result` SQL column.
    crypto_result: String,
    extras: Option<String>,
    record_commit_sha: Option<String>,
    signer_fingerprint: Option<String>,
    /// SHA of the events.yml commit effective at the record's commit time.
    /// Forwarded into [`CachedCrypto`] for the read-time projection and onto
    /// `Provenance::relevant_trust_events_commit` for downstream consumers.
    relevant_trust_events_commit: Option<String>,
    /// M3 lifecycle columns (JSON-encoded; NULL for non-promoted records).
    commit_evidence: Option<String>,
    promoted_from: Option<String>,
    inherited_warnings: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::test_util::open_test_db_with_seeded_chain;
    use crate::records::SignatureStatus;

    fn open() -> (tempfile::TempDir, rusqlite::Connection) {
        open_test_db_with_seeded_chain()
    }

    fn insert(conn: &rusqlite::Connection, id: &str, signed: bool) {
        let cr = if signed { "good" } else { "no-signature" };
        let (signer_fp, trust_commit) = if signed {
            (
                Some(crate::query::test_util::TEST_BOOTSTRAP_FP),
                Some(crate::query::test_util::TEST_TRUST_COMMIT),
            )
        } else {
            (None, None)
        };
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, session_refs, files, commits, confidence, outcome, \
             created, updated, content_hash, index_hash, crypto_result, \
             signer_fingerprint, relevant_trust_events_commit, indexed_at) \
             VALUES (?1, 'local', 'p', 'decision', ?1, '', '[]', '', 'manual', \
                     '[]', '[]', '[]', 'medium', 'working', \
                     '2026-04-29T00:00:00Z', '2026-04-29T00:00:00Z', 'h', 'ih', ?2, \
                     ?3, ?4, '2026-04-29T00:01:00Z')",
            rusqlite::params![id, cr, signer_fp, trust_commit],
        )
        .unwrap();
    }

    #[test]
    fn get_missing_returns_not_found() {
        let (_dir, conn) = open();
        let res = get(&conn, &RecordKey::bare("nope"), &GetOpts::default()).unwrap();
        assert_eq!(res, GetOutcome::NotFound);
    }

    #[test]
    fn get_signed_record_returns_full_record() {
        let (_dir, conn) = open();
        insert(&conn, "alpha", true);
        let res = get(
            &conn,
            &RecordKey::bare("alpha"),
            &GetOpts {
                include_unsigned: false,
                trust_policy: TrustPolicy::WarnButShow,
                strict_revocation: false,
            },
        )
        .unwrap();
        let GetOutcome::Found { record: r, .. } = res else {
            panic!("expected Found, got {res:?}");
        };
        assert_eq!(r.id, "alpha");
        assert_eq!(r.provenance.signature_status, SignatureStatus::Verified);
    }

    #[test]
    fn get_signed_record_carries_trust_basis() {
        use crate::records::TrustBasis;

        let (_dir, conn) = open();
        insert(&conn, "alpha", true);
        let res = get(
            &conn,
            &RecordKey::bare("alpha"),
            &GetOpts {
                include_unsigned: false,
                trust_policy: TrustPolicy::WarnButShow,
                strict_revocation: false,
            },
        )
        .unwrap();
        let GetOutcome::Found { record: r, .. } = res else {
            panic!("expected Found, got {res:?}");
        };
        // The seeded chain keeps the bootstrap key trusted at head, so a
        // record signed by it projects to `Current` — and `build_record`
        // must forward that onto `Provenance`, not drop it to `None`.
        assert_eq!(r.provenance.trust_basis, Some(TrustBasis::Current));
    }

    #[test]
    fn get_unsigned_record_has_no_trust_basis() {
        let (_dir, conn) = open();
        insert(&conn, "u", false);
        let res = get(
            &conn,
            &RecordKey::bare("u"),
            &GetOpts {
                include_unsigned: true,
                trust_policy: TrustPolicy::WarnButShow,
                strict_revocation: false,
            },
        )
        .unwrap();
        let GetOutcome::Found { record: r, .. } = res else {
            panic!("expected Found, got {res:?}");
        };
        // An unsigned record has no basis — the projection returns `None`
        // and `build_record` forwards it unchanged.
        assert_eq!(r.provenance.trust_basis, None);
        assert_eq!(r.provenance.signature_status, SignatureStatus::Unsigned);
    }

    #[test]
    fn get_unsigned_under_hide_policy_returns_hidden_unless_overridden() {
        let (_dir, conn) = open();
        insert(&conn, "u", false);
        let hide_default = GetOpts {
            include_unsigned: false,
            trust_policy: TrustPolicy::Hide,
            strict_revocation: false,
        };
        assert!(matches!(
            get(&conn, &RecordKey::bare("u"), &hide_default).unwrap(),
            GetOutcome::HiddenByPolicy {
                signature_status: SignatureStatus::Unsigned
            }
        ));
        let hide_override = GetOpts {
            include_unsigned: true,
            trust_policy: TrustPolicy::Hide,
            strict_revocation: false,
        };
        assert!(matches!(
            get(&conn, &RecordKey::bare("u"), &hide_override).unwrap(),
            GetOutcome::Found { .. }
        ));
    }

    #[test]
    fn get_unsigned_under_warn_but_show_returns_record() {
        let (_dir, conn) = open();
        insert(&conn, "u", false);
        let res = get(
            &conn,
            &RecordKey::bare("u"),
            &GetOpts {
                include_unsigned: false,
                trust_policy: TrustPolicy::WarnButShow,
                strict_revocation: false,
            },
        )
        .unwrap();
        assert!(matches!(res, GetOutcome::Found { .. }));
    }

    #[test]
    fn get_by_partial_key_with_source_only_narrows() {
        let (_dir, conn) = open();
        // Two rows with the same id, different sources.
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, session_refs, files, commits, confidence, outcome, created, updated, \
             content_hash, index_hash, crypto_result, indexed_at) VALUES \
             ('shared', 'local', 'p', 'decision', 'shared', '', '[]', '', 'manual', \
              '[]', '[]', '[]', 'medium', 'working', '2026-04-29T00:00:00Z', '2026-04-29T00:00:00Z', \
              'h', 'ih', 'good', '2026-04-29T00:01:00Z'), \
             ('shared', 'cc-native', 'p', 'decision', 'shared', '', '[]', '', 'manual', \
              '[]', '[]', '[]', 'medium', 'working', '2026-04-29T00:00:00Z', '2026-04-29T00:00:00Z', \
              'h', 'ih', 'good', '2026-04-29T00:01:00Z')",
            [],
        )
        .unwrap();
        // Bare id matches both — Ambiguous.
        let bare = get(&conn, &RecordKey::bare("shared"), &GetOpts::default());
        assert!(matches!(bare, Err(QueryError::Ambiguous { .. })));
        // Partial key narrowing by source.
        let key = RecordKey {
            source: Some(Source::Local),
            project_id: None,
            id: "shared".into(),
        };
        let outcome = get(&conn, &key, &GetOpts::default()).unwrap();
        assert!(matches!(outcome, GetOutcome::Found { .. }));
    }

    #[test]
    fn get_found_carries_populated_meta() {
        let (_dir, conn) = open();
        insert(&conn, "alpha", true);
        let res = get(
            &conn,
            &RecordKey::bare("alpha"),
            &GetOpts {
                include_unsigned: false,
                trust_policy: TrustPolicy::WarnButShow,
                strict_revocation: false,
            },
        )
        .unwrap();
        let GetOutcome::Found { record, meta } = res else {
            panic!("expected Found, got {res:?}");
        };
        assert_eq!(record.id, "alpha");
        // `_meta` is built over the same connection: source_counts reflects
        // the one seeded row, trust_policy mirrors the GetOpts policy.
        assert_eq!(meta.source_counts.local, 1);
        assert_eq!(meta.trust_policy, TrustPolicy::WarnButShow);
        // The single verified row was visible — no rows hidden.
        assert_eq!(meta.hidden_unsigned, 0);
        assert_eq!(meta.hidden_invalid, 0);
        assert_eq!(meta.hidden_compromised, 0);
        // trust_summary counts the one returned (verified) row.
        assert_eq!(meta.trust_summary.verified, 1);
    }

    #[test]
    fn get_found_via_include_unsigned_carries_meta() {
        // The escape-hatch path bypasses the policy filter; it must still
        // produce a populated `meta` so the success contract is uniform.
        let (_dir, conn) = open();
        insert(&conn, "u", false);
        let res = get(
            &conn,
            &RecordKey::bare("u"),
            &GetOpts {
                include_unsigned: true,
                trust_policy: TrustPolicy::Hide,
                strict_revocation: false,
            },
        )
        .unwrap();
        let GetOutcome::Found { record, meta } = res else {
            panic!("expected Found, got {res:?}");
        };
        assert_eq!(record.id, "u");
        assert_eq!(meta.source_counts.local, 1);
        assert_eq!(meta.trust_policy, TrustPolicy::Hide);
        // The escape-hatch path skips `apply_policy_outcome`, so the
        // hide-bucket counters and trust tallies stay at their defaults.
        assert_eq!(meta.hidden_unsigned, 0);
        assert_eq!(meta.hidden_invalid, 0);
        assert_eq!(meta.hidden_compromised, 0);
        assert_eq!(meta.trust_summary.verified, 0);
    }

    #[test]
    fn get_success_serializes_record_and_underscore_meta() {
        // The wire shape is `{ record, _meta }`; the struct field name `meta`
        // is renamed via serde and must not leak. The record's body and id
        // are surfaced under `record`; `_meta` carries the same `Meta`
        // envelope every other read verb emits.
        let (_dir, conn) = open();
        insert(&conn, "alpha", true);
        let outcome = get(
            &conn,
            &RecordKey::bare("alpha"),
            &GetOpts {
                include_unsigned: false,
                trust_policy: TrustPolicy::WarnButShow,
                strict_revocation: false,
            },
        )
        .unwrap();
        let GetOutcome::Found { record, meta } = outcome else {
            panic!("expected Found, got {outcome:?}");
        };
        let envelope = GetSuccess { record, meta };
        let v = serde_json::to_value(&envelope).expect("GetSuccess serializes");
        assert!(v.get("record").is_some(), "carries `record` key");
        assert!(v.get("_meta").is_some(), "carries `_meta` key (renamed)");
        assert!(
            v.get("meta").is_none(),
            "the raw struct field name must not leak"
        );
        assert_eq!(v["record"]["id"], "alpha");
    }

    /// Direct DB insert with populated lifecycle columns verifies the read
    /// path deserialization and the `inherited_warnings` merge.
    #[test]
    fn lifecycle_columns_round_trip_via_direct_insert() {
        use crate::records::types::{CommitEvidence, TreeFingerprint, VerificationStatus};

        let (_dir, conn) = open();

        let evidence = CommitEvidence {
            repo_identity: "git:abc".into(),
            branch: "main".into(),
            commit_sha: "a1b2c3d".into(),
            commit_time: chrono::DateTime::parse_from_rfc3339("2026-05-20T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            commit_message_hash: "0".repeat(64),
            tree_changes_fingerprint: TreeFingerprint {
                strict: "11".into(),
                loose: "22".into(),
                file_paths: vec!["src/lib.rs".into()],
            },
            verification_status: VerificationStatus::Verified,
        };
        let prom_key = RecordKey::bare("2026-04-29-x");

        let commit_evidence_json =
            serde_json::to_string(&evidence).expect("serializable commit evidence");
        let promoted_from_json = serde_json::to_string(&prom_key).expect("serializable record key");
        let inherited_warnings_json =
            serde_json::to_string(&["pre-recovery-record"]).expect("serializable warnings");

        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, session_refs, files, commits, confidence, outcome, \
             created, updated, content_hash, index_hash, crypto_result, indexed_at, \
             commit_evidence, promoted_from, inherited_warnings) \
             VALUES ('promoted-1', 'local', 'p', 'decision', 'promoted-1', '', '[]', '', \
                     'manual', '[]', '[]', '[]', 'medium', 'working', \
                     '2026-05-20T00:00:00Z', '2026-05-20T00:00:00Z', 'h', 'ih', \
                     'no-signature', '2026-05-20T00:01:00Z', \
                     ?1, ?2, ?3)",
            rusqlite::params![
                commit_evidence_json,
                promoted_from_json,
                inherited_warnings_json
            ],
        )
        .unwrap();

        let res = get(
            &conn,
            &RecordKey::bare("promoted-1"),
            &GetOpts {
                include_unsigned: true,
                trust_policy: TrustPolicy::WarnButShow,
                strict_revocation: false,
            },
        )
        .unwrap();
        let GetOutcome::Found { record: r, .. } = res else {
            panic!("expected Found, got {res:?}");
        };
        assert!(
            r.provenance.commit_evidence.is_some(),
            "commit_evidence must be populated"
        );
        assert_eq!(
            r.provenance.commit_evidence.as_ref().unwrap().commit_sha,
            "a1b2c3d"
        );
        assert!(
            r.provenance.promoted_from.is_some(),
            "promoted_from must be populated"
        );
        assert!(
            r.provenance
                .warnings
                .contains(&"pre-recovery-record".to_owned()),
            "inherited warning must be surfaced in warnings"
        );
        assert_eq!(r.provenance.inherited_warnings, vec!["pre-recovery-record"]);
    }

    /// End-to-end: write a promoted decision YAML, run `index_run`, read it back
    /// via `api::get`, and assert the provenance fields survive the full round-trip.
    #[test]
    fn promoted_decision_round_trips_commit_evidence() {
        use crate::api;
        use crate::config::types::Config;
        use crate::paths::Paths;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let paths = Paths::with_home(dir.path().to_owned());

        // Write the decision YAML into the per-project layout.
        let decisions_dir = paths.notebook_git.join("nexum").join("decisions");
        std::fs::create_dir_all(&decisions_dir).unwrap();

        let yaml = r#"schema_version: 1
id: 2026-05-21-promoted-e2e
record_type: decision
project_id: nexum
outcome: working
confidence: high
agent: claude-code
created: 2026-05-21T00:00:00Z
updated: 2026-05-21T00:00:00Z
problem: promoted e2e test decision
provenance:
  source: nexum-promoted
  promoted_from: {source: local, project_id: nexum, id: 2026-04-29-original}
  inherited_warnings: [pre-recovery-record]
  commit_evidence:
    repo_identity: "git:abc"
    branch: main
    commit_sha: a1b2c3ddeadbeef
    commit_time: 2026-05-20T00:00:00Z
    commit_message_hash: "0000000000000000000000000000000000000000000000000000000000000000"
    tree_changes_fingerprint: {strict: "11", loose: "22", file_paths: ["src/lib.rs"]}
    verification_status: verified
"#;
        std::fs::write(decisions_dir.join("2026-05-21-promoted-e2e.yml"), yaml).unwrap();

        let mut cfg = Config::seed();
        cfg.adapters.cc.enabled = false;
        cfg.adapters.codex.enabled = false;
        // local adapter enabled (default); points at paths.notebook_git.

        api::index_run(&paths, &cfg).expect("index_run must succeed");

        let res = api::get(
            &paths,
            &cfg,
            &RecordKey::bare("2026-05-21-promoted-e2e"),
            &GetOpts {
                include_unsigned: true,
                trust_policy: TrustPolicy::WarnButShow,
                strict_revocation: false,
            },
        )
        .expect("get must succeed");

        let GetOutcome::Found { record: r, .. } = res else {
            panic!("expected Found, got {res:?}");
        };
        assert!(
            r.provenance.commit_evidence.is_some(),
            "commit_evidence must survive index→get round-trip"
        );
        assert_eq!(
            r.provenance.commit_evidence.as_ref().unwrap().commit_sha,
            "a1b2c3ddeadbeef"
        );
        assert!(
            r.provenance
                .warnings
                .contains(&"pre-recovery-record".to_owned()),
            "inherited_warnings must be merged into warnings"
        );
    }

    /// UPDATE path: index a promoted record, mutate a field that changes
    /// `index_hash` but leaves `content_hash` (title/summary/body) intact,
    /// re-index, and confirm `update_record` fired and lifecycle columns survive.
    #[test]
    fn promoted_decision_update_preserves_lifecycle_columns() {
        use crate::api;
        use crate::config::types::Config;
        use crate::paths::Paths;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let paths = Paths::with_home(dir.path().to_owned());

        let decisions_dir = paths.notebook_git.join("nexum").join("decisions");
        std::fs::create_dir_all(&decisions_dir).unwrap();

        // confidence=high; title/summary/body are fixed so content_hash is
        // stable across the two passes.
        let yaml_v1 = r#"schema_version: 1
id: 2026-05-21-promoted-update
record_type: decision
project_id: nexum
outcome: working
confidence: high
agent: claude-code
created: 2026-05-21T00:00:00Z
updated: 2026-05-21T00:00:00Z
title: promoted update test
body: stable body text
provenance:
  source: nexum-promoted
  promoted_from: {source: local, project_id: nexum, id: 2026-04-29-src}
  inherited_warnings: [pre-recovery-record]
  commit_evidence:
    repo_identity: "git:abc"
    branch: main
    commit_sha: beef1234
    commit_time: 2026-05-20T00:00:00Z
    commit_message_hash: "0000000000000000000000000000000000000000000000000000000000000000"
    tree_changes_fingerprint: {strict: "1", loose: "2", file_paths: ["src/main.rs"]}
    verification_status: verified
"#;
        let yaml_path = decisions_dir.join("2026-05-21-promoted-update.yml");
        std::fs::write(&yaml_path, yaml_v1).unwrap();

        let mut cfg = Config::seed();
        cfg.adapters.cc.enabled = false;
        cfg.adapters.codex.enabled = false;

        // First pass: INSERT path.
        let outcome1 = api::index_run(&paths, &cfg).expect("first index_run must succeed");
        assert_eq!(outcome1.upserts, 1, "first pass must insert");

        // Mutate confidence high→medium: title/summary/body unchanged so
        // content_hash is identical, but confidence is part of index_hash so
        // index_hash changes. The dual-hash skip therefore does NOT fire and
        // apply_upserts calls update_record.
        let yaml_v2 = yaml_v1.replace("confidence: high", "confidence: medium");
        assert_ne!(yaml_v1, yaml_v2, "mutation must change the YAML");
        std::fs::write(&yaml_path, yaml_v2).unwrap();

        // Second pass: normal incremental run — the changed index_hash forces
        // a real UPDATE via update_record (no force flag needed).
        let outcome2 = api::index_run(&paths, &cfg).expect("second index_run must succeed");
        assert!(
            outcome2.upserts > 0,
            "second pass must upsert (update_record must fire); outcome={outcome2:?}"
        );

        let res = api::get(
            &paths,
            &cfg,
            &RecordKey::bare("2026-05-21-promoted-update"),
            &GetOpts {
                include_unsigned: true,
                trust_policy: TrustPolicy::WarnButShow,
                strict_revocation: false,
            },
        )
        .expect("get must succeed after update");

        let GetOutcome::Found { record: r, .. } = res else {
            panic!("expected Found, got {res:?}");
        };
        assert!(
            r.provenance.commit_evidence.is_some(),
            "commit_evidence must survive UPDATE path"
        );
        assert_eq!(
            r.provenance.commit_evidence.as_ref().unwrap().commit_sha,
            "beef1234"
        );
        assert!(
            r.provenance
                .warnings
                .contains(&"pre-recovery-record".to_owned()),
            "inherited_warnings must survive UPDATE path"
        );
    }
}
