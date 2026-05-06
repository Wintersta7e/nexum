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
use crate::trust::chain_state::ChainState;
use crate::trust::events_view::TrustEventsView;

use super::policy::{PolicyOpts, apply as apply_policy};
use super::types::QueryError;
use super::verify::{CachedCrypto, ProjectedTrust, project_trust};

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

/// Fetch the full `UnifiedRecord` for `key`.
///
/// Returns:
/// - `Ok(GetOutcome::Found(r))` — record found and visible.
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
    let view = TrustEventsView::new(conn);
    let chain = ChainState::from_view(&view)?;
    let cached = CachedCrypto {
        crypto_result,
        signer_fingerprint: raw.signer_fingerprint.as_deref(),
        commit_sha: raw.record_commit_sha.as_deref(),
        relevant_trust_events_commit: raw.relevant_trust_events_commit.as_deref(),
    };
    let projected = project_trust(cached, &view, &chain, opts.strict_revocation)?;

    // `include_unsigned` is the per-call escape hatch for agents that
    // need to inspect a record regardless of trust state. When set, we
    // bypass the centralized policy filter and surface the full
    // projection.
    if opts.include_unsigned {
        return build_record(raw, crypto_result, projected).map(|r| GetOutcome::Found(Box::new(r)));
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
    match outcome.visible.into_iter().next() {
        Some((raw, projected)) => {
            build_record(raw, crypto_result, projected).map(|r| GetOutcome::Found(Box::new(r)))
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
                           relevant_trust_events_commit";

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
            warnings: projected.warnings,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexer::db::open_or_create;
    use crate::records::SignatureStatus;
    use tempfile::TempDir;

    fn open() -> (TempDir, rusqlite::Connection) {
        let dir = TempDir::new().unwrap();
        let conn = open_or_create(&dir.path().join("index.db")).unwrap();
        crate::query::test_util::seed_bootstrap_chain(&conn);
        (dir, conn)
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
        let GetOutcome::Found(r) = res else {
            panic!("expected Found, got {res:?}");
        };
        assert_eq!(r.id, "alpha");
        assert_eq!(r.provenance.signature_status, SignatureStatus::Verified);
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
            GetOutcome::Found(_)
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
        assert!(matches!(res, GetOutcome::Found(_)));
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
        assert!(matches!(outcome, GetOutcome::Found(_)));
    }
}
