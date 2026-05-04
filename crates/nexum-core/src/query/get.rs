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
    Agent, Confidence, FileEvidence, GetOutcome, Outcome, Provenance, RecordKey, RecordType,
    SessionRef, SignatureStatus, Source, TrustBasis, TrustPolicy, UnifiedRecord,
};

use super::types::QueryError;

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
}

impl Default for GetOpts {
    fn default() -> Self {
        Self {
            include_unsigned: false,
            trust_policy: TrustPolicy::WarnButShow,
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
/// `QueryError::Json` on JSON column deserialization failure, or
/// `QueryError::Ambiguous` when the key under-specifies and matches >1 row.
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
    // Exactly one candidate — apply hide-policy then materialize.
    let raw = candidates.swap_remove(0);
    let signature_status = SignatureStatus::from_db_str(&raw.signature_status);
    if opts.trust_policy == TrustPolicy::Hide
        && !opts.include_unsigned
        && signature_status != SignatureStatus::Verified
    {
        return Ok(GetOutcome::HiddenByPolicy { signature_status });
    }
    build_record(raw, signature_status).map(|r| GetOutcome::Found(Box::new(r)))
}

/// Run the appropriate `SELECT` for the key shape and collect the rows.
fn fetch_candidates(conn: &Connection, key: &RecordKey) -> Result<Vec<RawRow>, QueryError> {
    const COLUMNS: &str = "id, source, project_id, record_type, title, summary, body, \
                           body_origin_path, tags, confidence, outcome, agent, session_refs, \
                           files, commits, created, updated, content_hash, signature_status, \
                           extras, record_commit_sha, signer_fingerprint, trust_basis, \
                           warning_code";

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
        signature_status: r.get::<_, String>(18)?,
        extras: r.get::<_, Option<String>>(19)?,
        record_commit_sha: r.get::<_, Option<String>>(20)?,
        signer_fingerprint: r.get::<_, Option<String>>(21)?,
        trust_basis: r.get::<_, Option<String>>(22)?,
        warning_code: r.get::<_, Option<String>>(23)?,
    })
}

fn build_record(
    raw: RawRow,
    signature_status: SignatureStatus,
) -> Result<UnifiedRecord, QueryError> {
    // Prefer the persisted `trust_basis` column when present; fall back to the
    // signature-status default for rows written before the column existed
    // or by adapters that don't track basis.
    let trust_basis = raw.trust_basis.as_deref().map(TrustBasis::from_db_str).or(
        if signature_status == SignatureStatus::Verified {
            Some(TrustBasis::Current)
        } else {
            None
        },
    );
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
            signature_status,
            trust_basis,
            extractor: None,
            digest_hash: None,
            record_commit_sha: raw.record_commit_sha,
            signer_fingerprint: raw.signer_fingerprint,
            warning_code: raw.warning_code,
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
    signature_status: String,
    extras: Option<String>,
    record_commit_sha: Option<String>,
    signer_fingerprint: Option<String>,
    trust_basis: Option<String>,
    warning_code: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexer::db::open_or_create;
    use tempfile::TempDir;

    fn open() -> (TempDir, rusqlite::Connection) {
        let dir = TempDir::new().unwrap();
        let conn = open_or_create(&dir.path().join("index.db")).unwrap();
        (dir, conn)
    }

    fn insert(conn: &rusqlite::Connection, id: &str, signed: bool) {
        let sig = if signed { "verified" } else { "unsigned" };
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, session_refs, files, commits, confidence, \
             created, updated, content_hash, index_hash, signature_status, indexed_at) \
             VALUES (?1, 'local', 'p', 'decision', ?1, '', '[]', '', 'manual', \
                     '[]', '[]', '[]', 'medium', \
                     '2026-04-29T00:00:00Z', '2026-04-29T00:00:00Z', 'h', 'ih', ?2, '2026-04-29T00:01:00Z')",
            rusqlite::params![id, sig],
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
             tags_fts, agent, session_refs, files, commits, confidence, created, updated, \
             content_hash, index_hash, signature_status, indexed_at) VALUES \
             ('shared', 'local', 'p', 'decision', 'shared', '', '[]', '', 'manual', \
              '[]', '[]', '[]', 'medium', '2026-04-29T00:00:00Z', '2026-04-29T00:00:00Z', \
              'h', 'ih', 'verified', '2026-04-29T00:01:00Z'), \
             ('shared', 'cc-native', 'p', 'decision', 'shared', '', '[]', '', 'manual', \
              '[]', '[]', '[]', 'medium', '2026-04-29T00:00:00Z', '2026-04-29T00:00:00Z', \
              'h', 'ih', 'verified', '2026-04-29T00:01:00Z')",
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
