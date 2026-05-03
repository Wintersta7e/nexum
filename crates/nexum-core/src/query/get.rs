//! `get(conn, id, opts)` — fetch one full record by id; honors the
//! hide-policy invariant (an unsigned record under `trust_policy = "hide"`
//! returns `None` unless `include_unsigned` is set).

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::records::{
    Agent, Confidence, FileEvidence, Outcome, Provenance, RecordType, SessionRef, SignatureStatus,
    Source, TrustBasis, UnifiedRecord,
};

use super::types::QueryError;

/// `get` options.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetOpts {
    /// `include_unsigned: true` returns the record regardless of policy
    /// (escape hatch for agents that need to inspect deliberately).
    pub include_unsigned: bool,
    /// Current trust policy from `[trust] unsigned_default`. When `"hide"`
    /// AND `include_unsigned == false`, an unverified record is returned
    /// as `Ok(None)`.
    pub trust_policy: String,
}

/// Fetch the full `UnifiedRecord` for `id`. Returns `Ok(None)` when the
/// record is hidden by trust policy OR when no such id exists.
///
/// # Errors
/// Returns `QueryError::Rusqlite` on rusqlite failure or
/// `QueryError::Json` on JSON column deserialization failure.
pub fn get(
    conn: &Connection,
    id: &str,
    opts: &GetOpts,
) -> Result<Option<UnifiedRecord>, QueryError> {
    let row: Option<RawRow> = conn
        .query_row(
            "SELECT id, source, project_id, record_type, title, summary, body, body_origin_path, \
                    tags, confidence, outcome, agent, session_refs, files, commits, \
                    created, updated, content_hash, signature_status, extras \
             FROM records WHERE id = ?1",
            params![id],
            |r| {
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
                })
            },
        )
        .optional()?;

    let Some(raw) = row else { return Ok(None) };
    let signature_status = SignatureStatus::from_db_str(&raw.signature_status);

    // Hide-policy: an unsigned record under `trust_policy = "hide"` returns
    // None unless the caller explicitly opts in via `include_unsigned`.
    if opts.trust_policy == "hide"
        && !opts.include_unsigned
        && signature_status != SignatureStatus::Verified
    {
        return Ok(None);
    }

    build_record(raw, signature_status).map(Some)
}

fn build_record(
    raw: RawRow,
    signature_status: SignatureStatus,
) -> Result<UnifiedRecord, QueryError> {
    let trust_basis = if signature_status == SignatureStatus::Verified {
        Some(TrustBasis::Current)
    } else {
        None
    };
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
             created, updated, content_hash, signature_status, indexed_at) \
             VALUES (?1, 'local', 'p', 'decision', ?1, '', '[]', '', 'manual', \
                     '[]', '[]', '[]', 'medium', \
                     '2026-04-29T00:00:00Z', '2026-04-29T00:00:00Z', 'h', ?2, '2026-04-29T00:01:00Z')",
            rusqlite::params![id, sig],
        )
        .unwrap();
    }

    #[test]
    fn get_missing_returns_none() {
        let (_dir, conn) = open();
        let res = get(&conn, "nope", &GetOpts::default()).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn get_signed_record_returns_full_record() {
        let (_dir, conn) = open();
        insert(&conn, "alpha", true);
        let res = get(
            &conn,
            "alpha",
            &GetOpts {
                include_unsigned: false,
                trust_policy: "warn-but-show".into(),
            },
        )
        .unwrap();
        let r = res.unwrap();
        assert_eq!(r.id, "alpha");
        assert_eq!(r.provenance.signature_status, SignatureStatus::Verified);
    }

    #[test]
    fn get_unsigned_under_hide_policy_returns_none_unless_overridden() {
        let (_dir, conn) = open();
        insert(&conn, "u", false);
        let hide_default = GetOpts {
            include_unsigned: false,
            trust_policy: "hide".into(),
        };
        assert!(get(&conn, "u", &hide_default).unwrap().is_none());
        let hide_override = GetOpts {
            include_unsigned: true,
            trust_policy: "hide".into(),
        };
        assert!(get(&conn, "u", &hide_override).unwrap().is_some());
    }

    #[test]
    fn get_unsigned_under_warn_but_show_returns_record() {
        let (_dir, conn) = open();
        insert(&conn, "u", false);
        let res = get(
            &conn,
            "u",
            &GetOpts {
                include_unsigned: false,
                trust_policy: "warn-but-show".into(),
            },
        )
        .unwrap();
        assert!(res.is_some());
    }
}
