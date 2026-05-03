//! `list(conn, filters, limit, cursor)` — paginated list with filter pushdown.
//! Sort order: `updated DESC, rowid DESC` for stable pagination.

use rusqlite::Connection;

use super::{
    search::build_filter_sql,
    types::{
        Filters, Meta, MetaSourceCounts, MetaTrustBasisSummary, MetaTrustSummary, QueryError,
        ResultSet, SearchResult,
    },
};
use crate::records::{RecordType, SignatureStatus, Source, TrustBasis};

/// Paginated list with `(updated DESC, rowid DESC)` ordering.
///
/// # Errors
/// Returns `QueryError::Rusqlite` on rusqlite failure;
/// `QueryError::InvalidFilter` if the cursor is malformed.
pub fn list(
    conn: &Connection,
    filters: &Filters,
    limit: u32,
    cursor: Option<&str>,
) -> Result<ResultSet, QueryError> {
    let (filter_sql, filter_params) = build_filter_sql(filters);

    // Param layout matches `build_filter_sql`'s contract: `?1` = cursor
    // (opaque rowid; `i64::MAX` when no cursor, which is a non-restrictive
    // bound under `records.rowid < ?1`), `?2` = limit, filters start at `?3`.
    let cursor_value: i64 = match cursor {
        Some(c) => c.parse().map_err(|_| QueryError::InvalidFilter {
            detail: format!("invalid cursor: {c}"),
        })?,
        None => i64::MAX,
    };
    let mut params: Vec<rusqlite::types::Value> = Vec::new();
    params.push(rusqlite::types::Value::Integer(cursor_value));
    params.push(rusqlite::types::Value::Integer(i64::from(limit + 1)));
    for p in filter_params {
        params.push(p);
    }

    let sql = format!(
        "SELECT records.rowid, records.id, records.record_type, records.title, records.summary, \
                records.source, records.project_id, records.signature_status, records.updated \
         FROM records \
         WHERE records.rowid < ?1 {filter_sql} \
         ORDER BY records.updated DESC, records.rowid DESC \
         LIMIT ?2"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params.iter()), |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, String>(8)?,
            ))
        })?
        .flatten();

    let mut accumulated: Vec<(i64, SearchResult)> = Vec::new();
    for (rowid, id, rt, title, summary, source, project_id, sig, updated) in rows {
        let signature_status = parse_signature_status(&sig);
        let trust_basis = if signature_status == SignatureStatus::Verified {
            Some(TrustBasis::Current)
        } else {
            None
        };
        let mut warnings: Vec<String> = Vec::new();
        if signature_status != SignatureStatus::Verified {
            warnings.push("unsigned".into());
        }
        accumulated.push((
            rowid,
            SearchResult {
                id,
                record_type: parse_record_type(&rt),
                title,
                summary,
                score: 0.0,
                source: parse_source(&source),
                project_id,
                signature_status,
                trust_basis,
                warnings,
                body: None,
                updated,
            },
        ));
    }

    let next_cursor: Option<String> = if accumulated.len() > usize::try_from(limit).unwrap_or(0) {
        let pivot = accumulated.pop();
        pivot.map(|(rowid, _)| rowid.to_string())
    } else {
        None
    };
    let results: Vec<SearchResult> = accumulated.into_iter().map(|(_, r)| r).collect();
    let total = u32::try_from(results.len()).unwrap_or(u32::MAX);

    let meta = build_meta(conn, &results)?;
    Ok(ResultSet {
        results,
        total_matched: total,
        next_cursor,
        meta,
    })
}

fn build_meta(conn: &Connection, results: &[SearchResult]) -> Result<Meta, QueryError> {
    let local: i64 = conn.query_row(
        "SELECT count(*) FROM records WHERE source = 'local'",
        [],
        |r| r.get(0),
    )?;
    let cc: i64 = conn.query_row(
        "SELECT count(*) FROM records WHERE source = 'cc-native'",
        [],
        |r| r.get(0),
    )?;
    let codex: i64 = conn.query_row(
        "SELECT count(*) FROM records WHERE source = 'codex-native'",
        [],
        |r| r.get(0),
    )?;
    let mut ts = MetaTrustSummary::default();
    let mut tbs = MetaTrustBasisSummary::default();
    for r in results {
        match r.signature_status {
            SignatureStatus::Verified => {
                ts.verified += 1;
                tbs.current += 1;
            }
            SignatureStatus::Unsigned => ts.unsigned += 1,
            SignatureStatus::Invalid => ts.invalid += 1,
            SignatureStatus::Unknown => ts.unknown += 1,
        }
    }
    Ok(Meta {
        source_counts: MetaSourceCounts {
            local: u32::try_from(local).unwrap_or(u32::MAX),
            cc_native: u32::try_from(cc).unwrap_or(u32::MAX),
            codex_native: u32::try_from(codex).unwrap_or(u32::MAX),
        },
        trust_policy: "warn-but-show".into(),
        trust_summary: ts,
        trust_basis_summary: tbs,
        policy_warnings: Vec::new(),
        embed_pool_saturated: false,
        saturation_wait_ms: 0,
    })
}

fn parse_signature_status(s: &str) -> SignatureStatus {
    match s {
        "verified" => SignatureStatus::Verified,
        "invalid" => SignatureStatus::Invalid,
        "unknown" => SignatureStatus::Unknown,
        _ => SignatureStatus::Unsigned,
    }
}

fn parse_record_type(s: &str) -> RecordType {
    match s {
        "decision" => RecordType::Decision,
        "recommendation" => RecordType::Recommendation,
        "failure" => RecordType::Failure,
        _ => RecordType::Untyped,
    }
}

fn parse_source(s: &str) -> Source {
    match s {
        "local" => Source::Local,
        "cc-native" => Source::CcNative,
        _ => Source::CodexNative,
    }
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

    fn insert(conn: &rusqlite::Connection, id: &str, updated: &str) {
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, session_refs, files, commits, confidence, \
             created, updated, content_hash, signature_status, indexed_at) \
             VALUES (?1, 'local', 'p', 'decision', ?1, '', '[]', '', 'manual', \
                     '[]', '[]', '[]', 'medium', \
                     '2026-01-01T00:00:00Z', ?2, 'h', 'verified', '2026-04-29T00:01:00Z')",
            rusqlite::params![id, updated],
        )
        .unwrap();
    }

    #[test]
    fn list_returns_results_in_updated_desc_order() {
        let (_dir, conn) = open();
        insert(&conn, "older", "2026-01-01T00:00:00Z");
        insert(&conn, "newer", "2026-04-01T00:00:00Z");
        let rs = list(&conn, &Filters::default(), 10, None).unwrap();
        assert_eq!(rs.results[0].id, "newer");
        assert_eq!(rs.results[1].id, "older");
    }

    #[test]
    fn list_pagination_yields_next_cursor_when_over_limit() {
        let (_dir, conn) = open();
        for i in 0..5 {
            insert(
                &conn,
                &format!("r{i}"),
                &format!("2026-04-{:02}T00:00:00Z", i + 1),
            );
        }
        let rs = list(&conn, &Filters::default(), 3, None).unwrap();
        assert_eq!(rs.results.len(), 3);
        assert!(rs.next_cursor.is_some());
    }

    #[test]
    fn list_filter_by_record_type_pushes_into_sql() {
        let (_dir, conn) = open();
        insert(&conn, "d1", "2026-04-01T00:00:00Z");
        // Insert a recommendation manually so the filter has a target.
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, session_refs, files, commits, confidence, created, updated, \
             content_hash, signature_status, indexed_at) VALUES \
             ('r1', 'local', 'p', 'recommendation', 't', '', '[]', '', 'manual', '[]', '[]', '[]', \
              'medium', '2026-04-01T00:00:00Z', '2026-04-01T00:00:00Z', 'h', 'verified', '2026-04-29T00:01:00Z')",
            [],
        )
        .unwrap();
        let filters = Filters {
            record_type: Some(crate::records::RecordType::Recommendation),
            ..Filters::default()
        };
        let rs = list(&conn, &filters, 10, None).unwrap();
        assert_eq!(rs.results.len(), 1);
        assert_eq!(rs.results[0].id, "r1");
    }
}
