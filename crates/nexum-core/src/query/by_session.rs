//! `by_session(conn, lookup)` — find records that reference a given CC
//! session UUID, Codex rollout path, or Codex thread id.

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

use super::types::{Meta, QueryError, ResultSet, SearchResult};
use crate::records::{RecordType, SignatureStatus, Source, TrustBasis};

/// Discriminator for [`by_session`] queries — names the kind of session
/// reference to look up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionLookup {
    /// CC session UUID written by the CC native adapter.
    CcSession { uuid: uuid::Uuid },
    /// Codex rollout file path (e.g. `/path/to/rollout.jsonl`).
    CodexRollout { path: std::path::PathBuf },
    /// Codex thread id, e.g. `thread-abc123`.
    CodexThread { thread_id: String },
}

/// Escape SQL `LIKE` wildcards (`%`, `_`) and the escape char itself
/// (`\`) so the needle is treated as a literal substring. Pair with
/// `ESCAPE '\\'` on the LIKE clause.
///
/// Order matters: backslashes must be doubled FIRST so the subsequent
/// substitutions are not themselves re-escaped.
fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Find records that reference the given session.
///
/// One SELECT against `records` projects the result rows directly; an empty
/// match short-circuits without any further round-trip to keep `by_session`
/// cheap on the common "no such session" path.
///
/// `trust_policy` is reflected verbatim in the response envelope's
/// `_meta.trust_policy` so callers see the runtime policy that produced the
/// result set.
///
/// # Errors
/// Returns `QueryError::Rusqlite` on rusqlite failure.
pub fn by_session(
    conn: &Connection,
    trust_policy: &str,
    lookup: &SessionLookup,
) -> Result<ResultSet, QueryError> {
    let needle = match lookup {
        // SessionRef JSON wire shape: `{"kind": "<snake_case>", "<field>": "<value>"}`.
        // Match the field-name + value pair rather than `kind` alone (multiple
        // variants can share kind values across different records).
        SessionLookup::CcSession { uuid } => format!("\"uuid\":\"{uuid}\""),
        SessionLookup::CodexRollout { path } => format!("\"path\":\"{}\"", path.display()),
        SessionLookup::CodexThread { thread_id } => format!("\"thread_id\":\"{thread_id}\""),
    };
    // Escape LIKE wildcards in the needle so paths / thread ids that
    // contain `%` or `_` cannot silently broaden the match. All three
    // variants are escaped (defense in depth) — uuids are unlikely to
    // contain wildcards, but a malformed thread_id from upstream
    // tooling could.
    let escaped = escape_like(&needle);
    let pattern = format!("%{escaped}%");
    let sql = "SELECT records.id, records.record_type, records.title, records.summary, \
                      records.source, records.project_id, records.signature_status, records.updated \
               FROM records \
               WHERE session_refs LIKE ?1 ESCAPE '\\' \
               ORDER BY records.updated DESC";
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(params![pattern], |r| {
        Ok(SearchResult {
            id: r.get(0)?,
            record_type: RecordType::from_db_str(&r.get::<_, String>(1)?),
            title: r.get(2)?,
            summary: r.get::<_, Option<String>>(3)?,
            score: 0.0,
            source: Source::from_db_str(&r.get::<_, String>(4)?),
            project_id: r.get(5)?,
            signature_status: SignatureStatus::from_db_str(&r.get::<_, String>(6)?),
            trust_basis: None,
            warnings: Vec::new(),
            body: None,
            updated: r.get(7)?,
        })
    })?;
    let mut results: Vec<SearchResult> = rows.flatten().collect();

    // Empty-result fast path: skip the trust-basis loop and any further
    // bookkeeping. Returning a fresh `ResultSet` is also more honest — an
    // empty session lookup shouldn't paint the global meta envelope onto
    // the response.
    if results.is_empty() {
        return Ok(ResultSet {
            results,
            total_matched: 0,
            next_cursor: None,
            meta: Meta {
                trust_policy: trust_policy.to_owned(),
                ..Default::default()
            },
        });
    }

    for r in &mut results {
        if r.signature_status == SignatureStatus::Verified {
            r.trust_basis = Some(TrustBasis::Current);
        } else {
            r.warnings.push("unsigned".into());
        }
    }
    let total = u32::try_from(results.len()).unwrap_or(u32::MAX);

    Ok(ResultSet {
        results,
        total_matched: total,
        next_cursor: None,
        meta: Meta {
            trust_policy: trust_policy.to_owned(),
            ..Default::default()
        },
    })
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

    fn insert(conn: &rusqlite::Connection, id: &str, session_refs_json: &str) {
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, session_refs, files, commits, confidence, created, updated, \
             content_hash, signature_status, indexed_at) VALUES \
             (?1, 'local', 'p', 'decision', ?1, '', '[]', '', 'manual', ?2, '[]', '[]', 'medium', \
              '2026-04-29T00:00:00Z', '2026-04-29T00:00:00Z', 'h', 'verified', '2026-04-29T00:01:00Z')",
            rusqlite::params![id, session_refs_json],
        )
        .unwrap();
    }

    #[test]
    fn cc_session_lookup_matches_records() {
        let (_dir, conn) = open();
        insert(
            &conn,
            "alpha",
            r#"[{"kind":"cc_session","uuid":"11111111-1111-4111-8111-111111111111"}]"#,
        );
        let res = by_session(
            &conn,
            "warn-but-show",
            &SessionLookup::CcSession {
                uuid: uuid::Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
            },
        )
        .unwrap();
        assert_eq!(res.results.len(), 1);
        assert_eq!(res.results[0].id, "alpha");
    }

    #[test]
    fn codex_thread_lookup_matches_records() {
        let (_dir, conn) = open();
        insert(
            &conn,
            "beta",
            r#"[{"kind":"codex_thread","thread_id":"thread-aaa","rollout_path":null}]"#,
        );
        let res = by_session(
            &conn,
            "warn-but-show",
            &SessionLookup::CodexThread {
                thread_id: "thread-aaa".into(),
            },
        )
        .unwrap();
        assert_eq!(res.results.len(), 1);
    }

    #[test]
    fn trust_policy_round_trips_into_meta() {
        let (_dir, conn) = open();
        let res = by_session(
            &conn,
            "warn-but-show",
            &SessionLookup::CcSession {
                uuid: uuid::Uuid::nil(),
            },
        )
        .unwrap();
        assert_eq!(res.meta.trust_policy, "warn-but-show");
        let res = by_session(
            &conn,
            "hide",
            &SessionLookup::CcSession {
                uuid: uuid::Uuid::nil(),
            },
        )
        .unwrap();
        assert_eq!(res.meta.trust_policy, "hide");
    }

    #[test]
    fn unknown_session_returns_empty() {
        let (_dir, conn) = open();
        let res = by_session(
            &conn,
            "warn-but-show",
            &SessionLookup::CcSession {
                uuid: uuid::Uuid::nil(),
            },
        )
        .unwrap();
        assert_eq!(res.results.len(), 0);
    }

    /// `CodexRollout` lookup matches by path. The path in this test
    /// includes both `_` and `%` so the LIKE-wildcard escape is exercised
    /// — without `escape_like` + `ESCAPE '\\'` on the LIKE clause, the
    /// `%` would broaden the match and the `_` would match any single
    /// character, both of which would yield false positives.
    #[test]
    fn codex_rollout_lookup_matches_records_with_wildcard_chars_in_path() {
        let (_dir, conn) = open();
        // Use forward slashes so the test runs identically on Windows
        // and Linux. `Path::display()` won't transform forward slashes
        // on either platform.
        let real_path = "/tmp/path_with_underscore_and_%pct.jsonl";
        // Minimal codex_rollout SessionRef JSON wire shape.
        let session_refs_json = format!(r#"[{{"kind":"codex_rollout","path":"{real_path}"}}]"#);
        insert(&conn, "gamma", &session_refs_json);

        // Insert a decoy whose path differs from the target only at the
        // `_` and `%` positions. If the wildcards weren't escaped, the
        // decoy would match too because `%` consumes any sequence and
        // `_` consumes any single character.
        let decoy_path = "/tmp/pathXwithXunderscoreXandXFOOpct.jsonl";
        let decoy_json = format!(r#"[{{"kind":"codex_rollout","path":"{decoy_path}"}}]"#);
        insert(&conn, "decoy", &decoy_json);

        let res = by_session(
            &conn,
            "warn-but-show",
            &SessionLookup::CodexRollout {
                path: std::path::PathBuf::from(real_path),
            },
        )
        .unwrap();
        let ids: Vec<&str> = res.results.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["gamma"], "expected exact-only match, got {ids:?}");
    }
}
