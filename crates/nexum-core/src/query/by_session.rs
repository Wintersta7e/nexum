//! `by_session(conn, lookup)` — find records that reference a given CC
//! session UUID, Codex rollout path, or Codex thread id.

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

use super::{
    policy::{PolicyOpts, apply as apply_policy},
    types::{Filters, Meta, QueryError, ResultSet, SearchResult},
    verify::{CachedCrypto, ProjectedTrust, ProjectionContext},
};
use crate::records::{CryptoResult, RecordType, Source, TrustPolicy};

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
/// result set. The strict-revocation overlay rides on
/// [`Filters::strict_revocation`] (and `require_signed` on the same shape
/// applies the stricter override); the api facade fills both from
/// `cfg.trust.*`.
///
/// # Errors
/// Returns `QueryError::Rusqlite` on rusqlite failure;
/// `QueryError::Trust` if the chain-state hydration fails.
pub fn by_session(
    conn: &Connection,
    filters: &Filters,
    trust_policy: TrustPolicy,
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
                      records.source, records.project_id, records.crypto_result, records.updated, \
                      records.record_commit_sha, records.signer_fingerprint, \
                      records.relevant_trust_events_commit \
               FROM records \
               WHERE session_refs LIKE ?1 ESCAPE '\\' \
               ORDER BY records.updated DESC";
    let mut stmt = conn.prepare(sql)?;
    let raw_rows = stmt
        .query_map(params![pattern], |r| {
            Ok(SessionRow {
                id: r.get(0)?,
                record_type: r.get::<_, String>(1)?,
                title: r.get(2)?,
                summary: r.get::<_, Option<String>>(3)?,
                source: r.get::<_, String>(4)?,
                project_id: r.get(5)?,
                crypto_result: r.get::<_, String>(6)?,
                updated: r.get(7)?,
                record_commit_sha: r.get::<_, Option<String>>(8)?,
                signer_fingerprint: r.get::<_, Option<String>>(9)?,
                relevant_trust_events_commit: r.get::<_, Option<String>>(10)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    // Empty-result fast path: skip any further bookkeeping. Returning a
    // fresh `ResultSet` is also more honest — an empty session lookup
    // shouldn't paint the global meta envelope onto the response.
    if raw_rows.is_empty() {
        return Ok(ResultSet {
            results: Vec::new(),
            total_matched: 0,
            next_cursor: None,
            meta: Meta {
                trust_policy,
                ..Default::default()
            },
        });
    }

    // Hydrate the chain once per verb invocation. Reused for every row's
    // projection.
    let ctx = ProjectionContext::new(conn)?;

    // Project every row up-front so the policy filter and the SearchResult
    // shape both consume the same per-row trust state.
    let projected_rows: Vec<(SessionRow, ProjectedTrust)> =
        ctx.project_rows(raw_rows, filters.strict_revocation, |raw| CachedCrypto {
            crypto_result: CryptoResult::from_db_str(&raw.crypto_result),
            signer_fingerprint: raw.signer_fingerprint.as_deref(),
            commit_sha: raw.record_commit_sha.as_deref(),
            relevant_trust_events_commit: raw.relevant_trust_events_commit.as_deref(),
        })?;

    // Centralized warn/hide/strict policy filter.
    let policy_opts = PolicyOpts {
        policy: trust_policy,
        require_signed: filters.require_signed,
    };
    let mut outcome = apply_policy(projected_rows, policy_opts, |row| &row.1);

    // Pluck the visible rows so the policy bucket counters and warnings on
    // `outcome` survive the rest of the value being consumed by
    // `meta.apply_policy_outcome`.
    let visible = std::mem::take(&mut outcome.visible);
    let results: Vec<SearchResult> = visible
        .into_iter()
        .map(|(raw, projected)| SearchResult {
            id: raw.id,
            record_type: RecordType::from_db_str(&raw.record_type),
            title: raw.title,
            summary: raw.summary,
            score: 0.0,
            source: Source::from_db_str(&raw.source),
            project_id: raw.project_id,
            signature_status: projected.signature_status,
            trust_basis: projected.trust_basis,
            record_commit_sha: raw.record_commit_sha,
            signer_fingerprint: raw.signer_fingerprint,
            warnings: projected.warnings,
            body: None,
            updated: raw.updated,
        })
        .collect();

    let total = u32::try_from(results.len()).unwrap_or(u32::MAX);
    let mut meta = super::meta::build_meta_listing(conn, &results, trust_policy)?;
    meta.apply_policy_outcome(&outcome);

    Ok(ResultSet {
        results,
        total_matched: total,
        next_cursor: None,
        meta,
    })
}

/// Raw per-row read of a session-matching record. Mirrors the SELECT column
/// order; chain-state hydration runs once and the projection consumes one
/// `SessionRow` at a time.
struct SessionRow {
    id: String,
    record_type: String,
    title: String,
    summary: Option<String>,
    source: String,
    project_id: String,
    /// `records.crypto_result` SQL column (one of `good` / `bad-signature` /
    /// `unknown-signer` / `no-signature`).
    crypto_result: String,
    updated: String,
    record_commit_sha: Option<String>,
    signer_fingerprint: Option<String>,
    /// SHA of the events.yml commit effective at the record's commit time.
    /// Forwarded into [`CachedCrypto`] for the read-time projection.
    relevant_trust_events_commit: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::test_util::open_test_db_with_seeded_chain;

    fn insert(conn: &rusqlite::Connection, id: &str, session_refs_json: &str) {
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, session_refs, files, commits, confidence, outcome, created, updated, \
             content_hash, index_hash, crypto_result, indexed_at) VALUES \
             (?1, 'local', 'p', 'decision', ?1, '', '[]', '', 'manual', ?2, '[]', '[]', 'medium', \
              'working', '2026-04-29T00:00:00Z', '2026-04-29T00:00:00Z', 'h', 'ih', 'good', '2026-04-29T00:01:00Z')",
            rusqlite::params![id, session_refs_json],
        )
        .unwrap();
    }

    #[test]
    fn cc_session_lookup_matches_records() {
        let (_dir, conn) = open_test_db_with_seeded_chain();
        insert(
            &conn,
            "alpha",
            r#"[{"kind":"cc_session","uuid":"11111111-1111-4111-8111-111111111111"}]"#,
        );
        let res = by_session(
            &conn,
            &Filters::default(),
            TrustPolicy::WarnButShow,
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
        let (_dir, conn) = open_test_db_with_seeded_chain();
        insert(
            &conn,
            "beta",
            r#"[{"kind":"codex_thread","thread_id":"thread-aaa","rollout_path":null}]"#,
        );
        let res = by_session(
            &conn,
            &Filters::default(),
            TrustPolicy::WarnButShow,
            &SessionLookup::CodexThread {
                thread_id: "thread-aaa".into(),
            },
        )
        .unwrap();
        assert_eq!(res.results.len(), 1);
    }

    #[test]
    fn by_session_with_hide_filters_and_counts() {
        let (_dir, conn) = open_test_db_with_seeded_chain();
        // Insert one verified, one unsigned, and one invalid record that all
        // reference the same CC session UUID so the lookup exercises both
        // hidden buckets.
        let session_json =
            r#"[{"kind":"cc_session","uuid":"22222222-2222-4222-8222-222222222222"}]"#;
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, session_refs, files, commits, confidence, outcome, created, updated, \
             content_hash, index_hash, crypto_result, signer_fingerprint, \
             relevant_trust_events_commit, indexed_at) VALUES \
             (?1, 'local', 'p', 'decision', ?1, '', '[]', '', 'manual', ?2, '[]', '[]', 'medium', \
              'working', '2026-04-29T00:00:00Z', '2026-04-29T00:00:00Z', 'h', 'ih', 'good', \
              ?3, ?4, '2026-04-29T00:01:00Z')",
            rusqlite::params![
                "sv1",
                session_json,
                crate::query::test_util::TEST_BOOTSTRAP_FP,
                crate::query::test_util::TEST_TRUST_COMMIT,
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, session_refs, files, commits, confidence, outcome, created, updated, \
             content_hash, index_hash, crypto_result, indexed_at) VALUES \
             (?1, 'local', 'p', 'decision', ?1, '', '[]', '', 'manual', ?2, '[]', '[]', 'medium', \
              'working', '2026-04-29T00:00:00Z', '2026-04-29T00:00:00Z', 'h2', 'ih2', 'no-signature', '2026-04-29T00:01:00Z')",
            rusqlite::params!["su1", session_json],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO records (id, source, project_id, record_type, title, body, tags, \
             tags_fts, agent, session_refs, files, commits, confidence, outcome, created, updated, \
             content_hash, index_hash, crypto_result, indexed_at) VALUES \
             (?1, 'local', 'p', 'decision', ?1, '', '[]', '', 'manual', ?2, '[]', '[]', 'medium', \
              'working', '2026-04-29T00:00:00Z', '2026-04-29T00:00:00Z', 'h3', 'ih3', 'bad-signature', '2026-04-29T00:01:00Z')",
            rusqlite::params!["si1", session_json],
        )
        .unwrap();

        let res = by_session(
            &conn,
            &Filters::default(),
            TrustPolicy::Hide,
            &SessionLookup::CcSession {
                uuid: uuid::Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
            },
        )
        .unwrap();
        assert_eq!(
            res.results.len(),
            1,
            "only verified record visible under hide"
        );
        assert_eq!(res.results[0].id, "sv1");
        assert_eq!(res.meta.hidden_unsigned, 1);
        assert_eq!(res.meta.hidden_invalid, 1);
        assert_eq!(res.meta.trust_policy, TrustPolicy::Hide);
    }

    #[test]
    fn trust_policy_round_trips_into_meta() {
        let (_dir, conn) = open_test_db_with_seeded_chain();
        let res = by_session(
            &conn,
            &Filters::default(),
            TrustPolicy::WarnButShow,
            &SessionLookup::CcSession {
                uuid: uuid::Uuid::nil(),
            },
        )
        .unwrap();
        assert_eq!(res.meta.trust_policy, TrustPolicy::WarnButShow);
        let res = by_session(
            &conn,
            &Filters::default(),
            TrustPolicy::Hide,
            &SessionLookup::CcSession {
                uuid: uuid::Uuid::nil(),
            },
        )
        .unwrap();
        assert_eq!(res.meta.trust_policy, TrustPolicy::Hide);
    }

    #[test]
    fn unknown_session_returns_empty() {
        let (_dir, conn) = open_test_db_with_seeded_chain();
        let res = by_session(
            &conn,
            &Filters::default(),
            TrustPolicy::WarnButShow,
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
        let (_dir, conn) = open_test_db_with_seeded_chain();
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
            &Filters::default(),
            TrustPolicy::WarnButShow,
            &SessionLookup::CodexRollout {
                path: std::path::PathBuf::from(real_path),
            },
        )
        .unwrap();
        let ids: Vec<&str> = res.results.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["gamma"], "expected exact-only match, got {ids:?}");
    }
}
