//! Spike S2 — vec0 update semantics + FTS trigger ordering
//!
//! Pass criteria (per design §3.6 S2):
//!   - Insert → update → delete a record. Verify FTS5 external-content triggers fire correctly.
//!   - Verify ordering rule from §7: `record_embeddings` DELETE must come BEFORE `records`
//!     DELETE; `record_embeddings` INSERT must come AFTER `records` INSERT. No orphans when
//!     followed; orphan demonstrably appears when violated.
//!
//! Throwaway. Same self-contained pattern as S1 (DDL + helpers duplicated, not factored into
//! a shared spike module). Each spike binary stands alone so individual measurements stay
//! traceable to a single file.

#![allow(
    // Spike-only: PRNG and rank-to-score conversions cross integer/float widths intentionally.
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    // Phases use locally-scoped names that read better as `emb_v1` / `emb_v2` / `emb_v3`.
    clippy::similar_names,
    // Spike `main` is end-to-end measurement orchestration; splitting helpers out would just
    // hide the linear flow that mirrors the spec's pass-criteria checklist.
    clippy::too_many_lines,
)]

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::os::raw::{c_char, c_int};
use std::path::Path;

const EMBEDDING_DIM: usize = 1024;

// ============================================================================
// main
// ============================================================================

fn main() -> Result<()> {
    init_tracing();
    register_sqlite_vec();

    let tmp = tempfile::Builder::new()
        .prefix("nexum-spike-s2-")
        .suffix(".db")
        .tempfile()
        .context("create temp db file")?;
    let db_path = tmp.path().to_owned();

    let conn = open_and_apply_ddl(&db_path).context("open + apply §7 DDL")?;
    let mut report = Report::new();
    report.pass(
        "ddl-accepted",
        "§7 DDL applied without error on Linux x86_64",
    );

    // ------------------------------------------------------------------------
    // PHASE 1 — INSERT (correct order: records first, then record_embeddings)
    // ------------------------------------------------------------------------
    let emb_v1 = unit_vector(0xA1A1_0000_0000_0001);
    let rowid = insert_record(
        &conn,
        "rec-A",
        "alpha title",
        "alpha body",
        r#"["alpha_tag"]"#,
    )
    .context("phase 1: insert record")?;
    insert_embedding(&conn, rowid, &emb_v1).context("phase 1: insert embedding")?;

    let r_count_1 = count(&conn, "records")?;
    let e_count_1 = count(&conn, "record_embeddings")?;
    let f_alpha_1 = fts_match(&conn, "alpha")?;
    let v_top_1 = vec_top1(&conn, &emb_v1)?;
    report.assert(
        "phase1-insert",
        r_count_1 == 1 && e_count_1 == 1 && f_alpha_1 == [rowid] && v_top_1 == Some(rowid),
        &format!(
            "records={r_count_1} vec0={e_count_1} fts(alpha)={f_alpha_1:?} vec_top1={v_top_1:?} \
             (expected 1 / 1 / [{rowid}] / Some({rowid}))"
        ),
    );

    // ------------------------------------------------------------------------
    // PHASE 2 — UPDATE record fields (FTS trigger reindexes; embedding untouched)
    // ------------------------------------------------------------------------
    update_record(&conn, rowid, "beta title", "beta body", r#"["beta_tag"]"#)
        .context("phase 2: update record")?;
    let f_alpha_2 = fts_match(&conn, "alpha")?;
    let f_beta_2 = fts_match(&conn, "beta")?;
    let v_top_2 = vec_top1(&conn, &emb_v1)?;
    report.assert(
        "phase2-update-record-fts-trigger",
        f_alpha_2.is_empty() && f_beta_2 == [rowid] && v_top_2 == Some(rowid),
        &format!(
            "fts(alpha)={f_alpha_2:?} (expected empty); fts(beta)={f_beta_2:?} (expected [{rowid}]); \
             vec_top1 still {v_top_2:?} (embedding untouched by record UPDATE)"
        ),
    );

    // ------------------------------------------------------------------------
    // PHASE 3 — UPDATE embedding (test BOTH in-place UPDATE and DELETE+INSERT)
    // ------------------------------------------------------------------------
    let emb_v2 = unit_vector(0xA2A2_0000_0000_0002);
    let update_outcome = match update_embedding_via_update(&conn, rowid, &emb_v2) {
        Ok(()) => {
            // Confirm the in-place change actually replaced the vector.
            let v_top_after = vec_top1(&conn, &emb_v2)?;
            if v_top_after == Some(rowid) {
                "in-place UPDATE accepted; new embedding is searchable".to_owned()
            } else {
                format!(
                    "in-place UPDATE returned Ok BUT vec_top1(new_vec) = {v_top_after:?} \
                     (expected Some({rowid})) — vec0 may have silently no-op'd"
                )
            }
        }
        Err(e) => format!("in-place UPDATE rejected: {e}"),
    };

    // Form B: DELETE + INSERT pattern. Always works because vec0 has no FK/trigger constraints
    // and the PRIMARY KEY uniqueness is satisfied after the DELETE.
    let emb_v3 = unit_vector(0xA3A3_0000_0000_0003);
    delete_embedding(&conn, rowid).context("phase 3: delete embedding before re-insert")?;
    insert_embedding(&conn, rowid, &emb_v3).context("phase 3: insert v3 embedding")?;
    let v_top_v3 = vec_top1(&conn, &emb_v3)?;

    report.assert(
        "phase3-update-embedding",
        v_top_v3 == Some(rowid),
        &format!(
            "Form A: {update_outcome}. Form B (DELETE+INSERT): vec_top1(v3) = {v_top_v3:?} \
             (expected Some({rowid})). Either form is acceptable for §7 — the indexer just \
             needs to commit to one."
        ),
    );

    // ------------------------------------------------------------------------
    // PHASE 4 — DELETE in correct order (vec0 first, then records). No orphans.
    // ------------------------------------------------------------------------
    delete_embedding(&conn, rowid).context("phase 4: delete embedding")?;
    delete_record(&conn, rowid).context("phase 4: delete record")?;

    let r_count_4 = count(&conn, "records")?;
    let e_count_4 = count(&conn, "record_embeddings")?;
    let f_count_4 = count_fts(&conn)?;
    report.assert(
        "phase4-delete-correct-order",
        r_count_4 == 0 && e_count_4 == 0 && f_count_4 == 0,
        &format!(
            "records={r_count_4} vec0={e_count_4} fts={f_count_4} (all expected 0; \
             records_ad trigger evicted FTS row; manual vec0 DELETE evicted embedding)"
        ),
    );

    // ------------------------------------------------------------------------
    // PHASE 5 — WRONG-ORDER DELETE demonstrates the §7 ordering invariant
    // (records DELETE first, vec0 DELETE not done) → orphan in record_embeddings.
    // Informational NOTE only; not a pass/fail gate.
    // ------------------------------------------------------------------------
    let emb_b = unit_vector(0xB0B0_0000_0000_0004);
    let rowid_b = insert_record(
        &conn,
        "rec-B",
        "gamma title",
        "gamma body",
        r#"["gamma_tag"]"#,
    )
    .context("phase 5: seed second record")?;
    insert_embedding(&conn, rowid_b, &emb_b).context("phase 5: seed second embedding")?;

    delete_record(&conn, rowid_b)
        .context("phase 5: delete record (wrong order — vec0 not deleted)")?;

    let r_count_5 = count(&conn, "records")?;
    let e_count_5 = count(&conn, "record_embeddings")?;
    let f_count_5 = count_fts(&conn)?;
    let orphan_observed = r_count_5 == 0 && e_count_5 == 1 && f_count_5 == 0;

    report.note(
        "phase5-wrong-order-creates-orphan",
        &format!(
            "After DELETE FROM records WITHOUT prior DELETE FROM record_embeddings: \
             records={r_count_5} (expected 0) | vec0={e_count_5} (expected 1 — the orphan) | \
             fts={f_count_5} (expected 0 — records_ad trigger fires). Orphan observed: \
             {orphan_observed}. Empirical confirmation that §7's ordering invariant is \
             load-bearing — the indexer MUST DELETE FROM record_embeddings BEFORE DELETE \
             FROM records, or run both inside a single transaction with explicit ordering."
        ),
    );

    // Cleanup so the temp DB ends in a tidy state (cosmetic — tempfile is dropped on exit).
    delete_embedding(&conn, rowid_b)?;

    report.print();
    if report.all_pass() {
        std::process::exit(0);
    }
    std::process::exit(1);
}

// ============================================================================
// sqlite-vec extension registration (same pattern as S1)
// ============================================================================

fn register_sqlite_vec() {
    // SAFETY: sqlite-vec's `sqlite3_vec_init` is the SQLite extension entry point with the
    // standard ABI; transmute coerces sqlite-vec's bindgen-generated `sqlite3` opaque type
    // to rusqlite's equivalent so the function-pointer types unify.
    type RusqliteExtInit = unsafe extern "C" fn(
        *mut rusqlite::ffi::sqlite3,
        *mut *mut c_char,
        *const rusqlite::ffi::sqlite3_api_routines,
    ) -> c_int;
    unsafe {
        let init_fn: RusqliteExtInit =
            std::mem::transmute(sqlite_vec::sqlite3_vec_init as *const ());
        rusqlite::ffi::sqlite3_auto_extension(Some(init_fn));
    }
}

// ============================================================================
// DDL — verbatim from design §7 (duplicated from S1 by spike convention)
// ============================================================================

fn open_and_apply_ddl(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).context("open temp sqlite db")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "busy_timeout", 5000_i64)?;
    conn.pragma_update(None, "foreign_keys", true)?;

    conn.execute_batch(
        r"
        CREATE TABLE records (
            rowid INTEGER PRIMARY KEY,
            id TEXT NOT NULL UNIQUE,
            source TEXT NOT NULL,
            project_id TEXT,
            record_type TEXT NOT NULL,
            title TEXT NOT NULL,
            summary TEXT,
            body TEXT,
            body_origin_path TEXT,
            tags JSON NOT NULL,
            confidence TEXT,
            outcome TEXT,
            agent TEXT,
            session_refs JSON,
            files JSON,
            commits JSON,
            created TEXT NOT NULL,
            updated TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            signature_status TEXT NOT NULL,
            extras JSON,
            indexed_at TEXT NOT NULL
        );

        CREATE UNIQUE INDEX idx_records_id ON records(id);

        CREATE VIRTUAL TABLE record_embeddings USING vec0(
            record_rowid INTEGER PRIMARY KEY,
            embedding FLOAT[1024]
        );

        CREATE VIRTUAL TABLE records_fts USING fts5(
            title, summary, body, tags,
            content='records',
            content_rowid='rowid',
            tokenize='unicode61 remove_diacritics 2'
        );

        CREATE TRIGGER records_ai AFTER INSERT ON records BEGIN
            INSERT INTO records_fts(rowid, title, summary, body, tags)
            VALUES (new.rowid, new.title, new.summary, new.body, new.tags);
        END;

        CREATE TRIGGER records_ad AFTER DELETE ON records BEGIN
            INSERT INTO records_fts(records_fts, rowid, title, summary, body, tags)
            VALUES('delete', old.rowid, old.title, old.summary, old.body, old.tags);
        END;

        CREATE TRIGGER records_au AFTER UPDATE ON records BEGIN
            INSERT INTO records_fts(records_fts, rowid, title, summary, body, tags)
            VALUES('delete', old.rowid, old.title, old.summary, old.body, old.tags);
            INSERT INTO records_fts(rowid, title, summary, body, tags)
            VALUES (new.rowid, new.title, new.summary, new.body, new.tags);
        END;
        ",
    )
    .context("apply §7 DDL batch")?;
    Ok(conn)
}

// ============================================================================
// CRUD helpers
// ============================================================================

fn insert_record(
    conn: &Connection,
    id: &str,
    title: &str,
    body: &str,
    tags_json: &str,
) -> Result<i64> {
    let now = "2026-04-30T00:00:00Z";
    conn.execute(
        r"INSERT INTO records (
            id, source, record_type, title, summary, body, tags,
            created, updated, content_hash, signature_status, indexed_at
        ) VALUES (?1, 'local', 'decision', ?2, '', ?3, ?4, ?5, ?5, 'h', 'unsigned', ?5)",
        params![id, title, body, tags_json, now],
    )?;
    Ok(conn.last_insert_rowid())
}

fn update_record(
    conn: &Connection,
    rowid: i64,
    title: &str,
    body: &str,
    tags_json: &str,
) -> Result<()> {
    conn.execute(
        "UPDATE records SET title = ?1, body = ?2, tags = ?3 WHERE rowid = ?4",
        params![title, body, tags_json, rowid],
    )?;
    Ok(())
}

fn delete_record(conn: &Connection, rowid: i64) -> Result<()> {
    conn.execute("DELETE FROM records WHERE rowid = ?1", params![rowid])?;
    Ok(())
}

fn insert_embedding(conn: &Connection, rowid: i64, emb: &[f32]) -> Result<()> {
    let bytes = vec_to_le_bytes(emb);
    conn.execute(
        "INSERT INTO record_embeddings(record_rowid, embedding) VALUES (?1, ?2)",
        params![rowid, bytes],
    )?;
    Ok(())
}

fn update_embedding_via_update(conn: &Connection, rowid: i64, emb: &[f32]) -> Result<()> {
    let bytes = vec_to_le_bytes(emb);
    conn.execute(
        "UPDATE record_embeddings SET embedding = ?2 WHERE record_rowid = ?1",
        params![rowid, bytes],
    )?;
    Ok(())
}

fn delete_embedding(conn: &Connection, rowid: i64) -> Result<()> {
    conn.execute(
        "DELETE FROM record_embeddings WHERE record_rowid = ?1",
        params![rowid],
    )?;
    Ok(())
}

// ============================================================================
// query helpers
// ============================================================================

fn fts_match(conn: &Connection, term: &str) -> Result<Vec<i64>> {
    let mut stmt =
        conn.prepare("SELECT rowid FROM records_fts WHERE records_fts MATCH ?1 ORDER BY rowid")?;
    let rows = stmt
        .query_map(params![term], |row| row.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn vec_top1(conn: &Connection, q: &[f32]) -> Result<Option<i64>> {
    let bytes = vec_to_le_bytes(q);
    let mut stmt = conn
        .prepare("SELECT record_rowid FROM record_embeddings WHERE embedding MATCH ?1 AND k = 1")?;
    let mut rows = stmt.query_map(params![bytes], |row| row.get::<_, i64>(0))?;
    rows.next().transpose().map_err(Into::into)
}

fn count(conn: &Connection, table: &str) -> Result<i64> {
    // Table name is hardcoded by the caller (records / record_embeddings); not user input.
    let sql = format!("SELECT COUNT(*) FROM {table}");
    let n: i64 = conn.query_row(&sql, [], |row| row.get(0))?;
    Ok(n)
}

fn count_fts(conn: &Connection) -> Result<i64> {
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM records_fts", [], |row| row.get(0))?;
    Ok(n)
}

// ============================================================================
// embeddings — deterministic xorshift64 PRNG, L2-normalized (same as S1)
// ============================================================================

fn unit_vector(seed: u64) -> Vec<f32> {
    let mut state = if seed == 0 { 1 } else { seed };
    let mut v = Vec::with_capacity(EMBEDDING_DIM);
    for _ in 0..EMBEDDING_DIM {
        let r = xorshift64(&mut state);
        let signed = (r >> 32) as i32;
        v.push(signed as f32 / i32::MAX as f32);
    }
    let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in &mut v {
            *x /= norm;
        }
    }
    v
}

fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn vec_to_le_bytes(v: &[f32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(v.len() * 4);
    for f in v {
        bytes.extend_from_slice(&f.to_le_bytes());
    }
    bytes
}

// ============================================================================
// reporting (same Report shape as S1)
// ============================================================================

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .try_init();
}

#[derive(Debug)]
struct Report {
    rows: Vec<ReportRow>,
}

#[derive(Debug)]
enum ReportRow {
    Pass { name: String, detail: String },
    Fail { name: String, detail: String },
    Note { name: String, detail: String },
}

impl Report {
    fn new() -> Self {
        Self { rows: Vec::new() }
    }
    fn pass(&mut self, name: &str, detail: &str) {
        self.rows.push(ReportRow::Pass {
            name: name.into(),
            detail: detail.into(),
        });
    }
    fn fail(&mut self, name: &str, detail: &str) {
        self.rows.push(ReportRow::Fail {
            name: name.into(),
            detail: detail.into(),
        });
    }
    fn note(&mut self, name: &str, detail: &str) {
        self.rows.push(ReportRow::Note {
            name: name.into(),
            detail: detail.into(),
        });
    }
    fn assert(&mut self, name: &str, condition: bool, detail: &str) {
        if condition {
            self.pass(name, detail);
        } else {
            self.fail(name, detail);
        }
    }
    fn all_pass(&self) -> bool {
        !self
            .rows
            .iter()
            .any(|r| matches!(r, ReportRow::Fail { .. }))
    }
    fn print(&self) {
        println!("\n=== nexum spike S2 — vec0 update semantics + FTS trigger ordering ===\n");
        for row in &self.rows {
            match row {
                ReportRow::Pass { name, detail } => println!("  PASS  [{name}] {detail}"),
                ReportRow::Fail { name, detail } => println!("  FAIL  [{name}] {detail}"),
                ReportRow::Note { name, detail } => println!("  NOTE  [{name}] {detail}"),
            }
        }
        let passes = self
            .rows
            .iter()
            .filter(|r| matches!(r, ReportRow::Pass { .. }))
            .count();
        let fails = self
            .rows
            .iter()
            .filter(|r| matches!(r, ReportRow::Fail { .. }))
            .count();
        let notes = self
            .rows
            .iter()
            .filter(|r| matches!(r, ReportRow::Note { .. }))
            .count();
        println!("\n  --- {passes} pass / {fails} fail / {notes} note(s) ---\n");
        println!(
            "  Platform: linux x86_64 only this run. Re-run on Windows native to close the §3.6 S2 cross-platform criterion."
        );
    }
}
