//! Spike S1 — sqlite-vec DDL + tag-heavy query
//!
//! Pass criteria (per design §3.6 S1, validated against §7 DDL):
//!   - §7 DDL accepted on Linux x86_64. Windows verification deferred to a Windows-side run.
//!   - Vector query, FTS query, hybrid (RRF) query, AND a tag-heavy query all return correct
//!     results against a 100-record fake corpus with a controlled tag distribution.
//!   - Tag-heavy query (`tags MATCH "concurrency database"`) exercises FTS over JSON-shaped
//!     tags (per Codex v3 🟠#1). With the seeded distribution it must return exactly N_BOTH
//!     records — neither more (false positives from FTS-over-JSON noise) nor fewer (failed
//!     tokenization of the JSON form).
//!
//! Throwaway. Delete once results are folded into the spike-results doc and any §7 deltas
//! are landed in the spec.

#![allow(
    // Spike-only: PRNG and rank-to-score conversions cross integer/float widths intentionally.
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    // The spike runs forms A and B side-by-side; renaming would hurt the spike's readability.
    clippy::similar_names,
    // Spike `main` is end-to-end measurement orchestration — splitting into helpers would
    // obscure the linear flow that mirrors the spec's pass-criteria checklist.
    clippy::too_many_lines,
)]

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, params};
use std::collections::HashMap;
use std::os::raw::{c_char, c_int};
use std::path::Path;

const EMBEDDING_DIM: usize = 1024;
const N_RECORDS: usize = 100;
const RRF_K: f32 = 60.0;
const TOP_K_PER_SOURCE: usize = 20;

// Controlled tag distribution (sums to N_RECORDS). The tag-heavy query expects exactly
// N_BOTH hits because that's the count of records carrying both `concurrency` AND `database`
// in their `tags` column.
const N_CONCURRENCY_ONLY: usize = 15;
const N_DATABASE_ONLY: usize = 15;
const N_BOTH: usize = 5;
const N_NEITHER: usize = N_RECORDS - N_CONCURRENCY_ONLY - N_DATABASE_ONLY - N_BOTH;

const FTS_TERM: &str = "concurrency";
const TAG_HEAVY_QUERY: &str = "concurrency database";

// ============================================================================
// main
// ============================================================================

fn main() -> Result<()> {
    init_tracing();

    register_sqlite_vec();

    let tmp = tempfile::Builder::new()
        .prefix("nexum-spike-s1-")
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

    let plan = seed_corpus(&conn).context("seed 100-record corpus")?;
    report.pass(
        "corpus-seeded",
        &format!(
            "{N_RECORDS} records inserted ({N_CONCURRENCY_ONLY} concurrency-only / \
             {N_DATABASE_ONLY} database-only / {N_BOTH} both / {N_NEITHER} neither)"
        ),
    );

    // -- Vector query ---------------------------------------------------------
    // Synthesize a query embedding by averaging the embeddings of the "both" cohort —
    // those records should rank highest in the vector query.
    let q_emb = average_embedding(&plan.both_seeds);
    let v_results = vector_query(&conn, &q_emb, TOP_K_PER_SOURCE)?;
    let v_top_rowids: Vec<i64> = v_results.iter().map(|(r, _)| *r).collect();
    let v_recall_both = count_intersection(&v_top_rowids, &plan.both_rowids);
    report.assert(
        "vector-query",
        v_results.len() == TOP_K_PER_SOURCE && v_recall_both == N_BOTH,
        &format!(
            "returned {}/{} hits; recovered {}/{} 'both' records in top-{}",
            v_results.len(),
            TOP_K_PER_SOURCE,
            v_recall_both,
            N_BOTH,
            TOP_K_PER_SOURCE
        ),
    );

    // -- FTS query ------------------------------------------------------------
    // `concurrency` is in tags for cohorts A (concurrency-only) and C (both) — total 20.
    let f_results = fts_query(&conn, FTS_TERM, TOP_K_PER_SOURCE)?;
    let f_top_rowids: Vec<i64> = f_results.iter().map(|(r, _)| *r).collect();
    let expected_fts = N_CONCURRENCY_ONLY + N_BOTH;
    report.assert(
        "fts-query",
        f_results.len() == TOP_K_PER_SOURCE && f_top_rowids.len() == expected_fts,
        &format!(
            "FTS('{}') returned {} hits, expected exactly {} (cohort A {} + both {})",
            FTS_TERM,
            f_top_rowids.len(),
            expected_fts,
            N_CONCURRENCY_ONLY,
            N_BOTH
        ),
    );

    // -- Hybrid (RRF) query ---------------------------------------------------
    let h_results = hybrid_rrf(&v_results, &f_results, RRF_K, TOP_K_PER_SOURCE);
    let h_top_rowids: Vec<i64> = h_results.iter().map(|(r, _)| *r).collect();
    let h_recall_both = count_intersection(&h_top_rowids, &plan.both_rowids);
    report.assert(
        "hybrid-rrf",
        !h_results.is_empty() && h_recall_both == N_BOTH,
        &format!(
            "RRF(k={}) fused {} hits; 'both' cohort fully recovered in fused top-{}: {}",
            RRF_K as i32,
            h_results.len(),
            TOP_K_PER_SOURCE,
            h_recall_both == N_BOTH
        ),
    );

    // -- Tag-heavy query — the spec's primary FTS-over-JSON gate ---------------
    // Try BOTH FTS5 column-restricted forms. The spec writes `tags MATCH "concurrency database"`
    // illustratively (§3.6 S1); the spike's job is to confirm the actual working form.
    let form_a = tag_heavy_via_column(&conn, TAG_HEAVY_QUERY);
    let form_b = tag_heavy_via_table(&conn, TAG_HEAVY_QUERY);

    let summarize = |r: &Result<Vec<i64>>| -> String {
        match r {
            Ok(v) => {
                let recall = count_intersection(v, &plan.both_rowids);
                format!("{} hits (recall {}/{})", v.len(), recall, N_BOTH)
            }
            Err(e) => format!("ERR ({e})"),
        }
    };
    let form_a_passes = matches!(&form_a, Ok(v)
        if v.len() == N_BOTH && count_intersection(v, &plan.both_rowids) == N_BOTH);
    let form_b_passes = matches!(&form_b, Ok(v)
        if v.len() == N_BOTH && count_intersection(v, &plan.both_rowids) == N_BOTH);

    report.assert(
        "tag-heavy-query",
        form_a_passes || form_b_passes,
        &format!(
            "Form A (col-MATCH per spec example): {} | Form B (table-MATCH + tags: prefix): {} | expected exactly {N_BOTH} hits, all from 'both' cohort",
            summarize(&form_a),
            summarize(&form_b),
        ),
    );

    if !form_a_passes && form_b_passes {
        report.note(
            "spec-update-required",
            "§7 / §3.6 S1 example uses `WHERE tags MATCH ?` (column-MATCH form), which fails \
             at runtime with a multi-token bound expression on rusqlite 0.32 + bundled SQLite \
             3.44 + sqlite-vec 0.1.9 (error: \"no such column: <second token>\"). The working \
             form is table-MATCH with a per-token column prefix: \
             `WHERE records_fts MATCH 'tags:concurrency tags:database'`. Update §7 example \
             before M1 — this is the kind of finding the spike is for.",
        );
    }

    // -- FTS-over-JSON quirk: hyphenated tag values --------------------------
    // Informational. Surfaces an FTS5 expression-parser quirk that affects tag values
    // containing punctuation (hyphens, dots, quotes). Not a §3.6 S1 pass/fail gate.
    let hyphen_outcome = match tag_heavy_via_column(&conn, "perf-database") {
        Ok(v) => format!("{} hits", v.len()),
        Err(e) => format!("ERR ({e})"),
    };
    report.note(
        "fts-tokenization-hyphen",
        &format!(
            "tags MATCH 'perf-database' (column-MATCH form): {hyphen_outcome}. FTS5's expression \
             parser treats '-' as a NOT operator, so hyphenated tag values collide with the \
             grammar. Implication for §7: tag values containing hyphens / dots / quotes need \
             pre-storage normalization (e.g., snake_case), explicit phrase quoting in FTS \
             expressions (`\"perf-database\"`), or a custom tokenizer. Document the chosen \
             policy in the indexing pipeline."
        ),
    );

    report.print();
    if report.all_pass() {
        std::process::exit(0);
    }
    std::process::exit(1);
}

// ============================================================================
// sqlite-vec extension registration
// ============================================================================

fn register_sqlite_vec() {
    // SAFETY: `sqlite3_auto_extension` registers an init function that SQLite invokes
    // when each new connection is opened. `sqlite_vec::sqlite3_vec_init` is the standard
    // sqlite-vec entry point and is ABI-compatible with the SQLite-extension init signature
    // — but its rustc-visible type uses sqlite-vec's bindgen-generated `sqlite3` opaque
    // alias rather than rusqlite's, so the transmute is needed to convince the type system
    // that the two ABI-equivalent function-pointer types are the same. This is the pattern
    // documented by sqlite-vec for static linking with rusqlite.
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
// DDL — verbatim from design §7
// ============================================================================

fn open_and_apply_ddl(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path).context("open temp sqlite db")?;

    conn.pragma_update(None, "journal_mode", "WAL")
        .context("set journal_mode = WAL")?;
    conn.pragma_update(None, "busy_timeout", 5000_i64)
        .context("set busy_timeout = 5000")?;
    conn.pragma_update(None, "foreign_keys", true)
        .context("set foreign_keys = ON")?;

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
        CREATE INDEX idx_records_project ON records(project_id);
        CREATE INDEX idx_records_type ON records(record_type);
        CREATE INDEX idx_records_source ON records(source);
        CREATE INDEX idx_records_updated ON records(updated);
        CREATE INDEX idx_records_hash ON records(content_hash);
        CREATE INDEX idx_records_signature ON records(signature_status);

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
// corpus seeding
// ============================================================================

#[derive(Debug)]
struct CorpusPlan {
    /// rowids of cohort C (both `concurrency` AND `database` tags)
    both_rowids: Vec<i64>,
    /// embeddings of cohort C, used to synthesize the vector query
    both_seeds: Vec<Vec<f32>>,
}

fn seed_corpus(conn: &Connection) -> Result<CorpusPlan> {
    let mut plan = CorpusPlan {
        both_rowids: Vec::with_capacity(N_BOTH),
        both_seeds: Vec::with_capacity(N_BOTH),
    };

    let tx = conn.unchecked_transaction()?;
    {
        let mut insert_record = tx.prepare(
            r"INSERT INTO records (
                id, source, record_type, title, summary, body, tags,
                created, updated, content_hash, signature_status, indexed_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        )?;
        let mut insert_embedding =
            tx.prepare("INSERT INTO record_embeddings(record_rowid, embedding) VALUES (?1, ?2)")?;

        for i in 0..N_RECORDS {
            let cohort = cohort_for_index(i);
            let id = format!("2026-04-30-rec-{i:03}");
            let title = title_for(cohort, i);
            let summary = format!("Spike S1 fake summary for record {i:03}.");
            let body = body_for(cohort, i);
            let tags = tags_for(cohort);
            let now = "2026-04-30T00:00:00Z";

            insert_record.execute(params![
                id,
                "local",
                record_type_for(cohort),
                title,
                summary,
                body,
                tags,
                now,
                now,
                format!("hash-{i:03}"),
                "unsigned",
                now,
            ])?;
            let rowid = tx.last_insert_rowid();

            let embedding = embedding_for(cohort, i);
            let bytes = vec_to_le_bytes(&embedding);
            insert_embedding.execute(params![rowid, bytes])?;

            if cohort == Cohort::Both {
                plan.both_rowids.push(rowid);
                plan.both_seeds.push(embedding);
            }
        }
    }
    tx.commit()?;

    if plan.both_rowids.len() != N_BOTH {
        bail!(
            "corpus seed mismatch: expected {} 'both' records, got {}",
            N_BOTH,
            plan.both_rowids.len()
        );
    }
    Ok(plan)
}

// Each record falls into exactly one cohort based on its index. Counts must sum to N_RECORDS.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum Cohort {
    ConcurrencyOnly,
    DatabaseOnly,
    Both,
    Neither,
}

fn cohort_for_index(idx: usize) -> Cohort {
    let upto_concurrency = N_CONCURRENCY_ONLY;
    let upto_database = upto_concurrency + N_DATABASE_ONLY;
    let upto_both = upto_database + N_BOTH;
    if idx < upto_concurrency {
        Cohort::ConcurrencyOnly
    } else if idx < upto_database {
        Cohort::DatabaseOnly
    } else if idx < upto_both {
        Cohort::Both
    } else {
        Cohort::Neither
    }
}

fn record_type_for(c: Cohort) -> &'static str {
    match c {
        Cohort::DatabaseOnly => "recommendation",
        Cohort::ConcurrencyOnly | Cohort::Both => "decision",
        Cohort::Neither => "failure",
    }
}

fn title_for(c: Cohort, i: usize) -> String {
    let topic = match c {
        Cohort::ConcurrencyOnly => "scheduler design",
        Cohort::DatabaseOnly => "schema rollout",
        Cohort::Both => "indexing pipeline",
        Cohort::Neither => "miscellaneous",
    };
    format!("{topic} note #{i:03}")
}

fn body_for(c: Cohort, i: usize) -> String {
    // Body text deliberately does NOT contain "concurrency" or "database" — we want the
    // FTS query to hit only via the tags column for cohorts A/B/C, validating that
    // FTS-over-JSON tags works.
    let theme = match c {
        Cohort::ConcurrencyOnly => "Notes on the scheduler experiment.",
        Cohort::DatabaseOnly => "Notes on the schema migration.",
        Cohort::Both => "Notes on the indexing pipeline experiment.",
        Cohort::Neither => "Filler note kept out of the searchable terms above.",
    };
    format!("{theme} Body filler line {i}.")
}

fn tags_for(c: Cohort) -> String {
    // JSON arrays. Stored as TEXT in records.tags; FTS5 indexes the literal string; the
    // unicode61 tokenizer strips brackets, quotes and commas, leaving the bare tag tokens.
    match c {
        Cohort::ConcurrencyOnly => r#"["concurrency","scheduler"]"#.to_owned(),
        Cohort::DatabaseOnly => r#"["database","schema"]"#.to_owned(),
        Cohort::Both => r#"["concurrency","database","performance"]"#.to_owned(),
        Cohort::Neither => r#"["misc","notes"]"#.to_owned(),
    }
}

// ============================================================================
// embeddings — deterministic xorshift64 PRNG, L2-normalized
// ============================================================================

fn embedding_for(cohort: Cohort, i: usize) -> Vec<f32> {
    // Per-cohort offset gives the cohorts visibly different centroids in the unit hypersphere
    // so the synthesized "both" centroid query reliably ranks cohort C records first.
    let cohort_seed: u64 = match cohort {
        Cohort::ConcurrencyOnly => 0xCCCC_0001_FFFF_0001,
        Cohort::DatabaseOnly => 0xDDDD_0002_FFFF_0002,
        Cohort::Both => 0xBBBB_0003_FFFF_0003,
        Cohort::Neither => 0xEEEE_0004_FFFF_0004,
    };
    let seed = cohort_seed ^ ((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    random_unit_vector(seed)
}

fn random_unit_vector(seed: u64) -> Vec<f32> {
    let mut state = if seed == 0 { 1 } else { seed };
    let mut v = Vec::with_capacity(EMBEDDING_DIM);
    for _ in 0..EMBEDDING_DIM {
        let r = xorshift64(&mut state);
        // Map u64 → f32 in [-1.0, 1.0] using high 32 bits as i32.
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

fn average_embedding(seeds: &[Vec<f32>]) -> Vec<f32> {
    assert!(!seeds.is_empty(), "need at least one seed vector");
    let mut acc = vec![0.0_f32; EMBEDDING_DIM];
    for v in seeds {
        for (a, x) in acc.iter_mut().zip(v.iter()) {
            *a += *x;
        }
    }
    let scale = 1.0 / seeds.len() as f32;
    for a in &mut acc {
        *a *= scale;
    }
    let norm: f32 = acc.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for a in &mut acc {
            *a /= norm;
        }
    }
    acc
}

fn vec_to_le_bytes(v: &[f32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(v.len() * 4);
    for f in v {
        bytes.extend_from_slice(&f.to_le_bytes());
    }
    bytes
}

// ============================================================================
// queries
// ============================================================================

fn vector_query(conn: &Connection, q_emb: &[f32], k: usize) -> Result<Vec<(i64, f64)>> {
    let q_bytes = vec_to_le_bytes(q_emb);
    let mut stmt = conn.prepare(
        "SELECT record_rowid, distance FROM record_embeddings
         WHERE embedding MATCH ?1 AND k = ?2
         ORDER BY distance",
    )?;
    let rows = stmt
        .query_map(params![q_bytes, k as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, f64>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn fts_query(conn: &Connection, term: &str, k: usize) -> Result<Vec<(i64, f64)>> {
    let mut stmt = conn.prepare(
        "SELECT rowid, bm25(records_fts) AS score
         FROM records_fts
         WHERE records_fts MATCH ?1
         ORDER BY score
         LIMIT ?2",
    )?;
    let rows = stmt
        .query_map(params![term, k as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, f64>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Form A — the spec's literal example syntax. `WHERE <fts5_column> MATCH ?` with a multi-token
/// bound expression. Documented in SQLite's FTS5 reference but observed to fail in practice
/// on rusqlite 0.32 + bundled SQLite 3.44 + sqlite-vec 0.1.9 — see §7 finding from this spike.
fn tag_heavy_via_column(conn: &Connection, query: &str) -> Result<Vec<i64>> {
    let mut stmt =
        conn.prepare("SELECT rowid FROM records_fts WHERE tags MATCH ?1 ORDER BY rowid")?;
    let rows = stmt
        .query_map(params![query], |row| row.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Form B — table-level MATCH with a `column:term` prefix per token. Reliably parses on
/// the same stack and is the recommended form for column-restricted FTS5 queries.
fn tag_heavy_via_table(conn: &Connection, query: &str) -> Result<Vec<i64>> {
    let qualified = query
        .split_whitespace()
        .map(|t| format!("tags:{t}"))
        .collect::<Vec<_>>()
        .join(" ");
    let mut stmt =
        conn.prepare("SELECT rowid FROM records_fts WHERE records_fts MATCH ?1 ORDER BY rowid")?;
    let rows = stmt
        .query_map(params![qualified], |row| row.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn hybrid_rrf(
    vector_results: &[(i64, f64)],
    fts_results: &[(i64, f64)],
    k: f32,
    top_n: usize,
) -> Vec<(i64, f32)> {
    let mut score: HashMap<i64, f32> = HashMap::new();
    for (rank, (rowid, _)) in vector_results.iter().enumerate() {
        let r = rank as f32 + 1.0;
        *score.entry(*rowid).or_insert(0.0) += 1.0 / (k + r);
    }
    for (rank, (rowid, _)) in fts_results.iter().enumerate() {
        let r = rank as f32 + 1.0;
        *score.entry(*rowid).or_insert(0.0) += 1.0 / (k + r);
    }
    let mut fused: Vec<(i64, f32)> = score.into_iter().collect();
    fused.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    fused.truncate(top_n);
    fused
}

// ============================================================================
// helpers
// ============================================================================

fn count_intersection(haystack: &[i64], needles: &[i64]) -> usize {
    let h: std::collections::HashSet<_> = haystack.iter().copied().collect();
    needles.iter().filter(|n| h.contains(n)).count()
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .try_init();
}

// Sanity-check at compile time that the cohort counts add to the corpus size and that
// dependent queries' expectations stay in sync if anyone tweaks the constants.
const _: () = {
    assert!(N_CONCURRENCY_ONLY + N_DATABASE_ONLY + N_BOTH + N_NEITHER == N_RECORDS);
    assert!(
        N_CONCURRENCY_ONLY + N_BOTH <= TOP_K_PER_SOURCE,
        "FTS top-k must hold all records matching the FTS_TERM"
    );
};

// ============================================================================
// reporting
// ============================================================================

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
        println!("\n=== nexum spike S1 — sqlite-vec DDL + tag-heavy query ===\n");
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
            "  Platform: linux x86_64 only this run. Re-run on Windows native to close the §3.6 S1 cross-platform criterion."
        );
    }
}
