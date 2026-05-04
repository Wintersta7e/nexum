//! Codex adapter — reads `<memories_dir>/*` and `<state_db_path>` (`state_5.sqlite`).
//!
//! - `MEMORY.md` is split by `## Task <n>` into one record per section.
//! - `rollout_summaries/*.md` becomes one record per file.
//! - `raw_memories.md` is opt-in via `[adapters.codex] read_raw_memories = true`.
//! - `state_5.sqlite.threads` provides the rollout-path → thread-row index used
//!   to populate `SessionRef::CodexThread` and `project_id` for each section.
//! - `SQLite` reads use URI mode `?mode=ro` inside one `BEGIN DEFERRED`
//!   transaction per pass; markdown reads use stable double-read with up to
//!   five 50 ms-backoff retries.

use chrono::{DateTime, TimeZone, Utc};
use rusqlite::OpenFlags;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use crate::{
    adapter::trait_def::{
        Adapter, AdapterError, AdapterPass, PassCompleteness, SkipKind, SkipReason,
    },
    project::{ProjectInput, ProjectResolution, resolve::resolve as resolve_project},
    records::{
        Agent, Confidence, Outcome, ProjectId, Provenance, RecordId, RecordSummary, RecordType,
        SessionRef, SignatureStatus, Source, UnifiedRecord, content_hash,
    },
};

/// Codex adapter — reads `<memories_dir>` + `<state_db_path>`.
pub struct CodexAdapter {
    memories_dir: PathBuf,
    state_db_path: PathBuf,
    read_raw_memories: bool,
}

impl CodexAdapter {
    /// Construct from configured paths. The adapter does not materialize on
    /// construction — work happens in `list()` / `read()`.
    #[must_use]
    pub fn new(memories_dir: PathBuf, state_db_path: PathBuf, read_raw_memories: bool) -> Self {
        Self {
            memories_dir,
            state_db_path,
            read_raw_memories,
        }
    }

    fn read_thread_index(&self) -> ThreadIndexResult {
        if !self.state_db_path.exists() {
            return ThreadIndexResult::Missing;
        }
        let uri = format!("file:{}?mode=ro&immutable=0", self.state_db_path.display());
        let Ok(conn) = rusqlite::Connection::open_with_flags(
            &uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        ) else {
            return ThreadIndexResult::Locked;
        };
        if conn.execute_batch("BEGIN DEFERRED;").is_err() {
            return ThreadIndexResult::Locked;
        }

        let mut by_rollout: HashMap<String, ThreadRow> = HashMap::new();
        let Ok(mut stmt) = conn.prepare(
            "SELECT id, rollout_path, cwd, git_origin_url, created_at, updated_at, title \
             FROM threads",
        ) else {
            return ThreadIndexResult::Locked;
        };
        let Ok(rows) = stmt.query_map([], |row| {
            Ok(ThreadRow {
                id: row.get::<_, String>(0)?,
                rollout_path: row.get::<_, String>(1)?,
                cwd: row.get::<_, String>(2)?,
                git_origin_url: row.get::<_, Option<String>>(3)?,
                created_at: row.get::<_, i64>(4)?,
                updated_at: row.get::<_, i64>(5)?,
                title: row.get::<_, String>(6)?,
            })
        }) else {
            return ThreadIndexResult::Locked;
        };
        for r in rows {
            match r {
                Ok(r) => {
                    by_rollout.insert(r.rollout_path.clone(), r);
                }
                Err(_) => return ThreadIndexResult::Malformed,
            }
        }
        let _ = conn.execute_batch("COMMIT;");
        ThreadIndexResult::Ok(by_rollout)
    }

    fn collect_memory_md(&self, records: &mut Vec<RecordSummary>, skipped: &mut Vec<SkipReason>) {
        let memory_md = self.memories_dir.join("MEMORY.md");
        if !memory_md.exists() {
            return;
        }
        match read_stable(&memory_md) {
            Ok(raw) => {
                let parsed = parse_memory_md(&raw);
                push_record_summaries(&parsed.records, "", records);
                if parsed.malformed_count > 0 {
                    skipped.push(SkipReason {
                        path: memory_md,
                        kind: SkipKind::FileMalformed,
                        at: Utc::now(),
                    });
                }
            }
            Err(()) => skipped.push(SkipReason {
                path: memory_md,
                kind: SkipKind::FileTransient,
                at: Utc::now(),
            }),
        }
    }

    fn collect_rollout_summaries(
        &self,
        records: &mut Vec<RecordSummary>,
        skipped: &mut Vec<SkipReason>,
    ) {
        let summaries_dir = self.memories_dir.join("rollout_summaries");
        if !summaries_dir.is_dir() {
            return;
        }
        let Ok(rd) = fs::read_dir(&summaries_dir) else {
            return;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if !is_md_file(&p) {
                continue;
            }
            match read_stable(&p) {
                Ok(raw) => {
                    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("anon");
                    let id = format!("rollout_summary_{stem}");
                    let title = stem.replace('_', " ");
                    let hash = content_hash(&title, None, &raw);
                    records.push(RecordSummary {
                        id,
                        content_hash: hash,
                    });
                }
                Err(()) => skipped.push(SkipReason {
                    path: p,
                    kind: SkipKind::FileTransient,
                    at: Utc::now(),
                }),
            }
        }
    }

    fn collect_raw_memories(
        &self,
        records: &mut Vec<RecordSummary>,
        skipped: &mut Vec<SkipReason>,
    ) {
        if !self.read_raw_memories {
            return;
        }
        let raw_path = self.memories_dir.join("raw_memories.md");
        if !raw_path.exists() {
            return;
        }
        match read_stable(&raw_path) {
            Ok(raw) => {
                let parsed = parse_memory_md(&raw);
                push_record_summaries(&parsed.records, "raw_", records);
                if parsed.malformed_count > 0 {
                    skipped.push(SkipReason {
                        path: raw_path,
                        kind: SkipKind::FileMalformed,
                        at: Utc::now(),
                    });
                }
            }
            Err(()) => skipped.push(SkipReason {
                path: raw_path,
                kind: SkipKind::FileTransient,
                at: Utc::now(),
            }),
        }
    }
}

#[derive(Debug, Clone)]
struct ThreadRow {
    id: String,
    rollout_path: String,
    cwd: String,
    git_origin_url: Option<String>,
    created_at: i64,
    updated_at: i64,
    title: String,
}

enum ThreadIndexResult {
    Ok(HashMap<String, ThreadRow>),
    Locked,
    Missing,
    Malformed,
}

impl Adapter for CodexAdapter {
    fn source(&self) -> Source {
        Source::CodexNative
    }

    fn list(&self) -> Result<AdapterPass, AdapterError> {
        // Detect a missing or unreadable memories_dir BEFORE collecting any
        // sub-files. The primary configured root is `memories_dir`; the
        // `state_db_path` join is best-effort and remains modeled via
        // existing Partial-pass entries when only the DB is missing.
        //
        // Note: there is a narrow TOCTOU window between this probe and the walk
        // below. If the root disappears in that window the walk surfaces an IO
        // error that propagates as AdapterError::Io, not MissingRoot. Acceptable;
        // the next pass catches it.
        match fs::metadata(&self.memories_dir) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(AdapterPass {
                    source: Source::CodexNative,
                    records: Vec::new(),
                    completeness: PassCompleteness::MissingRoot {
                        path: self.memories_dir.clone(),
                    },
                });
            }
            Err(e) => {
                return Ok(AdapterPass {
                    source: Source::CodexNative,
                    records: Vec::new(),
                    completeness: PassCompleteness::Unreadable {
                        path: self.memories_dir.clone(),
                        reason: e.to_string(),
                    },
                });
            }
        }

        let mut records: Vec<RecordSummary> = Vec::new();
        let mut skipped: Vec<SkipReason> = Vec::new();

        self.collect_memory_md(&mut records, &mut skipped);
        self.collect_rollout_summaries(&mut records, &mut skipped);
        self.collect_raw_memories(&mut records, &mut skipped);

        // Track state_db status. Don't fail the whole pass; surface as a
        // Partial-pass entry so the indexer suppresses delete computation
        // for this source.
        match self.read_thread_index() {
            ThreadIndexResult::Locked => {
                skipped.push(SkipReason {
                    path: self.state_db_path.clone(),
                    kind: SkipKind::LockContention,
                    at: Utc::now(),
                });
            }
            ThreadIndexResult::Malformed => {
                skipped.push(SkipReason {
                    path: self.state_db_path.clone(),
                    kind: SkipKind::FileMalformed,
                    at: Utc::now(),
                });
            }
            ThreadIndexResult::Missing if !records.is_empty() => {
                // Records present but state_db absent — the project_id /
                // SessionRef::CodexThread join can't run; surface as a
                // transient skip so the next pass retries.
                skipped.push(SkipReason {
                    path: self.state_db_path.clone(),
                    kind: SkipKind::FileTransient,
                    at: Utc::now(),
                });
            }
            ThreadIndexResult::Ok(_) | ThreadIndexResult::Missing => {
                // Ok: state_db read clean, no skip.
                // Missing + no records: the empty-memories common case; not a
                // skip — Authoritative-zero is the right answer.
            }
        }

        let completeness = if skipped.is_empty() {
            PassCompleteness::Authoritative
        } else {
            PassCompleteness::Partial { skipped }
        };
        Ok(AdapterPass {
            source: Source::CodexNative,
            records,
            completeness,
        })
    }

    fn read(&self, id: &RecordId) -> Result<UnifiedRecord, AdapterError> {
        let thread_index = match self.read_thread_index() {
            ThreadIndexResult::Ok(idx) => idx,
            ThreadIndexResult::Locked
            | ThreadIndexResult::Missing
            | ThreadIndexResult::Malformed => HashMap::new(),
        };

        // Try MEMORY.md sections first.
        let memory_md = self.memories_dir.join("MEMORY.md");
        if memory_md.exists() {
            let raw = fs::read_to_string(&memory_md).map_err(|e| AdapterError::Io {
                path: memory_md.clone(),
                source: e,
            })?;
            let parsed = parse_memory_md(&raw);
            for sec in parsed.records {
                if sec.id == *id {
                    return Ok(build_record(sec, &thread_index, &memory_md, false));
                }
            }
        }

        // Then rollout_summaries.
        let summaries_dir = self.memories_dir.join("rollout_summaries");
        if let Some(rest) = id.strip_prefix("rollout_summary_") {
            let candidate = summaries_dir.join(format!("{rest}.md"));
            if candidate.exists() {
                let raw = fs::read_to_string(&candidate).map_err(|e| AdapterError::Io {
                    path: candidate.clone(),
                    source: e,
                })?;
                let title = rest.replace('_', " ");
                let body = raw;
                let hash = content_hash(&title, None, &body);
                let sec = ParsedSection {
                    id: id.clone(),
                    title,
                    body,
                    keywords: Vec::new(),
                    rollout_summary_files: Vec::new(),
                };
                let mut record = build_record(sec, &thread_index, &candidate, false);
                record.content_hash = hash;
                return Ok(record);
            }
        }

        // Then raw_memories sections.
        if let Some(rest) = id.strip_prefix("raw_") {
            let raw_path = self.memories_dir.join("raw_memories.md");
            if raw_path.exists() {
                let raw = fs::read_to_string(&raw_path).map_err(|e| AdapterError::Io {
                    path: raw_path.clone(),
                    source: e,
                })?;
                let parsed = parse_memory_md(&raw);
                for sec in parsed.records {
                    if sec.id == rest {
                        let mut sec_with_prefix = sec;
                        sec_with_prefix.id.clone_from(id);
                        return Ok(build_record(
                            sec_with_prefix,
                            &thread_index,
                            &raw_path,
                            true,
                        ));
                    }
                }
            }
        }

        Err(AdapterError::Io {
            path: PathBuf::from(id),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, format!("codex record {id}")),
        })
    }
}

#[derive(Debug, Clone)]
struct ParsedSection {
    id: RecordId,
    title: String,
    body: String,
    keywords: Vec<String>,
    rollout_summary_files: Vec<String>,
}

struct ParseSections {
    records: Vec<ParsedSection>,
    malformed_count: usize,
}

fn parse_memory_md(raw: &str) -> ParseSections {
    let mut records: Vec<ParsedSection> = Vec::new();
    let mut malformed_count: usize = 0;

    let mut current: Option<ParsedSection> = None;
    let mut active_subsection: Option<Subsection> = None;
    let mut task_index: usize = 0;

    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("## Task ") {
            finalize_section(current.take(), &mut malformed_count, &mut records);
            task_index += 1;
            let id_label = rest.trim();
            let id = format!("task_{id_label}_idx{task_index}").replace(' ', "_");
            let title = format!("Task {id_label}");
            current = Some(ParsedSection {
                id,
                title,
                body: String::new(),
                keywords: Vec::new(),
                rollout_summary_files: Vec::new(),
            });
            active_subsection = None;
        } else if line.starts_with("### keywords") {
            active_subsection = Some(Subsection::Keywords);
        } else if line.starts_with("### rollout_summary_files") {
            active_subsection = Some(Subsection::RolloutSummaryFiles);
        } else if let Some(stripped) = line.strip_prefix("### ") {
            // Unrecognized subsection — treat as body content; reset
            // active_subsection so the lines following fall back to body.
            active_subsection = None;
            if let Some(sec) = current.as_mut() {
                sec.body.push_str("### ");
                sec.body.push_str(stripped);
                sec.body.push('\n');
            }
        } else if let Some(sec) = current.as_mut() {
            match active_subsection {
                Some(Subsection::Keywords) => {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        for k in trimmed
                            .split([',', ';'])
                            .map(str::trim)
                            .filter(|t| !t.is_empty())
                        {
                            sec.keywords.push(k.to_owned());
                        }
                    }
                }
                Some(Subsection::RolloutSummaryFiles) => {
                    let trimmed = line.trim_start_matches(['-', ' ']).trim();
                    if !trimmed.is_empty() {
                        sec.rollout_summary_files.push(trimmed.to_owned());
                    }
                }
                None => {
                    sec.body.push_str(line);
                    sec.body.push('\n');
                }
            }
        }
    }
    finalize_section(current, &mut malformed_count, &mut records);
    ParseSections {
        records,
        malformed_count,
    }
}

#[derive(Debug, Clone, Copy)]
enum Subsection {
    Keywords,
    RolloutSummaryFiles,
}

fn finalize_section(
    current: Option<ParsedSection>,
    malformed_count: &mut usize,
    records: &mut Vec<ParsedSection>,
) {
    let Some(mut sec) = current else {
        return;
    };
    let trimmed_start = sec.body.len() - sec.body.trim_start().len();
    let trimmed_len = sec.body.trim().len();
    sec.body.drain(..trimmed_start);
    sec.body.truncate(trimmed_len);
    let has_body_or_tags = !sec.body.is_empty() || !sec.keywords.is_empty();
    let has_title = !sec.title.is_empty();
    if has_title && has_body_or_tags {
        records.push(sec);
    } else {
        *malformed_count += 1;
    }
}

fn push_record_summaries(
    parsed: &[ParsedSection],
    id_prefix: &str,
    records: &mut Vec<RecordSummary>,
) {
    for s in parsed {
        let hash = content_hash(&s.title, None, &s.body);
        let id = if id_prefix.is_empty() {
            s.id.clone()
        } else {
            format!("{id_prefix}{}", s.id)
        };
        records.push(RecordSummary {
            id,
            content_hash: hash,
        });
    }
}

fn build_record(
    sec: ParsedSection,
    thread_index: &HashMap<String, ThreadRow>,
    origin_path: &Path,
    is_raw: bool,
) -> UnifiedRecord {
    let mut session_refs: Vec<SessionRef> = Vec::new();
    let mut chosen_thread: Option<&ThreadRow> = None;
    for rollout in &sec.rollout_summary_files {
        let pb = PathBuf::from(rollout);
        session_refs.push(SessionRef::CodexRollout { path: pb });
        if let Some(row) = thread_index.get(rollout) {
            chosen_thread = Some(row);
        }
    }
    if let Some(row) = chosen_thread {
        session_refs.push(SessionRef::CodexThread {
            thread_id: row.id.clone(),
            rollout_path: Some(PathBuf::from(&row.rollout_path)),
        });
    }
    let project_id: ProjectId = chosen_thread.map_or_else(
        || "codex-no-state".to_owned(),
        resolve_project_id_from_thread,
    );

    let updated: DateTime<Utc> = chosen_thread
        .and_then(|t| Utc.timestamp_opt(t.updated_at, 0).single())
        .unwrap_or_else(Utc::now);
    let created: DateTime<Utc> = chosen_thread
        .and_then(|t| Utc.timestamp_opt(t.created_at, 0).single())
        .unwrap_or(updated);

    let summary: Option<String> = chosen_thread
        .map(|t| t.title.clone())
        .filter(|t| !t.is_empty());
    let hash = content_hash(&sec.title, summary.as_deref(), &sec.body);

    let mut extras: HashMap<String, serde_json::Value> = HashMap::new();
    if is_raw {
        extras.insert(
            "codex_section_kind".into(),
            serde_json::Value::String("raw".into()),
        );
    }
    if let Some(t) = chosen_thread
        && let Some(g) = &t.git_origin_url
    {
        extras.insert(
            "git_origin_url".into(),
            serde_json::Value::String(g.clone()),
        );
    }

    UnifiedRecord {
        id: sec.id,
        record_type: RecordType::Untyped,
        source: Source::CodexNative,
        project_id,
        title: sec.title,
        summary,
        body: sec.body,
        body_origin_path: Some(origin_path.to_owned()),
        tags: sec.keywords,
        agent: Agent::Codex,
        session_refs,
        files: Vec::new(),
        commits: Vec::new(),
        created,
        updated,
        confidence: Confidence::Medium,
        outcome: Outcome::NotApplicable,
        provenance: Provenance {
            source: Source::CodexNative,
            signature_status: SignatureStatus::Unsigned,
            trust_basis: None,
            extractor: None,
            digest_hash: None,
            record_commit_sha: None,
            signer_fingerprint: None,
            warning_code: None,
        },
        extras,
        content_hash: hash,
    }
}

fn resolve_project_id_from_thread(t: &ThreadRow) -> ProjectId {
    let input = ProjectInput {
        cc_slug: None,
        codex_cwd: Some(PathBuf::from(&t.cwd)),
        git_origin_url: t.git_origin_url.clone(),
        registered_name: None,
    };
    match resolve_project(&input) {
        ProjectResolution::Resolved { project_id, .. } => project_id,
        ProjectResolution::Ambiguous { candidates, .. } => candidates
            .first()
            .map_or_else(|| format!("codex-cwd:{}", t.cwd), |c| c.project_id.clone()),
        ProjectResolution::Unresolved => format!("codex-cwd:{}", t.cwd),
    }
}

fn is_md_file(p: &Path) -> bool {
    p.extension().is_some_and(|e| e.eq_ignore_ascii_case("md"))
}

/// Read a file with a stable double-read strategy: read size+mtime, read
/// content, re-read size+mtime; if they match the content is accepted.
/// Otherwise retry up to 5 times with 50 ms backoff. On persistent failure
/// return `Err(())` so the caller surfaces it as `SkipKind::FileTransient`.
fn read_stable(path: &Path) -> Result<String, ()> {
    for attempt in 0_u64..5 {
        let pre = match path.metadata() {
            Ok(m) => (m.len(), m.modified().ok()),
            Err(_) => return Err(()),
        };
        let Ok(content) = fs::read_to_string(path) else {
            return Err(());
        };
        let post = match path.metadata() {
            Ok(m) => (m.len(), m.modified().ok()),
            Err(_) => return Err(()),
        };
        if pre == post {
            return Ok(content);
        }
        thread::sleep(Duration::from_millis(50 + attempt * 25));
    }
    Err(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn fixture_state_db() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("codex")
            .join("state_5.sqlite")
    }

    fn write_file(p: &Path, content: &str) {
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = fs::File::create(p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    #[test]
    fn empty_memories_dir_no_state_db_returns_authoritative_zero() {
        let dir = TempDir::new().unwrap();
        let memories = dir.path().join("memories");
        fs::create_dir_all(&memories).unwrap();
        let adapter = CodexAdapter::new(memories, dir.path().join("nonexistent.sqlite"), false);
        let pass = adapter.list().expect("list ok");
        assert_eq!(pass.records.len(), 0);
        assert_eq!(pass.completeness, PassCompleteness::Authoritative);
    }

    #[test]
    fn memory_md_with_two_task_sections_yields_two_records() {
        let dir = TempDir::new().unwrap();
        let memories = dir.path().join("memories");
        write_file(
            &memories.join("MEMORY.md"),
            "# memories\n\n\
             ## Task 1\n\
             First task title.\n\
             ### keywords\n\
             auth, security\n\
             ### rollout_summary_files\n\
             - sessions/2026/04/01/rollout-aaa.jsonl\n\
             First task body.\n\n\
             ## Task 2\n\
             Second task title.\n\
             ### keywords\n\
             concurrency\n\
             Second task body.\n",
        );
        let adapter = CodexAdapter::new(memories, dir.path().join("nonexistent.sqlite"), false);
        let pass = adapter.list().expect("list ok");
        assert_eq!(pass.records.len(), 2);
    }

    #[test]
    fn rollout_summary_file_yields_one_record() {
        let dir = TempDir::new().unwrap();
        let memories = dir.path().join("memories");
        write_file(
            &memories.join("rollout_summaries").join("alpha.md"),
            "# alpha\n\nSome content.\n",
        );
        let adapter = CodexAdapter::new(memories, dir.path().join("nonexistent.sqlite"), false);
        let pass = adapter.list().expect("list ok");
        assert_eq!(pass.records.len(), 1);
        assert!(pass.records[0].id.starts_with("rollout_summary_"));
    }

    #[test]
    fn raw_memories_skipped_unless_opted_in() {
        let dir = TempDir::new().unwrap();
        let memories = dir.path().join("memories");
        write_file(
            &memories.join("raw_memories.md"),
            "## Task 1\nraw content\n",
        );

        let opted_out = CodexAdapter::new(memories.clone(), dir.path().join("x.sqlite"), false);
        let pass = opted_out.list().unwrap();
        assert_eq!(
            pass.records.len(),
            0,
            "raw_memories must be skipped by default"
        );

        let opted_in = CodexAdapter::new(memories, dir.path().join("x.sqlite"), true);
        let pass = opted_in.list().unwrap();
        assert_eq!(
            pass.records.len(),
            1,
            "raw_memories must be read when opted in"
        );
    }

    #[test]
    fn fixture_state_sqlite_thread_join_works() {
        // The fixture has three threads (thread-aaa/bbb/ccc), each with a
        // distinct rollout_path. Build a memories/MEMORY.md that references
        // one of them and confirm the SessionRef::CodexThread is populated
        // from the SQLite join.
        let dir = TempDir::new().unwrap();
        let memories = dir.path().join("memories");
        write_file(
            &memories.join("MEMORY.md"),
            "## Task 1\nbody\n### rollout_summary_files\n\
             - sessions/2026/04/01/rollout-2026-04-01T10-05-00-thread-aaa.jsonl\n",
        );
        let adapter = CodexAdapter::new(memories, fixture_state_db(), false);
        let pass = adapter.list().expect("list ok");
        assert_eq!(pass.records.len(), 1);

        // Read the full record to confirm the thread join landed.
        let r = adapter.read(&pass.records[0].id).expect("read ok");
        let has_codex_thread = r.session_refs.iter().any(|sref| {
            matches!(sref, SessionRef::CodexThread { thread_id, .. } if thread_id == "thread-aaa")
        });
        assert!(
            has_codex_thread,
            "expected SessionRef::CodexThread for thread-aaa, got {:?}",
            r.session_refs
        );
    }

    #[test]
    fn missing_state_db_with_present_memory_yields_partial_pass() {
        // state_5.sqlite missing → fall back to "unknown project"; surface
        // as a transient skip pointing at the missing DB so the next pass
        // retries.
        let dir = TempDir::new().unwrap();
        let memories = dir.path().join("memories");
        write_file(&memories.join("MEMORY.md"), "## Task 1\nbody\n");
        let adapter = CodexAdapter::new(memories, dir.path().join("missing.sqlite"), false);
        let pass = adapter.list().expect("list ok");
        match pass.completeness {
            PassCompleteness::Partial { skipped } => {
                assert!(
                    skipped.iter().any(|s| s.path.ends_with("missing.sqlite")),
                    "partial pass must surface missing state_db: {skipped:?}"
                );
            }
            other => panic!("expected Partial when state_db is missing, got {other:?}"),
        }
        // Records still extracted; project_id falls through to "codex-no-state".
        assert_eq!(pass.records.len(), 1);
    }

    #[test]
    fn dropped_section_with_empty_body_and_no_tags_is_partial_malformed() {
        // Parser validation: every parsed section must have a non-empty
        // title AND either a tag list OR a non-empty body.
        let dir = TempDir::new().unwrap();
        let memories = dir.path().join("memories");
        write_file(
            &memories.join("MEMORY.md"),
            "## Task 1\n\n## Task 2\nproper body\n",
        );
        let adapter = CodexAdapter::new(memories, dir.path().join("x.sqlite"), false);
        let pass = adapter.list().unwrap();
        assert_eq!(
            pass.records.len(),
            1,
            "only the well-formed section is kept"
        );
        match pass.completeness {
            PassCompleteness::Partial { skipped } => {
                assert!(skipped.iter().any(|s| s.kind == SkipKind::FileMalformed));
            }
            other => panic!("expected Partial, got {other:?}"),
        }
    }
}
