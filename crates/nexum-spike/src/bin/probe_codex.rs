//! Phase 1a Codex probe — investigation tool.
//!
//! Opens a Codex-style state SQLite (read-only) and reports tables + row counts (with sample row in detail mode),
//! then walks the sessions dir reporting per-file line counts + total bytes. Two output modes (`summary` / `detail`)
//! with the same privacy-safe / debug split as probe-cc. Defaults: `--state-db ~/.codex/state_5.sqlite` and
//! `--sessions-dir ~/.codex/sessions/`; override via flags or env vars `NEXUM_TEST_CODEX_STATE_DB` and
//! `NEXUM_TEST_CODEX_SESSIONS_DIR`. Env vars win over flags (matching Phase 0's Paths::resolve precedence).
//!
//! Throwaway. Deleted after Phase 1a findings are folded into the spec.

#![forbid(unsafe_code)]

use clap::{Parser, ValueEnum};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(about = "Phase 1a Codex adapter probe — investigation tool, throwaway.")]
struct Args {
    /// State SQLite path (default: $HOME/.codex/state_5.sqlite, or NEXUM_TEST_CODEX_STATE_DB)
    #[arg(long)]
    state_db: Option<PathBuf>,

    /// Sessions dir (default: $HOME/.codex/sessions/, or NEXUM_TEST_CODEX_SESSIONS_DIR)
    #[arg(long)]
    sessions_dir: Option<PathBuf>,

    /// Output mode.
    #[arg(long, value_enum, default_value_t = Mode::Summary)]
    mode: Mode,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    Summary,
    Detail,
}

fn main() {
    let args = Args::parse();
    let state_db = resolve_state_db(args.state_db.as_deref());
    let sessions_dir = resolve_sessions_dir(args.sessions_dir.as_deref());

    let mut had_input = false;

    if let Some(db) = state_db.as_deref() {
        if db.is_file() {
            had_input = true;
            match scan_state_db(db) {
                Ok(report) => print_state_report(&report, args.mode, db),
                Err(e) => eprintln!("probe-codex: state DB scan failed: {e}"),
            }
        } else {
            eprintln!("probe-codex: state DB not found: {}", db.display());
        }
    }

    if let Some(dir) = sessions_dir.as_deref() {
        if dir.is_dir() {
            had_input = true;
            let report = scan_sessions(dir);
            print_sessions_report(&report, args.mode, dir);
        } else {
            eprintln!("probe-codex: sessions dir not found: {}", dir.display());
        }
    }

    if !had_input {
        eprintln!(
            "probe-codex: nothing to probe — set NEXUM_TEST_CODEX_STATE_DB / \
             NEXUM_TEST_CODEX_SESSIONS_DIR or pass --state-db / --sessions-dir"
        );
        std::process::exit(2);
    }
}

fn resolve_state_db(arg: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("NEXUM_TEST_CODEX_STATE_DB") {
        return Some(PathBuf::from(p));
    }
    if let Some(p) = arg {
        return Some(p.to_owned());
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".codex").join("state_5.sqlite"))
}

fn resolve_sessions_dir(arg: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("NEXUM_TEST_CODEX_SESSIONS_DIR") {
        return Some(PathBuf::from(p));
    }
    if let Some(p) = arg {
        return Some(p.to_owned());
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".codex").join("sessions"))
}

#[derive(Debug)]
struct StateReport {
    tables: Vec<TableFinding>,
}

#[derive(Debug)]
struct TableFinding {
    name: String,
    column_count: usize,
    row_count: i64,
    /// First row, rendered as `(col=value, col=value, ...)`. Empty if row_count == 0
    /// or if the row contains BLOB values we can't safely string-render.
    sample_row: String,
}

fn scan_state_db(path: &Path) -> rusqlite::Result<StateReport> {
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )?;
    let mut tables = Vec::new();
    let table_names: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    for name in table_names {
        let column_count: usize = conn
            .prepare(&format!("PRAGMA table_info({name})"))?
            .query_map([], |_| Ok(()))?
            .count();
        let row_count: i64 =
            conn.query_row(&format!("SELECT count(*) FROM {name}"), [], |r| r.get(0))?;
        let sample_row = if row_count > 0 {
            sample_first_row(&conn, &name).unwrap_or_default()
        } else {
            String::new()
        };
        tables.push(TableFinding {
            name,
            column_count,
            row_count,
            sample_row,
        });
    }
    Ok(StateReport { tables })
}

fn sample_first_row(conn: &Connection, table: &str) -> rusqlite::Result<String> {
    let mut stmt = conn.prepare(&format!("SELECT * FROM {table} LIMIT 1"))?;
    let column_names: Vec<String> = stmt
        .column_names()
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let mut rows = stmt.query([])?;
    let Some(row) = rows.next()? else {
        return Ok(String::new());
    };
    let mut parts = Vec::with_capacity(column_names.len());
    for (i, name) in column_names.iter().enumerate() {
        let value = row.get_ref(i)?;
        let rendered = match value {
            rusqlite::types::ValueRef::Null => "NULL".to_owned(),
            rusqlite::types::ValueRef::Integer(n) => n.to_string(),
            rusqlite::types::ValueRef::Real(f) => f.to_string(),
            rusqlite::types::ValueRef::Text(b) => {
                format!("\"{}\"", String::from_utf8_lossy(b).replace('\n', "\\n"))
            }
            rusqlite::types::ValueRef::Blob(b) => format!("<blob {} bytes>", b.len()),
        };
        parts.push(format!("{name}={rendered}"));
    }
    Ok(format!("({})", parts.join(", ")))
}

fn print_state_report(r: &StateReport, mode: Mode, path: &Path) {
    println!("=== state DB: {} ===", path.display());
    println!("tables: {}", r.tables.len());
    for t in &r.tables {
        println!(
            "  {:24}  {:>3} cols  {:>6} rows",
            t.name, t.column_count, t.row_count
        );
    }
    if matches!(mode, Mode::Detail) {
        println!("\n--- detail: sample row per table ---");
        for t in &r.tables {
            if t.sample_row.is_empty() {
                println!("  {}: (no rows)", t.name);
            } else {
                println!("  {}: {}", t.name, t.sample_row);
            }
        }
    }
}

#[derive(Debug, Default)]
struct SessionsReport {
    sessions: Vec<SessionFinding>,
}

#[derive(Debug)]
struct SessionFinding {
    name: String,
    bytes: u64,
    line_count: usize,
}

fn scan_sessions(dir: &Path) -> SessionsReport {
    let mut report = SessionsReport::default();
    let entries: Vec<_> = std::fs::read_dir(dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .collect();
    for entry in entries {
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("<non-utf8>")
            .to_owned();
        let bytes = entry.metadata().map_or(0, |m| m.len());
        let line_count = std::fs::read_to_string(&path).map_or(0, |s| s.lines().count());
        report.sessions.push(SessionFinding {
            name,
            bytes,
            line_count,
        });
    }
    report.sessions.sort_by(|a, b| a.name.cmp(&b.name));
    report
}

fn print_sessions_report(r: &SessionsReport, mode: Mode, dir: &Path) {
    println!();
    println!("=== sessions dir: {} ===", dir.display());
    println!("session files: {}", r.sessions.len());
    let total_bytes: u64 = r.sessions.iter().map(|s| s.bytes).sum();
    let total_lines: usize = r.sessions.iter().map(|s| s.line_count).sum();
    println!("total bytes:   {total_bytes}");
    println!("total lines:   {total_lines}");
    if matches!(mode, Mode::Detail) {
        println!("\n--- detail: per session ---");
        for s in &r.sessions {
            println!(
                "  {:32}  {:>6} B  {:>4} lines",
                s.name, s.bytes, s.line_count
            );
        }
    }
}
