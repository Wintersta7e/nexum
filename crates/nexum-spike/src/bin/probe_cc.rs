//! Phase 1a CC probe — investigation tool.
//!
//! Walks a directory mirroring `~/.claude/projects/<encoded-cwd>/` and reports the
//! shape of what's there: how many projects, how many memory files per project, and
//! which of the two known layouts they use (top-level `CLAUDE.md` vs. subdir
//! `memory/MEMORY.md`). Two output modes:
//!   --mode summary  (default): counts + layout-tag totals; no per-file paths
//!                              (privacy-safe; suitable for the findings doc)
//!   --mode detail:             includes per-file path + size (local debug only;
//!                              never commit this output)
//!
//! Override the projects dir via `--projects-dir <PATH>` or `NEXUM_TEST_CC_PROJECTS_DIR`.
//! The env var wins if both are set, matching Phase 0's Paths::resolve precedence.
//!
//! Throwaway. Will be deleted after Phase 1a's findings are folded into the spec.

#![forbid(unsafe_code)]

use clap::{Parser, ValueEnum};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(about = "Phase 1a CC adapter probe — investigation tool, throwaway.")]
struct Args {
    /// Root projects dir (default: $HOME/.claude/projects/, or NEXUM_TEST_CC_PROJECTS_DIR)
    #[arg(long)]
    projects_dir: Option<PathBuf>,

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
    let root = resolve_projects_dir(args.projects_dir.as_deref());
    let Some(root) = root else {
        eprintln!(
            "probe-cc: no projects dir resolved (set NEXUM_TEST_CC_PROJECTS_DIR, \
             pass --projects-dir, or ensure $HOME/.claude/projects/ exists)"
        );
        std::process::exit(2);
    };

    if !root.is_dir() {
        eprintln!("probe-cc: not a directory: {}", root.display());
        std::process::exit(2);
    }

    let report = scan(&root);
    print_report(&report, args.mode, &root);
}

fn resolve_projects_dir(arg: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("NEXUM_TEST_CC_PROJECTS_DIR") {
        return Some(PathBuf::from(p));
    }
    if let Some(p) = arg {
        return Some(p.to_owned());
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".claude").join("projects"))
}

#[derive(Debug, Default)]
struct Report {
    projects: Vec<ProjectFinding>,
}

#[derive(Debug)]
struct ProjectFinding {
    /// Last path component of the project dir.
    name: String,
    files: Vec<MemoryFile>,
    total_bytes: u64,
}

#[derive(Debug)]
struct MemoryFile {
    /// Path RELATIVE to the project dir.
    rel_path: PathBuf,
    layout: Layout,
    bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Layout {
    /// `<project>/CLAUDE.md` — the top-level form.
    TopLevelClaudeMd,
    /// `<project>/memory/MEMORY.md` — the subdir form.
    SubdirMemoryMd,
    /// Anything else under the project dir (other markdown, JSON, etc.)
    Other,
}

impl Layout {
    fn tag(self) -> &'static str {
        match self {
            Self::TopLevelClaudeMd => "top-level-CLAUDE.md",
            Self::SubdirMemoryMd => "subdir-memory-MEMORY.md",
            Self::Other => "other",
        }
    }
}

fn scan(root: &Path) -> Report {
    let mut report = Report::default();
    let project_entries: Vec<_> = std::fs::read_dir(root)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|e| e.path().is_dir())
        .collect();
    for proj_entry in project_entries {
        let proj_path = proj_entry.path();
        let name = proj_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("<non-utf8>")
            .to_owned();
        let mut files = Vec::new();
        let mut total_bytes = 0_u64;
        for entry in WalkDir::new(&proj_path).max_depth(3).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }
            let rel = entry
                .path()
                .strip_prefix(&proj_path)
                .unwrap_or(entry.path())
                .to_owned();
            let bytes = entry.metadata().map_or(0, |m| m.len());
            let layout = classify(&rel);
            total_bytes += bytes;
            files.push(MemoryFile {
                rel_path: rel,
                layout,
                bytes,
            });
        }
        report.projects.push(ProjectFinding {
            name,
            files,
            total_bytes,
        });
    }
    report.projects.sort_by(|a, b| a.name.cmp(&b.name));
    report
}

fn classify(rel: &Path) -> Layout {
    let s = rel.to_string_lossy();
    if s == "CLAUDE.md" {
        Layout::TopLevelClaudeMd
    } else if s == "memory/MEMORY.md" || s == "memory\\MEMORY.md" {
        Layout::SubdirMemoryMd
    } else {
        Layout::Other
    }
}

fn print_report(r: &Report, mode: Mode, root: &Path) {
    println!("probe-cc — projects dir: {}", root.display());
    println!("projects discovered: {}", r.projects.len());
    let total_files: usize = r.projects.iter().map(|p| p.files.len()).sum();
    let total_bytes: u64 = r.projects.iter().map(|p| p.total_bytes).sum();
    println!("memory-related files: {total_files}");
    println!("total bytes:          {total_bytes}");

    let mut tag_counts = std::collections::BTreeMap::<&'static str, usize>::new();
    for p in &r.projects {
        for f in &p.files {
            *tag_counts.entry(f.layout.tag()).or_default() += 1;
        }
    }
    println!("layout breakdown:");
    for (tag, n) in &tag_counts {
        println!("  {tag}: {n}");
    }

    if matches!(mode, Mode::Detail) {
        println!();
        println!("--- detail (project-by-project) ---");
        for p in &r.projects {
            println!("project: {} ({} bytes total)", p.name, p.total_bytes);
            for f in &p.files {
                println!(
                    "  {:<30}  {:>6} B  [{}]",
                    f.rel_path.display(),
                    f.bytes,
                    f.layout.tag()
                );
            }
        }
    }
}
