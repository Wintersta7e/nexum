//! `nexum doctor` — store health check and reanchor-sentinel cleanup.
//!
//! With no flags, runs all 4 checks (key-state summary, signer-file diff,
//! merge-commit detection, reanchor-sentinel presence) and emits a report.
//! Exit 0 if no Critical findings; exit 4 (`STORE_INTEGRITY`) if any Critical.
//! With `--resolve-pending-reanchor`, inspects `~/.nexum/.reanchor_pending`
//! and dispatches the cleanup per the three documented phases.

use std::process::ExitCode;

use clap::Args;
use nexum_core::api::{self, ReanchorResolveMode, ReanchorResolveOutcome};
use nexum_core::paths::Paths;

use super::exit_codes;

// Four `bool` flags are inherent to clap's `Args` derive; a state machine
// would conflict with the `default_value_t` / `conflicts_with` machinery.
#[allow(clippy::struct_excessive_bools)]
#[derive(Args, Debug)]
pub struct DoctorArgs {
    /// Inspect `.reanchor_pending` and apply the phase-based cleanup.
    /// Requires exactly one of `--continue` or `--revert`.
    #[arg(long, default_value_t = false)]
    pub resolve_pending_reanchor: bool,

    /// Re-attempt the next reanchor phase. Valid in phases `pin_updated` or
    /// `events_committed`. Refused in phase `init` (keys-recover not yet
    /// available).
    #[arg(
        long,
        default_value_t = false,
        conflicts_with = "revert",
        requires = "resolve_pending_reanchor"
    )]
    pub r#continue: bool,

    /// Abandon a pending reanchor and remove the sentinel. Only valid in
    /// phase `init` (no signed commit exists yet).
    #[arg(
        long,
        default_value_t = false,
        conflicts_with = "continue",
        requires = "resolve_pending_reanchor"
    )]
    pub revert: bool,

    /// Emit a structured JSON envelope to stdout.
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Force the key-state summary into the prose output even when the
    /// store is otherwise clean. (JSON mode always emits the summary.)
    #[arg(long, default_value_t = false)]
    pub key_state: bool,

    /// Force the signer-file check result into the prose output even when
    /// the projection matches disk. (JSON mode always emits it.)
    #[arg(long, default_value_t = false)]
    pub check_trust_files: bool,
}

// ─── Output types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "severity", rename_all = "lowercase")]
pub enum DoctorCheckResult {
    Ok,
    Warn { code: String, message: String },
    Critical { code: String, message: String },
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct KeyStateSummary {
    pub active: u32,
    pub rotated: u32,
    pub compromised: u32,
    pub reanchored: u32,
    pub bootstrap_fingerprint: String,
    pub current_signer_fingerprint: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorReport {
    pub ok: bool,
    pub kind: &'static str,
    pub key_state: KeyStateSummary,
    pub signer_files: DoctorCheckResult,
    pub merge_commits: DoctorCheckResult,
    pub reanchor_sentinel: DoctorCheckResult,
    pub acked_warnings: Vec<String>,
}

// ─── Entry point ─────────────────────────────────────────────────────────────

pub fn run(args: &DoctorArgs) -> ExitCode {
    if args.resolve_pending_reanchor {
        return run_resolve_pending(args);
    }

    // Default mode bypasses `resolve_runtime` so a pending sentinel surfaces
    // as a Warn rather than causing exit 8.
    let paths = match nexum_core::paths::Paths::resolve() {
        Ok(p) => p,
        Err(e) => {
            if args.json {
                let env = serde_json::json!({
                    "ok": false,
                    "code": "NOT_INITIALIZED",
                    "message": e.to_string(),
                });
                println!("{env:#}");
            } else {
                eprintln!("error: {e}");
            }
            return ExitCode::from(exit_codes::NOT_INITIALIZED);
        }
    };
    let cfg = match nexum_core::config::load(&paths.config) {
        Ok(c) => c,
        Err(e) => {
            let env: nexum_core::api::error::ErrorEnvelope =
                (&nexum_core::api::ApiError::Config(e)).into();
            if args.json {
                return super::json_emit::emit_error(&env, exit_codes::for_envelope(&env));
            }
            eprintln!("error: {}", env.message);
            return ExitCode::from(exit_codes::for_envelope(&env));
        }
    };

    // key_state_summary opens index.db via keys_list. When the index is
    // absent or a reanchor sentinel blocks the open, degrade to a zeroed
    // summary rather than aborting — the sentinel and signer-file checks
    // still run and the sentinel will surface as a Warn in reanchor_sentinel.
    let key_state = match key_state_summary(&paths, &cfg) {
        Ok(s) => s,
        Err(
            nexum_core::api::ApiError::Query(nexum_core::query::QueryError::IndexMissing {
                ..
            })
            | nexum_core::api::ApiError::Trust(
                nexum_core::trust::events::TrustError::ReanchorPending { .. },
            ),
        ) => KeyStateSummary {
            active: 0,
            rotated: 0,
            compromised: 0,
            reanchored: 0,
            bootstrap_fingerprint: cfg.trust.bootstrap.fingerprint.clone(),
            current_signer_fingerprint: None,
        },
        Err(e) => {
            let env: nexum_core::api::error::ErrorEnvelope = (&e).into();
            if args.json {
                return super::json_emit::emit_error(&env, exit_codes::for_envelope(&env));
            }
            eprintln!("error: {}", env.message);
            return ExitCode::from(exit_codes::for_envelope(&env));
        }
    };
    let signer_files = signer_file_check(&paths);
    let merge_commits = merge_commit_check(&paths);
    let reanchor_sentinel = reanchor_sentinel_check(&paths);
    let acked_warnings = api::list_pre_recovery_acks(&paths).unwrap_or_default();

    let has_critical = matches!(signer_files, DoctorCheckResult::Critical { .. })
        || matches!(merge_commits, DoctorCheckResult::Critical { .. });

    let report = DoctorReport {
        ok: !has_critical,
        kind: "doctor.report",
        key_state,
        signer_files,
        merge_commits,
        reanchor_sentinel,
        acked_warnings,
    };

    if args.json {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(_) => return ExitCode::from(1),
        }
    } else {
        render_prose_report(&report, args.key_state, args.check_trust_files);
    }

    if has_critical {
        ExitCode::from(exit_codes::STORE_INTEGRITY)
    } else {
        ExitCode::SUCCESS
    }
}

// ─── Check helpers ────────────────────────────────────────────────────────────

fn key_state_summary(
    paths: &nexum_core::paths::Paths,
    cfg: &nexum_core::config::types::Config,
) -> Result<KeyStateSummary, nexum_core::api::ApiError> {
    let outcome = nexum_core::api::keys_list(paths, cfg)?;
    let mut active = 0u32;
    let mut rotated = 0u32;
    let mut compromised = 0u32;
    let mut reanchored = 0u32;
    for k in &outcome.keys {
        use nexum_core::trust::key_state::KeyRole;
        match k.role {
            KeyRole::Active => active += 1,
            KeyRole::Rotated => rotated += 1,
            KeyRole::Compromised => compromised += 1,
            KeyRole::Reanchored => reanchored += 1,
        }
    }
    Ok(KeyStateSummary {
        active,
        rotated,
        compromised,
        reanchored,
        bootstrap_fingerprint: outcome.bootstrap_fingerprint,
        current_signer_fingerprint: outcome.current_signer_fingerprint,
    })
}

fn signer_file_check(paths: &nexum_core::paths::Paths) -> DoctorCheckResult {
    use nexum_core::trust::regenerate::regenerate_files;

    let events_yml = paths.notebook_git.join(".trust/events.yml");
    let trust_dir = paths.notebook_git.join(".trust");

    // Dry-run regeneration into a tempdir; compare to live files.
    let tmp = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => {
            return DoctorCheckResult::Warn {
                code: "doctor-temp-fail".into(),
                message: format!("could not create temp dir: {e}"),
            };
        }
    };
    let tmp_trust = tmp.path();
    if let Err(e) = std::fs::copy(&events_yml, tmp_trust.join("events.yml")) {
        return DoctorCheckResult::Warn {
            code: "doctor-events-read-fail".into(),
            message: format!("could not read events.yml: {e}"),
        };
    }
    if let Err(e) = regenerate_files(&tmp_trust.join("events.yml"), tmp_trust) {
        return DoctorCheckResult::Critical {
            code: "trust-files-projection-fail".into(),
            message: format!("regenerate_files failed: {e}"),
        };
    }
    let mut mismatch: Vec<String> = Vec::new();
    for name in &["historical_signers", "allowed_signers", "revoked_signers"] {
        let expected = std::fs::read_to_string(tmp_trust.join(name)).unwrap_or_default();
        let actual = std::fs::read_to_string(trust_dir.join(name)).unwrap_or_default();
        if expected.trim() != actual.trim() {
            mismatch.push((*name).to_owned());
        }
    }
    if mismatch.is_empty() {
        return DoctorCheckResult::Ok;
    }

    // Classify: if the only diff is allowed_signers containing pubkeys for
    // old fingerprints of BootstrapReanchor events, it's pre-recovery drift
    // (old key still listed) rather than genuine tampering — Warn, not Critical.
    if is_legacy_reanchor_drift(&events_yml, &trust_dir, tmp_trust, &mismatch) {
        DoctorCheckResult::Warn {
            code: "trust-files-pre-recovery-drift".into(),
            message: format!(
                "{} contains the pre-recovery projection (old key still listed); \
                 run `nexum trust regenerate-files` to update",
                mismatch.join(", ")
            ),
        }
    } else {
        DoctorCheckResult::Critical {
            code: "trust-files-mismatch".into(),
            message: format!(
                "{} differs from the events.yml projection; \
                 run `nexum trust regenerate-files`",
                mismatch.join(", ")
            ),
        }
    }
}

/// Returns true when the on-disk `allowed_signers` differs from the
/// freshly-regenerated projection by exactly one line per
/// `BootstrapReanchor.old_fingerprint` pubkey (the pre-recovery shape).
/// All other mismatches — missing expected entries, extra unrelated keys,
/// duplicates, or differences in other signer files — return false so the
/// caller raises a Critical tampering finding instead of a Warn.
fn is_legacy_reanchor_drift(
    events_yml: &std::path::Path,
    trust_dir: &std::path::Path,
    expected_trust_dir: &std::path::Path,
    mismatched_files: &[String],
) -> bool {
    use std::collections::{HashMap, HashSet};

    use nexum_core::trust::events::EventKind;

    // Only `allowed_signers` can be the legacy-drift surface; mismatches
    // in historical_signers / revoked_signers always mean tampering.
    if mismatched_files.iter().any(|n| n != "allowed_signers") {
        return false;
    }
    let Ok(log) = nexum_core::trust::events::load_events_yml(events_yml) else {
        return false;
    };

    // Collect reanchor old-fingerprints and a fingerprint→pubkey map.
    let mut reanchor_old_fps: HashSet<&str> = HashSet::new();
    let mut fp_to_pubkey: HashMap<&str, &str> = HashMap::new();
    for e in &log.events {
        match &e.payload {
            EventKind::BootstrapReanchor {
                old_fingerprint, ..
            } => {
                reanchor_old_fps.insert(old_fingerprint.as_str());
            }
            EventKind::BootstrapKey {
                fingerprint,
                public_key,
                ..
            }
            | EventKind::KeyAdded {
                fingerprint,
                public_key,
                ..
            } => {
                fp_to_pubkey.insert(fingerprint.as_str(), public_key.as_str());
            }
            _ => {}
        }
    }
    if reanchor_old_fps.is_empty() {
        return false;
    }
    let expected_old_pubkeys: HashSet<&str> = reanchor_old_fps
        .iter()
        .filter_map(|fp| fp_to_pubkey.get(fp).copied())
        .collect();
    // Every old fp must resolve to a pubkey, else we cannot safely classify.
    if expected_old_pubkeys.len() != reanchor_old_fps.len() {
        return false;
    }

    let parse_lines = |text: &str| -> HashSet<String> {
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect()
    };
    let expected_lines = parse_lines(
        &std::fs::read_to_string(expected_trust_dir.join("allowed_signers")).unwrap_or_default(),
    );
    let actual_lines = parse_lines(
        &std::fs::read_to_string(trust_dir.join("allowed_signers")).unwrap_or_default(),
    );

    // Legacy drift = actual is a strict superset of expected, and each
    // extra line carries exactly one old-reanchor pubkey, with every old
    // pubkey covered by at least one extra. Anything else (missing
    // expected entries, lines that mention zero or multiple old pubkeys)
    // is tampering.
    if !expected_lines.is_subset(&actual_lines) {
        return false;
    }
    let extras: Vec<&String> = actual_lines.difference(&expected_lines).collect();
    let mut covered: HashSet<&str> = HashSet::new();
    for extra in &extras {
        let mut count = 0usize;
        let mut matched: &str = "";
        for pk in &expected_old_pubkeys {
            if extra.contains(*pk) {
                count += 1;
                matched = *pk;
            }
        }
        if count != 1 {
            return false;
        }
        covered.insert(matched);
    }
    covered == expected_old_pubkeys
}

fn merge_commit_check(paths: &nexum_core::paths::Paths) -> DoctorCheckResult {
    // notebook.git is a trust-only repo: any merge commit in its history is a
    // linear-history violation. The query lives in nexum-core so it can run
    // through the env-scrubbed git builder — a user gitconfig must not be able
    // to redirect it.
    match nexum_core::trust::git_history::notebook_merge_commits(&paths.notebook_git) {
        Ok(shas) if shas.is_empty() => DoctorCheckResult::Ok,
        Ok(shas) => DoctorCheckResult::Critical {
            code: "trust-history-not-linear".into(),
            message: format!("merge commits found in trust history: {}", shas.join(", ")),
        },
        Err(_) => DoctorCheckResult::Warn {
            code: "doctor-git-log-fail".into(),
            message: "git log failed; could not check for merges".into(),
        },
    }
}

fn reanchor_sentinel_check(paths: &nexum_core::paths::Paths) -> DoctorCheckResult {
    use nexum_core::trust::reanchor_pending::read_sentinel;
    match read_sentinel(&paths.home) {
        Ok(None) => DoctorCheckResult::Ok,
        Ok(Some(sentinel)) => DoctorCheckResult::Warn {
            code: "reanchor-pending".into(),
            message: format!(
                "pending reanchor (phase {}); resolve via `nexum doctor --resolve-pending-reanchor`",
                sentinel.phase_completed().as_str()
            ),
        },
        Err(_) => DoctorCheckResult::Warn {
            code: "reanchor-sentinel-malformed".into(),
            message: "sentinel exists but is malformed".into(),
        },
    }
}

// ─── Prose renderer ──────────────────────────────────────────────────────────

fn render_prose_report(report: &DoctorReport, force_key_state: bool, force_trust_files: bool) {
    println!("doctor: {}", if report.ok { "OK" } else { "ISSUES FOUND" });
    println!();

    if force_key_state
        || report.key_state.rotated > 0
        || report.key_state.compromised > 0
        || report.key_state.reanchored > 0
        || report.key_state.active > 1
    {
        println!(
            "keys: active={}, rotated={}, compromised={}, reanchored={}",
            report.key_state.active,
            report.key_state.rotated,
            report.key_state.compromised,
            report.key_state.reanchored,
        );
    }

    match &report.signer_files {
        DoctorCheckResult::Ok if force_trust_files => println!("signer files: OK"),
        DoctorCheckResult::Ok => {}
        DoctorCheckResult::Warn { message, .. } => println!("signer files (warn): {message}"),
        DoctorCheckResult::Critical { message, .. } => {
            println!("signer files (CRITICAL): {message}");
        }
    }

    match &report.merge_commits {
        DoctorCheckResult::Ok => {}
        DoctorCheckResult::Warn { message, .. } => println!("merges (warn): {message}"),
        DoctorCheckResult::Critical { message, .. } => println!("merges (CRITICAL): {message}"),
    }

    match &report.reanchor_sentinel {
        DoctorCheckResult::Ok => {}
        DoctorCheckResult::Warn { message, .. } => println!("reanchor (warn): {message}"),
        DoctorCheckResult::Critical { message, .. } => println!("reanchor (CRITICAL): {message}"),
    }

    if !report.acked_warnings.is_empty() {
        println!();
        println!("suppressed warnings: {}", report.acked_warnings.join(", "));
    }
}

// ─── --resolve-pending-reanchor branch ───────────────────────────────────────

/// Handle `--resolve-pending-reanchor`. Deliberately bypasses the normal
/// `resolve_runtime` pre-check so that a command whose entire purpose is to
/// clear a reanchor sentinel is not itself blocked by that sentinel.
fn run_resolve_pending(args: &DoctorArgs) -> ExitCode {
    let paths = match Paths::resolve() {
        Ok(p) => p,
        Err(e) => {
            if args.json {
                let env = serde_json::json!({
                    "ok": false,
                    "code": "NOT_INITIALIZED",
                    "message": e.to_string(),
                });
                println!("{env:#}");
            } else {
                eprintln!("error: {e}");
            }
            return ExitCode::from(exit_codes::NOT_INITIALIZED);
        }
    };

    let mode = match (args.r#continue, args.revert) {
        (true, false) => Some(ReanchorResolveMode::Continue),
        (false, true) => Some(ReanchorResolveMode::Revert),
        _ => None,
    };

    match api::resolve_pending_reanchor(&paths, mode) {
        Ok(ReanchorResolveOutcome::NoSentinel) => {
            if args.json {
                println!(r#"{{"ok": true, "kind": "doctor.reanchor.no_sentinel"}}"#);
            } else {
                println!("no pending reanchor; nothing to do");
            }
            ExitCode::SUCCESS
        }
        Ok(ReanchorResolveOutcome::Resolved { from_phase }) => {
            if args.json {
                let env = serde_json::json!({
                    "ok": true,
                    "kind": "doctor.reanchor.resolved",
                    "from_phase": from_phase,
                });
                println!("{env:#}");
            } else {
                println!("resolved pending reanchor (was phase={from_phase})");
            }
            ExitCode::SUCCESS
        }
        Ok(ReanchorResolveOutcome::Refused { phase, reason }) => {
            // Refused is a usage error (wrong mode for the phase, or no
            // mode flag), not a store-integrity violation — exit code 2
            // so agents can distinguish recoverable input mistakes from
            // store damage.
            if args.json {
                let env = serde_json::json!({
                    "ok": false,
                    "code": "USAGE",
                    "kind": "doctor.reanchor.refused",
                    "phase": phase,
                    "message": reason,
                });
                println!("{env:#}");
            } else {
                eprintln!("refused: {reason}");
            }
            ExitCode::from(exit_codes::USAGE)
        }
        Err(e) => {
            let env: nexum_core::api::error::ErrorEnvelope = (&e).into();
            if args.json {
                super::json_emit::emit_error(&env, exit_codes::for_envelope(&env))
            } else {
                eprintln!("error: {}", env.message);
                ExitCode::from(exit_codes::for_envelope(&env))
            }
        }
    }
}
