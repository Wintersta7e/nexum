//! Spike S6 — full trust state machine roundtrip with REAL records
//!
//! Pass criteria (per design §3.6 S6, expanded in v1.7 from 6 → 7 phases):
//!   1. Bootstrap key A; events.yml + 3 derived signer files + META.yml; signed bootstrap commit;
//!      one trust_events row.
//!   2. Real record signed by A under decisions/test-rec-A.yml; verify_record → verified, current.
//!   3. KeyAdded(B); events.yml + regen; commit signed by A; two trust_events rows.
//!   4. KeyRotatedOut(A); events.yml + regen; commit signed by B.
//!      verify_record(test-rec-A) → verified, rotated-historical, ["signer-key-rotated"].
//!      Plain `git verify-commit` (no redirect) against default config → expect FAILURE.
//!   5. NEGATIVE — payload tampering: edit existing event's public_key in commit C4. Re-materialize.
//!      Expect trust_chain_tampering row. verify_record → invalid, ["broken-trust-chain", "event-tampered"].
//!   6. NEGATIVE — reanchor without pin update: D signs BootstrapReanchor(A,D) but pin not updated.
//!      verify_record(test-rec-A) → invalid, ["broken-trust-chain"].
//!   7. POSITIVE reanchor: pin updated first, then BootstrapReanchor commit + Cr2 signed by D.
//!      verify_record(test-rec-A) (pre-reanchor) → verified, pre-reanchor, ["pre-recovery-record"].
//!      verify_record(test-rec-D) (post-reanchor) → verified, current.
//!
//! Throwaway. The trust state machine implemented here is a minimal-viable subset of §9 — just
//! enough to drive the 7 phases and validate the design's invariants. M1's production
//! implementation lives in nexum-core and will be more thorough (proper error types,
//! incremental materialization, transactional file writes). The point of this spike is to
//! confirm the design works end-to-end before committing the production implementation.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::similar_names,
    clippy::too_many_lines,
    // `Event { event_id, ... }` — `event_id` is the canonical term in the §9 state machine.
    clippy::struct_field_names,
)]

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use ssh_key::sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

// ============================================================================
// Test plan: phases 1-7 on three throwaway repos sharing the same key set.
//
//   repo_main  — phases 1..5 (linear timeline: bootstrap → record → KeyAdded →
//                KeyRotatedOut → tampered C4)
//   repo_neg6  — phase 6: fork from C2 state, reanchor signed by D WITHOUT pin update.
//   repo_pos7  — phase 7: fork from C2 state, reanchor signed by D WITH pin updated.
// ============================================================================

fn main() -> Result<()> {
    init_tracing();
    let mut report = Report::new();

    // Probe environment for required tools.
    if let Err(e) = probe_env() {
        report.fail(
            "env-probe",
            &format!("{e}. Spike requires: git >= 2.34, ssh-keygen."),
        );
        report.print();
        std::process::exit(1);
    }
    report.pass("env-probe", "git >= 2.34 + ssh-keygen present");

    let scratch = tempfile::tempdir().context("create temp scratch dir")?;
    let scratch_path = scratch.path().to_owned();
    let key_dir = scratch_path.join("keys");
    std::fs::create_dir_all(&key_dir)?;

    // Generate three Ed25519 keys (A, B, D).
    let key_a = SshKey::generate(&key_dir, "key-a").context("generate key A")?;
    let key_b = SshKey::generate(&key_dir, "key-b").context("generate key B")?;
    let key_d = SshKey::generate(&key_dir, "key-d").context("generate key D")?;
    report.pass(
        "ssh-keygen",
        &format!(
            "3 Ed25519 keys generated (fingerprints A/B/D = {}/{}/{})",
            short(&key_a.fingerprint),
            short(&key_b.fingerprint),
            short(&key_d.fingerprint),
        ),
    );

    // ===== Repo for phases 1-5 (linear) =====
    let repo_main = scratch_path.join("repo-main");
    git_init(&repo_main).context("init main repo")?;
    setup_allowed_signers(&repo_main, &[&key_a, &key_b, &key_d])?;

    // -------------------- PHASE 1 --------------------
    let mut events = vec![Event::new_bootstrap_key(&key_a.public_openssh)];
    write_trust_state(&repo_main, &events)?;
    git_add_all(&repo_main)?;
    let _c1 = git_commit_signed(&repo_main, &key_a, "bootstrap with key A")?;
    let state_1 = materialize_trust_events(&repo_main)?;
    report.assert(
        "phase-1-bootstrap",
        state_1.events.len() == 1
            && matches!(state_1.events[0].kind, EventKind::BootstrapKey)
            && state_1.events[0].fingerprint == key_a.fingerprint,
        &format!(
            "trust_events rows: {} (expected 1, BootstrapKey, fp={}); got {:?}",
            state_1.events.len(),
            short(&key_a.fingerprint),
            state_1
                .events
                .iter()
                .map(|e| (e.kind.as_str(), short(&e.fingerprint)))
                .collect::<Vec<_>>()
        ),
    );

    // -------------------- PHASE 2 --------------------
    write_record(&repo_main, "test-rec-A", "Real record signed by A.")?;
    git_add_all(&repo_main)?;
    let _cr1 = git_commit_signed(&repo_main, &key_a, "add decisions/test-rec-A.yml")?;
    let v2 = verify_record(&repo_main, "test-rec-A", &state_1)?;
    report.assert(
        "phase-2-real-record-signed-by-A",
        v2.signature_status == SignatureStatus::Verified
            && v2.trust_basis == TrustBasis::Current
            && v2.warnings.is_empty(),
        &format!("verify_record(test-rec-A) = {v2:?}"),
    );

    // -------------------- PHASE 3 --------------------
    events.push(Event::new_key_added(&key_b.public_openssh));
    write_trust_state(&repo_main, &events)?;
    git_add_all(&repo_main)?;
    let _c2 = git_commit_signed(&repo_main, &key_a, "KeyAdded(B) signed by A")?;
    let state_3 = materialize_trust_events(&repo_main)?;
    report.assert(
        "phase-3-key-added",
        state_3.events.len() == 2
            && matches!(state_3.events[1].kind, EventKind::KeyAdded)
            && state_3.events[1].fingerprint == key_b.fingerprint,
        &format!(
            "trust_events rows: {} (expected 2, last=KeyAdded fp={})",
            state_3.events.len(),
            short(&key_b.fingerprint)
        ),
    );

    // -------------------- PHASE 4 --------------------
    events.push(Event::new_key_rotated_out(&key_a.public_openssh));
    write_trust_state(&repo_main, &events)?;
    git_add_all(&repo_main)?;
    let _c3 = git_commit_signed(&repo_main, &key_b, "KeyRotatedOut(A) signed by B")?;
    let state_4 = materialize_trust_events(&repo_main)?;
    let v4 = verify_record(&repo_main, "test-rec-A", &state_4)?;
    let plain_verify_failed = !git_verify_commit_plain_succeeds(&repo_main, "HEAD~2");
    report.assert(
        "phase-4-key-rotated-out",
        v4.signature_status == SignatureStatus::Verified
            && v4.trust_basis == TrustBasis::RotatedHistorical
            && v4.warnings == vec!["signer-key-rotated".to_owned()]
            && plain_verify_failed,
        &format!(
            "verify_record(test-rec-A) = {v4:?}; plain `git verify-commit` failed = {plain_verify_failed}"
        ),
    );

    // -------------------- PHASE 5 (negative — tamper) --------------------
    // Mutate KeyAdded(B) public_key in events.yml in a NEW commit C4 signed by B.
    let tampered = tamper_key_added_event(&events, &key_d.public_openssh);
    write_trust_state(&repo_main, &tampered)?;
    git_add_all(&repo_main)?;
    let _c4 = git_commit_signed(
        &repo_main,
        &key_b,
        "tamper events.yml: change KeyAdded(B) public_key",
    )?;
    let state_5 = materialize_trust_events(&repo_main)?;
    let v5 = verify_record(&repo_main, "test-rec-A", &state_5)?;
    report.assert(
        "phase-5-negative-tampering",
        !state_5.tampered_event_ids.is_empty()
            && v5.signature_status == SignatureStatus::Invalid
            && v5.warnings.contains(&"broken-trust-chain".to_owned())
            && v5.warnings.contains(&"event-tampered".to_owned()),
        &format!(
            "tamper rows: {}; verify(test-rec-A) = {:?}",
            state_5.tampered_event_ids.len(),
            v5
        ),
    );

    // -------------------- PHASE 6 (negative — reanchor without pin) --------------------
    let repo_neg6 = scratch_path.join("repo-neg6");
    let mut events_n6 =
        fork_from_state_after_c2(&repo_main, &repo_neg6, &[&key_a, &key_b, &key_d])?;
    events_n6.push(Event::new_bootstrap_reanchor(
        &key_a.public_openssh,
        &key_d.public_openssh,
    ));
    write_trust_state(&repo_neg6, &events_n6)?;
    git_add_all(&repo_neg6)?;
    let _r_n6 = git_commit_signed(
        &repo_neg6,
        &key_d,
        "BootstrapReanchor(A->D) signed by D (no pin)",
    )?;
    let state_n6 = materialize_trust_events(&repo_neg6)?;
    let pin_n6 = TrustPin::pinned_to(&key_a.fingerprint); // pin still on A — NOT updated
    let v6 = verify_record_with_pin(&repo_neg6, "test-rec-A", &state_n6, &pin_n6)?;
    report.assert(
        "phase-6-negative-reanchor-without-pin",
        v6.signature_status == SignatureStatus::Invalid
            && v6.warnings.contains(&"broken-trust-chain".to_owned()),
        &format!("verify(test-rec-A) on n6 = {v6:?}"),
    );

    // -------------------- PHASE 7 (positive reanchor + post-reanchor record) --------------------
    let repo_pos7 = scratch_path.join("repo-pos7");
    let mut events_p7 =
        fork_from_state_after_c2(&repo_main, &repo_pos7, &[&key_a, &key_b, &key_d])?;
    events_p7.push(Event::new_bootstrap_reanchor(
        &key_a.public_openssh,
        &key_d.public_openssh,
    ));
    write_trust_state(&repo_pos7, &events_p7)?;
    git_add_all(&repo_pos7)?;
    let _r_p7 = git_commit_signed(&repo_pos7, &key_d, "BootstrapReanchor(A->D) signed by D")?;
    write_record(
        &repo_pos7,
        "test-rec-D",
        "Post-reanchor record signed by D.",
    )?;
    git_add_all(&repo_pos7)?;
    let _cr2 = git_commit_signed(&repo_pos7, &key_d, "add decisions/test-rec-D.yml")?;
    let state_p7 = materialize_trust_events(&repo_pos7)?;
    let pin_p7 = TrustPin::pinned_to(&key_d.fingerprint); // pin updated to D BEFORE reanchor

    let v7a = verify_record_with_pin(&repo_pos7, "test-rec-A", &state_p7, &pin_p7)?;
    let v7d = verify_record_with_pin(&repo_pos7, "test-rec-D", &state_p7, &pin_p7)?;
    report.assert(
        "phase-7-positive-reanchor",
        v7a.signature_status == SignatureStatus::Verified
            && v7a.trust_basis == TrustBasis::PreReanchor
            && v7a.warnings.contains(&"pre-recovery-record".to_owned())
            && v7d.signature_status == SignatureStatus::Verified
            && v7d.trust_basis == TrustBasis::Current,
        &format!("verify(test-rec-A) = {v7a:?}; verify(test-rec-D) = {v7d:?}"),
    );

    // Cleanup is automatic — `scratch` (tempdir) is dropped at scope exit.
    drop(scratch);

    report.print();
    if report.all_pass() {
        Ok(())
    } else {
        std::process::exit(1)
    }
}

// ============================================================================
// SSH key generation + format
// ============================================================================

#[derive(Debug, Clone)]
struct SshKey {
    name: String,
    private_path: PathBuf,
    /// OpenSSH single-line public key text: `ssh-ed25519 AAAA... <name>`
    public_openssh: String,
    /// SHA256 fingerprint hex (matches what `ssh-keygen -l -f pub` would print, sans prefix).
    fingerprint: String,
    /// Email used for git committer + allowed_signers map.
    email: String,
}

impl SshKey {
    fn generate(dir: &Path, name: &str) -> Result<Self> {
        use ssh_key::PrivateKey;

        // Generate via ssh-keygen — produces a file pair with correct OpenSSH format and 0600
        // perms. ssh-key crate's PrivateKey::random produces in-memory bytes; writing to disk
        // and re-loading via OpenSSH parser is fine, but ssh-keygen avoids the serialization
        // round-trip and matches what a real user would use.
        let private_path = dir.join(name);
        let _ = std::fs::remove_file(&private_path);
        let _ = std::fs::remove_file(dir.join(format!("{name}.pub")));

        let status = Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                private_path.to_str().context("non-utf8 path")?,
                "-N",
                "",
                "-C",
                &format!("{name}@nexum-spike"),
                "-q",
            ])
            .status()
            .context("invoke ssh-keygen")?;
        if !status.success() {
            bail!("ssh-keygen failed");
        }

        // Sanity-check via the ssh-key crate that the generated key is parseable Ed25519.
        let key_bytes = std::fs::read(&private_path)?;
        let _verified: PrivateKey =
            PrivateKey::from_openssh(&key_bytes).context("ssh-key parse generated private key")?;
        // Production may switch from `ssh-keygen` shellout to `PrivateKey::random` (in-process
        // keygen) — kept the import + parse roundtrip above to validate the format compatibility.

        let public_openssh = std::fs::read_to_string(dir.join(format!("{name}.pub")))?
            .trim()
            .to_owned();
        let fingerprint = ssh_keygen_fingerprint(&dir.join(format!("{name}.pub")))?;
        let email = format!("{name}@nexum-spike.local");

        Ok(Self {
            name: name.to_owned(),
            private_path,
            public_openssh,
            fingerprint,
            email,
        })
    }
}

fn ssh_keygen_fingerprint(pub_path: &Path) -> Result<String> {
    let out = Command::new("ssh-keygen")
        .args(["-l", "-f", pub_path.to_str().context("non-utf8 path")?])
        .output()
        .context("ssh-keygen -l")?;
    if !out.status.success() {
        bail!(
            "ssh-keygen -l failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    // Output: "256 SHA256:abc123... user@host (ED25519)"
    let line = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let fp = line
        .split_whitespace()
        .nth(1)
        .context("ssh-keygen output missing fingerprint field")?
        .to_owned();
    Ok(fp)
}

fn short(fp: &str) -> String {
    fp.chars().take(20).collect::<String>() + "…"
}

// ============================================================================
// git operations (shell-out — git2 doesn't natively SSH-sign)
// ============================================================================

fn probe_env() -> Result<()> {
    let v = Command::new("git").arg("--version").output()?;
    let s = String::from_utf8_lossy(&v.stdout).to_string();
    let parts: Vec<&str> = s.split_whitespace().collect();
    let raw_version = parts.get(2).copied().unwrap_or("0.0.0");
    let major_minor: Vec<&str> = raw_version.split('.').take(2).collect();
    let maj = major_minor
        .first()
        .and_then(|x| x.parse::<u32>().ok())
        .unwrap_or(0);
    let min = major_minor
        .get(1)
        .and_then(|x| x.parse::<u32>().ok())
        .unwrap_or(0);
    if (maj, min) < (2, 34) {
        bail!("git {raw_version} too old; need >= 2.34 for SSH signing");
    }
    let _ssh = Command::new("ssh-keygen").arg("-V").output()?;
    Ok(())
}

fn git_init(repo: &Path) -> Result<()> {
    std::fs::create_dir_all(repo)?;
    let s = Command::new("git")
        .args(["init", "-q", "-b", "main"])
        .current_dir(repo)
        .status()?;
    if !s.success() {
        bail!("git init failed");
    }
    Ok(())
}

/// Write the allowed_signers file mapping each key's email → public key. Required for
/// `git verify-commit` to recognize SSH-signed commits.
fn setup_allowed_signers(repo: &Path, keys: &[&SshKey]) -> Result<()> {
    let allowed_path = repo.join(".git").join("allowed_signers");
    let body = keys
        .iter()
        .map(|k| format!("{} {}", k.email, k.public_openssh))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&allowed_path, body)?;
    // Configure the repo to consult this file for verification.
    let s = Command::new("git")
        .args([
            "config",
            "gpg.ssh.allowedSignersFile",
            allowed_path.to_str().context("non-utf8")?,
        ])
        .current_dir(repo)
        .status()?;
    if !s.success() {
        bail!("git config gpg.ssh.allowedSignersFile failed");
    }
    Ok(())
}

fn git_add_all(repo: &Path) -> Result<()> {
    let s = Command::new("git")
        .args(["add", "-A"])
        .current_dir(repo)
        .status()?;
    if !s.success() {
        bail!("git add failed");
    }
    Ok(())
}

fn git_commit_signed(repo: &Path, signer: &SshKey, msg: &str) -> Result<String> {
    let mut cmd = Command::new("git");
    cmd.current_dir(repo).args([
        "-c",
        &format!("user.name=spike-{}", signer.name),
        "-c",
        &format!("user.email={}", signer.email),
        "-c",
        "gpg.format=ssh",
        "-c",
        &format!("user.signingkey={}", signer.private_path.display()),
        "-c",
        "commit.gpgsign=true",
        "commit",
        "-S",
        "-q",
        "-m",
        msg,
    ]);
    let out = cmd.output()?;
    if !out.status.success() {
        bail!(
            "git commit signed failed: stdout={}, stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let oid = git_rev_parse_head(repo)?;
    Ok(oid)
}

fn git_rev_parse_head(repo: &Path) -> Result<String> {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Returns `true` if `git verify-commit <oid>` succeeds when allowed_signers is /dev/null,
/// `false` if it fails. We expect FALSE in phase 4 — that's the whole point: without the
/// nexum signer-redirect, plain git can't verify SSH-signed commits whose key has been
/// rotated out (or, in the simpler case, when no allowed_signers list is provided at all).
fn git_verify_commit_plain_succeeds(repo: &Path, oid: &str) -> bool {
    let out = Command::new("git")
        .current_dir(repo)
        .args([
            "-c",
            "gpg.ssh.allowedSignersFile=/dev/null",
            "verify-commit",
            oid,
        ])
        .output();
    out.is_ok_and(|o| o.status.success())
}

/// Get the SSH key fingerprint that signed a given commit. Uses `git log --format=%GF`.
fn git_signing_fingerprint(repo: &Path, oid: &str) -> Result<String> {
    let out = Command::new("git")
        .current_dir(repo)
        .args(["log", "-1", "--format=%GF", oid])
        .output()?;
    let fp = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if fp.is_empty() {
        bail!("git log -1 --format=%GF returned empty for {oid}");
    }
    Ok(fp)
}

/// List commits in topological (oldest-first) order, with their signing fingerprint.
fn git_commits_topo(repo: &Path) -> Result<Vec<(String, String)>> {
    let out = Command::new("git")
        .current_dir(repo)
        .args(["log", "--reverse", "--pretty=%H %GF"])
        .output()?;
    let body = String::from_utf8_lossy(&out.stdout);
    let mut rows = Vec::new();
    for line in body.lines() {
        let mut parts = line.splitn(2, ' ');
        let oid = parts.next().unwrap_or("").to_owned();
        let fp = parts.next().unwrap_or("").to_owned();
        if !oid.is_empty() {
            rows.push((oid, fp));
        }
    }
    Ok(rows)
}

/// Commit (oldest-first index) where a given record file was last modified.
fn git_record_last_commit_pos(repo: &Path, record_id: &str) -> Result<usize> {
    let path = format!("decisions/{record_id}.yml");
    let out = Command::new("git")
        .current_dir(repo)
        .args(["log", "--reverse", "--pretty=%H", "--", &path])
        .output()?;
    let body = String::from_utf8_lossy(&out.stdout);
    let last_oid = body
        .lines()
        .last()
        .context("no commits touched record")?
        .to_owned();
    let topo = git_commits_topo(repo)?;
    let pos = topo
        .iter()
        .position(|(oid, _)| oid == &last_oid)
        .context("record commit not in repo log")?;
    Ok(pos)
}

// ============================================================================
// Trust state machine — minimal §9 implementation
// ============================================================================

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum EventKind {
    BootstrapKey,
    KeyAdded,
    KeyRotatedOut,
    BootstrapReanchor,
}

impl EventKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::BootstrapKey => "BootstrapKey",
            Self::KeyAdded => "KeyAdded",
            Self::KeyRotatedOut => "KeyRotatedOut",
            Self::BootstrapReanchor => "BootstrapReanchor",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Event {
    event_id: String,
    #[serde(rename = "type")]
    kind: String,
    /// For BootstrapKey / KeyAdded / KeyRotatedOut: the affected public key (single-line OpenSSH).
    /// For BootstrapReanchor: the NEW root key.
    public_key: String,
    /// Only set for BootstrapReanchor — the previous root being replaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_root: Option<String>,
}

impl Event {
    fn new_bootstrap_key(public_openssh: &str) -> Self {
        Self {
            event_id: uuid::Uuid::now_v7().to_string(),
            kind: "BootstrapKey".to_owned(),
            public_key: public_openssh.to_owned(),
            previous_root: None,
        }
    }
    fn new_key_added(public_openssh: &str) -> Self {
        Self {
            event_id: uuid::Uuid::now_v7().to_string(),
            kind: "KeyAdded".to_owned(),
            public_key: public_openssh.to_owned(),
            previous_root: None,
        }
    }
    fn new_key_rotated_out(public_openssh: &str) -> Self {
        Self {
            event_id: uuid::Uuid::now_v7().to_string(),
            kind: "KeyRotatedOut".to_owned(),
            public_key: public_openssh.to_owned(),
            previous_root: None,
        }
    }
    fn new_bootstrap_reanchor(prev_root: &str, new_root: &str) -> Self {
        Self {
            event_id: uuid::Uuid::now_v7().to_string(),
            kind: "BootstrapReanchor".to_owned(),
            public_key: new_root.to_owned(),
            previous_root: Some(prev_root.to_owned()),
        }
    }
    fn parse_kind(&self) -> Option<EventKind> {
        match self.kind.as_str() {
            "BootstrapKey" => Some(EventKind::BootstrapKey),
            "KeyAdded" => Some(EventKind::KeyAdded),
            "KeyRotatedOut" => Some(EventKind::KeyRotatedOut),
            "BootstrapReanchor" => Some(EventKind::BootstrapReanchor),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EventsFile {
    schema_version: u32,
    events: Vec<Event>,
}

#[derive(Debug, Clone)]
struct MaterializedEvent {
    /// Stable across re-materializations; mutating an event in place changes content but not id.
    #[allow(dead_code)]
    event_id: String,
    kind: EventKind,
    fingerprint: String,
    /// Original OpenSSH text for the event's public key — kept for trust-chain auditing
    /// even though the verifier currently keys off `fingerprint`.
    #[allow(dead_code)]
    public_openssh: String,
    /// Position in topological commit order (oldest = 0) of the commit that introduced
    /// this event into events.yml.
    effective_commit_topo_pos: usize,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum SignatureStatus {
    Verified,
    Invalid,
    #[allow(dead_code)]
    Unsigned,
    #[allow(dead_code)]
    Unknown,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum TrustBasis {
    Current,
    RotatedHistorical,
    PreReanchor,
    #[allow(dead_code)]
    Unknown,
}

#[derive(Debug, Clone)]
struct VerifyResult {
    signature_status: SignatureStatus,
    trust_basis: TrustBasis,
    warnings: Vec<String>,
}

/// Pin file abstraction — equivalent to `[trust.bootstrap]` in `~/.nexum/config.toml`.
struct TrustPin {
    fingerprint: String,
}

impl TrustPin {
    fn pinned_to(fingerprint: &str) -> Self {
        Self {
            fingerprint: fingerprint.to_owned(),
        }
    }
}

/// Compute (historical, allowed, revoked) sets from the event timeline.
fn compute_signer_sets(events: &[Event]) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut historical: Vec<String> = Vec::new();
    let mut revoked: Vec<String> = Vec::new();
    for e in events {
        match e.parse_kind() {
            Some(EventKind::BootstrapKey | EventKind::KeyAdded | EventKind::BootstrapReanchor)
                if !historical.contains(&e.public_key) =>
            {
                historical.push(e.public_key.clone());
            }
            Some(EventKind::KeyRotatedOut) if !revoked.contains(&e.public_key) => {
                revoked.push(e.public_key.clone());
            }
            _ => {}
        }
    }
    let allowed: Vec<String> = historical
        .iter()
        .filter(|h| !revoked.contains(h))
        .cloned()
        .collect();
    (historical, allowed, revoked)
}

fn write_trust_state(repo: &Path, events: &[Event]) -> Result<()> {
    let trust_dir = repo.join("trust");
    std::fs::create_dir_all(&trust_dir)?;
    let events_yaml = serde_yaml::to_string(&EventsFile {
        schema_version: 1,
        events: events.to_vec(),
    })?;
    std::fs::write(trust_dir.join("events.yml"), &events_yaml)?;

    let (historical, allowed, revoked) = compute_signer_sets(events);
    std::fs::write(
        trust_dir.join("historical_keys.yml"),
        serde_yaml::to_string(&historical)?,
    )?;
    std::fs::write(
        trust_dir.join("allowed_keys.yml"),
        serde_yaml::to_string(&allowed)?,
    )?;
    std::fs::write(
        trust_dir.join("revoked_keys.yml"),
        serde_yaml::to_string(&revoked)?,
    )?;

    // META.yml — content hash over the four trust files (deterministic).
    let mut h = Sha256::new();
    h.update(events_yaml.as_bytes());
    h.update(serde_yaml::to_string(&historical)?.as_bytes());
    h.update(serde_yaml::to_string(&allowed)?.as_bytes());
    h.update(serde_yaml::to_string(&revoked)?.as_bytes());
    let digest = format!("{:x}", h.finalize());
    let meta = format!("schema_version: 1\ncontent_hash: {digest}\n");
    std::fs::write(trust_dir.join("META.yml"), meta)?;
    Ok(())
}

fn write_record(repo: &Path, record_id: &str, body: &str) -> Result<()> {
    let dir = repo.join("decisions");
    std::fs::create_dir_all(&dir)?;
    let yaml = format!(
        "schema_version: 1\nid: {record_id}\nrecord_type: decision\ntitle: Spike S6 record\nbody: |\n  {body}\n"
    );
    std::fs::write(dir.join(format!("{record_id}.yml")), yaml)?;
    Ok(())
}

#[derive(Debug, Clone)]
struct TrustState {
    events: Vec<MaterializedEvent>,
    /// event_ids whose stored (kind, public_key) was mutated AFTER first being committed.
    /// The materialized list keeps the FIRST observed value; the tampering record is a
    /// side channel telling the verifier "this key state can no longer be trusted".
    tampered_event_ids: Vec<String>,
    /// Topological position of the earliest commit that introduced any tampering.
    earliest_tamper_pos: Option<usize>,
}

/// Walk git log (oldest first); for each commit that touches trust/events.yml, parse the
/// events.yml as of that commit. New event_ids are added; previously-seen event_ids whose
/// (kind, public_key) has changed are recorded as tampering.
fn materialize_trust_events(repo: &Path) -> Result<TrustState> {
    let topo = git_commits_topo(repo)?;
    let mut materialized: Vec<MaterializedEvent> = Vec::new();
    let mut seen: HashMap<String, (EventKind, String)> = HashMap::new();
    let mut tampered_event_ids: Vec<String> = Vec::new();
    let mut earliest_tamper_pos: Option<usize> = None;

    for (pos, (oid, _fp)) in topo.iter().enumerate() {
        let touched = Command::new("git")
            .current_dir(repo)
            .args(["show", "--name-only", "--pretty=", oid])
            .output()?;
        let touched_str = String::from_utf8_lossy(&touched.stdout);
        if !touched_str.lines().any(|l| l.trim() == "trust/events.yml") {
            continue;
        }

        let blob = Command::new("git")
            .current_dir(repo)
            .args(["show", &format!("{oid}:trust/events.yml")])
            .output()?;
        let yaml = String::from_utf8_lossy(&blob.stdout);
        let parsed: EventsFile =
            serde_yaml::from_str(&yaml).with_context(|| format!("parse events.yml at {oid}"))?;
        for evt in parsed.events {
            let Some(kind) = evt.parse_kind() else {
                continue;
            };
            if let Some((prev_kind, prev_pub)) = seen.get(&evt.event_id) {
                if *prev_kind != kind || prev_pub != &evt.public_key {
                    if !tampered_event_ids.contains(&evt.event_id) {
                        tampered_event_ids.push(evt.event_id.clone());
                    }
                    earliest_tamper_pos = Some(earliest_tamper_pos.map_or(pos, |e| e.min(pos)));
                }
                continue;
            }
            let fp = openssh_pubkey_fingerprint(&evt.public_key, repo)?;
            seen.insert(evt.event_id.clone(), (kind, evt.public_key.clone()));
            materialized.push(MaterializedEvent {
                event_id: evt.event_id,
                kind,
                fingerprint: fp,
                public_openssh: evt.public_key,
                effective_commit_topo_pos: pos,
            });
        }
    }
    Ok(TrustState {
        events: materialized,
        tampered_event_ids,
        earliest_tamper_pos,
    })
}

/// Compute SHA256 fingerprint of a single-line OpenSSH public key by writing it to a temp
/// file and shelling out to `ssh-keygen -l -f`. Production would use ssh-key crate's parser.
fn openssh_pubkey_fingerprint(public_openssh: &str, repo: &Path) -> Result<String> {
    let tmp = repo.join(".git").join("nexum-spike-pubkey.tmp");
    std::fs::write(&tmp, public_openssh)?;
    let fp = ssh_keygen_fingerprint(&tmp)?;
    std::fs::remove_file(&tmp)?;
    Ok(fp)
}

/// Tamper test helper — return a copy of the events list where the FIRST KeyAdded event's
/// public_key has been replaced (event_id preserved).
fn tamper_key_added_event(events: &[Event], replacement: &str) -> Vec<Event> {
    let mut out = events.to_vec();
    for e in &mut out {
        if e.kind == "KeyAdded" {
            replacement.clone_into(&mut e.public_key);
            break;
        }
    }
    out
}

/// Default verifier: pin = bootstrap key in trust_events[0].
fn verify_record(repo: &Path, record_id: &str, state: &TrustState) -> Result<VerifyResult> {
    let bootstrap_fp = state
        .events
        .first()
        .map(|e| e.fingerprint.clone())
        .context("no trust events")?;
    let pin = TrustPin::pinned_to(&bootstrap_fp);
    verify_record_with_pin(repo, record_id, state, &pin)
}

fn verify_record_with_pin(
    repo: &Path,
    record_id: &str,
    state: &TrustState,
    pin: &TrustPin,
) -> Result<VerifyResult> {
    let topo = git_commits_topo(repo)?;
    let record_pos = git_record_last_commit_pos(repo, record_id)?;
    let (oid, _fp) = topo[record_pos].clone();
    let signer_fp = git_signing_fingerprint(repo, &oid)?;

    // Records committed at-or-after the earliest tampering commit can no longer be trusted —
    // the trust chain's history is mutable and any verification result based on it could be
    // a forged answer.
    if let Some(tamper_pos) = state.earliest_tamper_pos
        && record_pos <= tamper_pos
    {
        // Records before the tamper are still suspect because the verifier consults the
        // mutated history when computing trust_basis. Mark invalid.
        return Ok(VerifyResult {
            signature_status: SignatureStatus::Invalid,
            trust_basis: TrustBasis::Unknown,
            warnings: vec!["broken-trust-chain".to_owned(), "event-tampered".to_owned()],
        });
    }

    // Walk back the bootstrap chain to confirm the pin authorizes the current root.
    let bootstrap_chain_root = compute_chain_root_fp(&state.events);
    if bootstrap_chain_root != pin.fingerprint {
        return Ok(VerifyResult {
            signature_status: SignatureStatus::Invalid,
            trust_basis: TrustBasis::Unknown,
            warnings: vec!["broken-trust-chain".to_owned()],
        });
    }

    // Find the trust state at the record's commit position.
    let signer_known_at_record = state
        .events
        .iter()
        .any(|e| e.fingerprint == signer_fp && e.effective_commit_topo_pos <= record_pos);
    if !signer_known_at_record {
        return Ok(VerifyResult {
            signature_status: SignatureStatus::Invalid,
            trust_basis: TrustBasis::Unknown,
            warnings: vec!["unknown-signer".to_owned()],
        });
    }

    // Check rotation status: was the signing key revoked AFTER the record commit?
    let rotated_after = state.events.iter().any(|e| {
        matches!(e.kind, EventKind::KeyRotatedOut)
            && e.fingerprint == signer_fp
            && e.effective_commit_topo_pos > record_pos
    });

    // Check pre-reanchor: is there a BootstrapReanchor AFTER this record?
    let reanchored_after = state.events.iter().any(|e| {
        matches!(e.kind, EventKind::BootstrapReanchor) && e.effective_commit_topo_pos > record_pos
    });

    if reanchored_after {
        return Ok(VerifyResult {
            signature_status: SignatureStatus::Verified,
            trust_basis: TrustBasis::PreReanchor,
            warnings: vec!["pre-recovery-record".to_owned()],
        });
    }
    if rotated_after {
        return Ok(VerifyResult {
            signature_status: SignatureStatus::Verified,
            trust_basis: TrustBasis::RotatedHistorical,
            warnings: vec!["signer-key-rotated".to_owned()],
        });
    }
    Ok(VerifyResult {
        signature_status: SignatureStatus::Verified,
        trust_basis: TrustBasis::Current,
        warnings: vec![],
    })
}

/// Walk forward through trust_events. The chain root starts at the BootstrapKey; each
/// BootstrapReanchor event whose `previous_root` matches the current root advances the
/// root to its `public_key`. The final root is what the pin must match for the chain to
/// be authorized.
fn compute_chain_root_fp(trust_events: &[MaterializedEvent]) -> String {
    if trust_events.is_empty() {
        return String::new();
    }
    let mut root_fp = trust_events[0].fingerprint.clone();
    for e in trust_events.iter().skip(1) {
        if matches!(e.kind, EventKind::BootstrapReanchor) {
            // Reanchor advances root to the new key (regardless of which previous_root claim;
            // production verifier validates the previous_root matches, which is left as an
            // M1 detail).
            root_fp.clone_from(&e.fingerprint);
        }
    }
    root_fp
}

/// Fork helper for phases 6 + 7. Replays the C1..C2 timeline (bootstrap + record + KeyAdded)
/// into a fresh repo so phases 6/7 can verify pre-reanchor records signed by A. Returns the
/// events list so the caller can append the reanchor event WITHOUT regenerating event_ids
/// (which would look like tamper to the materializer).
///
/// `keys`: must contain at least [A, B, D] in that order; A bootstraps, B is added, D is the
/// reanchor signer.
fn fork_from_state_after_c2(_src: &Path, dst: &Path, keys: &[&SshKey]) -> Result<Vec<Event>> {
    let key_a = keys[0];
    let key_b = keys[1];

    git_init(dst)?;
    setup_allowed_signers(dst, keys)?;

    // C1 — bootstrap signed by A.
    let mut events = vec![Event::new_bootstrap_key(&key_a.public_openssh)];
    write_trust_state(dst, &events)?;
    git_add_all(dst)?;
    git_commit_signed(dst, key_a, "bootstrap with key A")?;

    // Cr1 — real record signed by A.
    write_record(dst, "test-rec-A", "Real record signed by A.")?;
    git_add_all(dst)?;
    git_commit_signed(dst, key_a, "add decisions/test-rec-A.yml")?;

    // C2 — KeyAdded(B) signed by A.
    events.push(Event::new_key_added(&key_b.public_openssh));
    write_trust_state(dst, &events)?;
    git_add_all(dst)?;
    git_commit_signed(dst, key_a, "KeyAdded(B) signed by A")?;

    Ok(events)
}

// ============================================================================
// reporting (same shape as S1/S2/S4)
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
    #[allow(dead_code)]
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
        println!("\n=== nexum spike S6 — full trust state machine roundtrip ===\n");
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
            "  Platform: linux x86_64 only this run. Re-run on Windows native (with OpenSSH) to close the §3.6 S6 cross-platform criterion."
        );
    }
}
