//! Targeted tests asserting every config.toml seed field is populated correctly.

mod common;

use common::write_ephemeral_keypair;
use nexum_core::{
    config::types::Config,
    init::{InitOpts, run},
    records::TrustPolicy,
};

fn init_and_load_config() -> (Config, nexum_core::init::InitOutcome) {
    let home = common::NexumTestHome::new().unwrap();
    let key_dir = tempfile::tempdir().unwrap();
    let priv_path = write_ephemeral_keypair(key_dir.path());
    let outcome = run(InitOpts {
        ssh_key: Some(priv_path),
        root: Some(home.path().join(".nexum")),
        force: false,
    })
    .expect("init must succeed");
    let config_path = outcome.root.join("config.toml");
    let raw = std::fs::read_to_string(&config_path).unwrap();
    let cfg: Config = toml::from_str(&raw).unwrap();
    (cfg, outcome)
}

#[test]
fn config_schema_version_is_one() {
    let (cfg, _) = init_and_load_config();
    assert_eq!(cfg.schema_version, 1);
}

#[test]
fn config_paths_section_populated() {
    let (cfg, outcome) = init_and_load_config();
    // Paths use `~/.nexum` shorthand (not resolved) per the seed-config shape.
    assert_eq!(cfg.paths.root, "~/.nexum");
    assert_eq!(cfg.paths.notebook_git, "~/.nexum/notebook.git");
    assert_eq!(cfg.paths.index_db, "~/.nexum/index.db");
    assert_eq!(cfg.paths.models, "~/.nexum/models");
    // Root in outcome is absolute; config uses tilde paths — both acceptable.
    assert!(!outcome.root.as_os_str().is_empty());
}

#[test]
fn config_trust_bootstrap_fingerprint_matches_outcome() {
    let (cfg, outcome) = init_and_load_config();
    assert_eq!(cfg.trust.bootstrap.fingerprint, outcome.fingerprint);
    assert!(cfg.trust.bootstrap.fingerprint.starts_with("SHA256:"));
}

#[test]
fn config_trust_bootstrap_key_type_is_ed25519() {
    let (cfg, _) = init_and_load_config();
    assert_eq!(cfg.trust.bootstrap.key_type, "ssh-ed25519");
}

#[test]
fn config_trust_bootstrap_public_key_is_present() {
    let (cfg, _) = init_and_load_config();
    assert!(!cfg.trust.bootstrap.public_key.is_empty());
    assert!(cfg.trust.bootstrap.public_key.starts_with("ssh-ed25519 "));
}

#[test]
fn config_trust_bootstrap_established_at_is_present() {
    let (cfg, _) = init_and_load_config();
    assert!(!cfg.trust.bootstrap.established_at.is_empty());
}

#[test]
fn config_embed_disabled_by_default() {
    let (cfg, _) = init_and_load_config();
    assert!(!cfg.embed.enabled);
    assert_eq!(cfg.embed.model, "bge-m3");
    assert!(cfg.embed.model_path.is_empty());
}

#[test]
fn config_adapters_enabled_by_default() {
    let (cfg, _) = init_and_load_config();
    assert!(cfg.adapters.cc.enabled);
    assert!(cfg.adapters.codex.enabled);
    assert!(cfg.adapters.local.enabled);
}

#[test]
fn config_trust_defaults() {
    let (cfg, _) = init_and_load_config();
    assert_eq!(cfg.trust.unsigned_default, TrustPolicy::WarnButShow);
    assert!((cfg.trust.ranking_penalty - 0.7).abs() < f64::EPSILON);
    assert!(!cfg.trust.strict_revocation);
}

#[test]
fn config_promote_disabled_by_default() {
    let (cfg, _) = init_and_load_config();
    assert!(!cfg.promote.enabled);
    assert!(!cfg.promote.auto_promote);
}
