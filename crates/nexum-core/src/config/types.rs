//! Serde types for `~/.nexum/config.toml`.
//!
//! Mirrors the §8 "Initial config.toml" block verbatim — field names and section
//! names are canonical. Changes to this file should be accompanied by a spec patch.

use serde::{Deserialize, Serialize};

use crate::records::TrustPolicy;

/// Top-level configuration for a nexum installation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub schema_version: u32,
    pub paths: PathsConfig,
    pub trust: TrustConfig,
    pub runtime: RuntimeConfig,
    pub adapters: AdaptersConfig,
    pub embed: EmbedConfig,
    pub extractor: ExtractorConfig,
    pub promote: PromoteConfig,
    /// Populated by `nexum project register`; empty at init.
    #[serde(default)]
    pub projects: toml::Table,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathsConfig {
    pub root: String,
    pub notebook_git: String,
    pub index_db: String,
    pub models: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustConfig {
    pub unsigned_default: TrustPolicy,
    pub ranking_penalty: f64,
    pub strict_revocation: bool,
    pub bootstrap: BootstrapConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct BootstrapConfig {
    /// SSH key fingerprint, e.g. `"SHA256:abc123..."`. Populated by init.
    pub fingerprint: String,
    /// e.g. `"ssh-ed25519"`.
    pub key_type: String,
    /// Full public key blob for offline verification.
    pub public_key: String,
    pub established_at: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub worker_threads: u32,
    pub max_blocking_threads: u32,
    pub embed_threads: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdaptersConfig {
    pub cc: AdapterCcConfig,
    pub codex: AdapterCodexConfig,
    pub local: AdapterLocalConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdapterCcConfig {
    pub enabled: bool,
    pub projects_dir: String,
    pub max_age_years: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdapterCodexConfig {
    pub enabled: bool,
    pub memories_dir: String,
    pub state_db: String,
    pub read_raw_memories: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdapterLocalConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmbedConfig {
    pub enabled: bool,
    pub model: String,
    pub model_path: String,
    pub model_base_url: String,
    pub hybrid_alpha: f64,
    pub top_k_semantic: u32,
    pub top_k_fts: u32,
    pub query_cache_size: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtractorConfig {
    pub provider: String,
    pub model: String,
    pub max_digest_tokens: u32,
    pub anthropic: ExtractorAnthropicConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtractorAnthropicConfig {
    pub api_key_env: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PromoteConfig {
    pub enabled: bool,
    pub auto_promote: bool,
    pub correlation_window_days: u32,
    pub file_overlap_threshold: f64,
    pub require_message_reference: bool,
}

impl Config {
    /// Produce the §8 seed shape with empty bootstrap fields.
    /// Caller fills `trust.bootstrap` after key detection.
    #[must_use]
    pub fn seed() -> Self {
        Self {
            schema_version: 1,
            paths: PathsConfig {
                root: "~/.nexum".into(),
                notebook_git: "~/.nexum/notebook.git".into(),
                index_db: "~/.nexum/index.db".into(),
                models: "~/.nexum/models".into(),
            },
            trust: TrustConfig {
                unsigned_default: TrustPolicy::WarnButShow,
                ranking_penalty: 0.7,
                strict_revocation: false,
                bootstrap: BootstrapConfig {
                    fingerprint: String::new(),
                    key_type: String::new(),
                    public_key: String::new(),
                    established_at: String::new(),
                    note: "Bootstrap key — do not delete or rotate without `nexum keys recover --reanchor`".into(),
                },
            },
            runtime: RuntimeConfig {
                worker_threads: 0,
                max_blocking_threads: 0,
                embed_threads: 0,
            },
            adapters: AdaptersConfig {
                cc: AdapterCcConfig {
                    enabled: true,
                    projects_dir: "~/.claude/projects".into(),
                    max_age_years: 2,
                },
                codex: AdapterCodexConfig {
                    enabled: true,
                    memories_dir: "~/.codex/memories".into(),
                    state_db: "~/.codex/state_5.sqlite".into(),
                    read_raw_memories: false,
                },
                local: AdapterLocalConfig { enabled: true },
            },
            embed: EmbedConfig {
                enabled: false,
                model: "bge-m3".into(),
                model_path: String::new(),
                model_base_url: "https://huggingface.co/BAAI/bge-m3/resolve/main/onnx/".into(),
                hybrid_alpha: 0.6,
                top_k_semantic: 100,
                top_k_fts: 100,
                query_cache_size: 100,
            },
            extractor: ExtractorConfig {
                provider: "anthropic".into(),
                model: "claude-opus-4-7".into(),
                max_digest_tokens: 32000,
                anthropic: ExtractorAnthropicConfig {
                    api_key_env: "ANTHROPIC_API_KEY".into(),
                },
            },
            promote: PromoteConfig {
                enabled: false,
                auto_promote: false,
                correlation_window_days: 30,
                file_overlap_threshold: 0.7,
                require_message_reference: false,
            },
            projects: toml::Table::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_round_trips_toml() {
        let cfg = Config::seed();
        let serialized = toml::to_string_pretty(&cfg).expect("serialize");
        let back: Config = toml::from_str(&serialized).expect("deserialize");
        assert_eq!(cfg, back);
    }

    #[test]
    fn seed_schema_version_is_one() {
        assert_eq!(Config::seed().schema_version, 1);
    }

    #[test]
    fn seed_embed_disabled_by_default() {
        assert!(!Config::seed().embed.enabled);
    }

    #[test]
    fn seed_trust_bootstrap_fingerprint_empty() {
        assert!(Config::seed().trust.bootstrap.fingerprint.is_empty());
    }
}
