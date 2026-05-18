//! Prompt + version registry.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PromptVersion {
    V1,
}

#[derive(Debug, Clone)]
pub struct Prompt {
    pub version: PromptVersion,
    pub body: &'static str,
}

const PROMPT_V1: &str = include_str!("extraction_v1.md");

/// The currently-default prompt. New versions are added as new constants
/// and the `current_prompt` body's version selector grows a match arm.
#[must_use]
pub fn current_prompt() -> Prompt {
    Prompt {
        version: PromptVersion::V1,
        body: PROMPT_V1,
    }
}

/// Look up an arbitrary version. Used by reproducibility / replay paths.
// Forward-compat: reachable once replay / reproducibility paths land later
// in the extract pipeline; keeping it total now avoids a churning enum site.
#[allow(dead_code)]
#[must_use]
pub fn prompt_for(version: PromptVersion) -> Prompt {
    match version {
        PromptVersion::V1 => Prompt {
            version: PromptVersion::V1,
            body: PROMPT_V1,
        },
    }
}
