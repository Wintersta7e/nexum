//! Stub. Returns `ProviderUnsupported` on every call. Intended placeholder so
//! the trait surface is total when an operator sets `extractor.provider = "ollama"`
//! without first installing a working implementation.

use super::types::{ExtractError, ExtractionOutput, ModelClient};
use crate::extract::digest::SessionDigest;

pub struct OllamaClient;

impl ModelClient for OllamaClient {
    fn provider_name(&self) -> &'static str {
        "ollama"
    }

    fn extract(&self, _digest: &SessionDigest) -> Result<ExtractionOutput, ExtractError> {
        Err(ExtractError::ProviderUnsupported {
            provider: "ollama".into(),
        })
    }

    fn count_input_tokens(&self, _digest: &SessionDigest) -> Result<u32, ExtractError> {
        Err(ExtractError::ProviderUnsupported {
            provider: "ollama".into(),
        })
    }
}
