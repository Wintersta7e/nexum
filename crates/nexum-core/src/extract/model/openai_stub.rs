//! Stub. Returns `ProviderUnsupported` on every call. Intended placeholder so
//! the trait surface is total when an operator sets `extractor.provider = "openai"`
//! without first installing a working implementation.

use super::types::{ExtractError, ExtractionOutput, ModelClient};
use crate::extract::digest::SessionDigest;

pub struct OpenAiClient;

impl ModelClient for OpenAiClient {
    fn provider_name(&self) -> &'static str {
        "openai"
    }

    fn extract(&self, _digest: &SessionDigest) -> Result<ExtractionOutput, ExtractError> {
        Err(ExtractError::ProviderUnsupported {
            provider: "openai".into(),
        })
    }

    fn count_input_tokens(&self, _digest: &SessionDigest) -> Result<u32, ExtractError> {
        Err(ExtractError::ProviderUnsupported {
            provider: "openai".into(),
        })
    }
}
