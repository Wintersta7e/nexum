//! Versioned extraction prompts. Each prompt is checked into source so
//! reproducibility survives prompt revisions.

mod types;

pub use types::{Prompt, PromptVersion, current_prompt};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_prompt_is_version_one() {
        let prompt = current_prompt();
        assert_eq!(prompt.version, PromptVersion::V1);
    }

    #[test]
    fn current_prompt_body_is_non_empty() {
        let prompt = current_prompt();
        assert!(!prompt.body.is_empty());
        // The contract clauses are mandatory in every emitted prompt.
        assert!(prompt.body.contains("Refuse to fabricate"));
        assert!(prompt.body.contains("NO RECORDS"));
        assert!(prompt.body.contains("schema_version: 1"));
    }

    #[test]
    fn prompt_version_serializes_kebab_case() {
        let serialized = serde_json::to_string(&PromptVersion::V1).unwrap();
        assert_eq!(serialized, "\"v1\"");
    }
}
