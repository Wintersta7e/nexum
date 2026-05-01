//! CC cwd-slug decoding per §5 / patch4. Implementation lands in Task 10.

#[derive(Debug, thiserror::Error)]
pub enum SlugError {
    #[error("slug too long to enumerate decodings: {hyphen_count} internal hyphens")]
    TooManyHyphens { hyphen_count: usize },
}
