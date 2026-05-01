//! Path + git-URL canonicalization per §13. Implementation lands in Task 8 / 9.

#[derive(Debug, thiserror::Error)]
pub enum CanonError {
    #[error("symlink chain depth exceeded ({0} hops)")]
    SymlinkDepth(usize),
    #[error("io error during canonicalization: {0}")]
    Io(#[from] std::io::Error),
}
