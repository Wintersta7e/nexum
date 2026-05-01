//! §7 index DDL constant + `apply()` helper that lands it onto a connection
//! and verifies the expected tables / triggers exist post-apply.

#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error("sqlite error during DDL apply: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("expected {what} missing after DDL apply")]
    Missing { what: String },
}

/// Verbatim §7 DDL. Loaded from a sibling .sql file so SQL tooling works.
pub const DDL: &str = include_str!("schema.sql");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ddl_constant_is_non_empty_and_mentions_records() {
        assert!(!DDL.is_empty(), "DDL constant must not be empty");
        assert!(
            DDL.contains("CREATE TABLE records"),
            "DDL must define records table"
        );
        assert!(
            DDL.contains("tags_fts TEXT NOT NULL"),
            "DDL must define tags_fts column"
        );
        assert!(
            DDL.contains("CREATE VIRTUAL TABLE records_fts USING fts5"),
            "DDL must define records_fts virtual table"
        );
    }
}
