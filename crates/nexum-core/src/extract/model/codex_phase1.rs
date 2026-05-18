//! `CodexPhase1Reader` — reads pre-extracted YAML rows out of Codex's own
//! `state_5.sqlite.stage1_outputs` table when present.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

use super::types::{ExtractError, ExtractionOutput, RawRecord};

pub struct CodexPhase1Reader {
    state_db: PathBuf,
}

impl CodexPhase1Reader {
    #[must_use]
    pub fn new(state_db: impl Into<PathBuf>) -> Self {
        Self {
            state_db: state_db.into(),
        }
    }

    /// Look up pre-extracted records for a Codex thread id. Returns
    /// `NoRecords` when either the table is missing or the thread has no rows.
    ///
    /// # Errors
    /// `ExtractError::Io` wrapping `rusqlite`'s error if opening or querying
    /// the database fails for a reason other than a missing table.
    /// `ExtractError::MalformedResponse` if a row's YAML payload fails to parse.
    pub fn extract_for_thread(&self, thread_id: &str) -> Result<ExtractionOutput, ExtractError> {
        if !Path::new(&self.state_db).exists() {
            return Ok(ExtractionOutput::NoRecords {
                reason: format!("state_5.sqlite absent at {}", self.state_db.display()),
            });
        }
        let conn = Connection::open(&self.state_db).map_err(|e| map_sqlite_err(&e))?;
        // Verify the table exists before SELECTing — missing table is a clean NoRecords.
        let table_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='stage1_outputs'",
                [],
                |row| row.get::<_, i64>(0).map(|c| c > 0),
            )
            .map_err(|e| map_sqlite_err(&e))?;
        if !table_exists {
            return Ok(ExtractionOutput::NoRecords {
                reason: "stage1_outputs table absent".into(),
            });
        }
        let mut stmt = conn
            .prepare("SELECT yaml FROM stage1_outputs WHERE thread_id = ?1 ORDER BY record_index")
            .map_err(|e| map_sqlite_err(&e))?;
        let rows = stmt
            .query_map([thread_id], |row| row.get::<_, String>(0))
            .map_err(|e| map_sqlite_err(&e))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| map_sqlite_err(&e))?;
        if rows.is_empty() {
            return Ok(ExtractionOutput::NoRecords {
                reason: format!("no stage1_outputs rows for thread `{thread_id}`"),
            });
        }
        let records: Vec<RawRecord> = rows
            .into_iter()
            .map(|yaml_text| {
                let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml_text).map_err(|e| {
                    ExtractError::MalformedResponse {
                        reason: format!("stage1_outputs YAML: {e}"),
                    }
                })?;
                Ok(RawRecord { yaml: parsed })
            })
            .collect::<Result<_, ExtractError>>()?;
        Ok(ExtractionOutput::Records(records))
    }
}

fn map_sqlite_err(e: &rusqlite::Error) -> ExtractError {
    ExtractError::Io(std::io::Error::other(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use rusqlite::Connection;
    use tempfile::TempDir;

    fn populated_db(dir: &TempDir) -> std::path::PathBuf {
        let path = dir.path().join("state_5.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "
            CREATE TABLE stage1_outputs (
                thread_id TEXT NOT NULL,
                record_index INTEGER NOT NULL,
                yaml TEXT NOT NULL,
                PRIMARY KEY (thread_id, record_index)
            );
            INSERT INTO stage1_outputs(thread_id, record_index, yaml) VALUES
                ('t1', 0, 'id: 2026-04-15-x\nrecord_type: recommendation'),
                ('t1', 1, 'id: 2026-04-15-y\nrecord_type: failure');
            ",
        )
        .unwrap();
        path
    }

    #[test]
    fn reads_pre_extracted_rows_for_thread() {
        let dir = TempDir::new().unwrap();
        let db = populated_db(&dir);
        let reader = CodexPhase1Reader::new(db);
        let out = reader.extract_for_thread("t1").expect("extract");
        match out {
            crate::extract::model::ExtractionOutput::Records(rs) => {
                assert_eq!(rs.len(), 2);
            }
            crate::extract::model::ExtractionOutput::NoRecords { reason } => {
                panic!("expected Records, got NoRecords: {reason}")
            }
        }
    }

    #[test]
    fn missing_table_returns_no_records() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("state_5.sqlite");
        Connection::open(&path)
            .unwrap()
            .execute("CREATE TABLE other(x INTEGER)", [])
            .unwrap();
        let reader = CodexPhase1Reader::new(path);
        let out = reader.extract_for_thread("any").expect("extract");
        assert!(matches!(
            out,
            crate::extract::model::ExtractionOutput::NoRecords { .. }
        ));
    }

    #[test]
    fn no_rows_for_thread_returns_no_records() {
        let dir = TempDir::new().unwrap();
        let db = populated_db(&dir);
        let reader = CodexPhase1Reader::new(db);
        let out = reader.extract_for_thread("not-a-thread").expect("extract");
        assert!(matches!(
            out,
            crate::extract::model::ExtractionOutput::NoRecords { .. }
        ));
    }
}
