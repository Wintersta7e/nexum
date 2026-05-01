//! Normalize raw tag JSON (from `records.tags` column) into a space-separated
//! form suitable for FTS5 indexing in `records.tags_fts`.
//!
//! The §7 "FTS5 tag tokenization quirk" rule (from spike S1's NOTE): FTS5's
//! expression parser treats `-` as a NOT operator, so a tag value like
//! `perf-database` collides with the grammar when matched. Storing tags as raw
//! JSON in an FTS5 column is brittle; the indexer normalizes at write time and
//! FTS5 indexes the normalized column instead.
//!
//! Normalization rules:
//!   - JSON brackets (`[`, `]`) become spaces.
//!   - JSON quotes (`"`, `'`) become spaces.
//!   - JSON commas become spaces.
//!   - Internal hyphens (`-`) and dots (`.`) become underscores (so they
//!     don't collide with FTS5's NOT / phrase / column operators).
//!   - Whitespace runs collapse to a single space.
//!   - Output is lowercase ASCII.
//!   - Leading / trailing whitespace stripped.
//!
//! This is intentionally permissive on input shape — it works on raw JSON arrays
//! AND on already-stripped space-separated text, so the indexer can use the
//! same fn whether tags arrive as `["a","b"]` or `a b`. Malformed JSON is not an
//! error: we never *parse* the JSON; we just translate punctuation.

#[must_use]
pub fn normalize_tags_for_fts(tags_json: &str) -> String {
    let mut out = String::with_capacity(tags_json.len());
    let mut last_was_space = true; // suppress leading spaces
    for ch in tags_json.chars() {
        let mapped: char = match ch {
            '[' | ']' | ',' | '"' | '\'' => ' ',
            '-' | '.' => '_',
            c if c.is_whitespace() => ' ',
            c => c.to_ascii_lowercase(),
        };
        if mapped == ' ' && !last_was_space {
            out.push(' ');
            last_was_space = true;
        } else if mapped != ' ' {
            out.push(mapped);
            last_was_space = false;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_two_tags_no_punctuation() {
        assert_eq!(
            normalize_tags_for_fts(r#"["concurrency","database"]"#),
            "concurrency database"
        );
    }

    #[test]
    fn single_tag_no_punctuation() {
        assert_eq!(normalize_tags_for_fts(r#"["alpha"]"#), "alpha");
    }

    #[test]
    fn empty_array_yields_empty_string() {
        assert_eq!(normalize_tags_for_fts("[]"), "");
    }

    #[test]
    fn three_tags_alphanumeric() {
        assert_eq!(
            normalize_tags_for_fts(r#"["one","two","three"]"#),
            "one two three"
        );
    }
}
