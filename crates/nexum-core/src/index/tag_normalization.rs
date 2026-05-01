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

    #[test]
    fn hyphen_in_tag_value_becomes_underscore() {
        // The §7 / S1 NOTE specific case: `perf-database` would otherwise be
        // parsed by FTS5 as `perf NOT database`.
        assert_eq!(
            normalize_tags_for_fts(r#"["perf-database"]"#),
            "perf_database"
        );
    }

    #[test]
    fn dot_in_tag_value_becomes_underscore() {
        // FTS5 column-qualified MATCH uses `:` as the column delimiter; dots
        // also have special meaning in some FTS5 contexts. Normalize defensively.
        assert_eq!(
            normalize_tags_for_fts(r#"["semver.major"]"#),
            "semver_major"
        );
    }

    #[test]
    fn embedded_quote_becomes_space() {
        // Raw-string-literal tag containing an internal single-quote.
        assert_eq!(normalize_tags_for_fts(r#"["it's-fine"]"#), "it s_fine");
    }

    #[test]
    fn malformed_json_is_not_an_error() {
        // We never parse the JSON; we only translate punctuation. Malformed
        // input still produces a sane (if probably-unsearchable) string.
        assert_eq!(normalize_tags_for_fts(r#"["unclosed"#), "unclosed");
    }

    #[test]
    fn already_normalized_input_is_idempotent_modulo_lowercasing() {
        // The function is permissive — given already-normalized input it
        // produces the same output (modulo lowercase).
        assert_eq!(
            normalize_tags_for_fts("Already Normalized"),
            "already normalized"
        );
    }

    #[test]
    fn collapses_consecutive_whitespace_runs() {
        assert_eq!(
            normalize_tags_for_fts(r#"["a"  ,  "b"   ,   "c"]"#),
            "a b c"
        );
    }

    #[test]
    fn unicode_letters_pass_through() {
        // Non-ASCII letters are kept (FTS5 unicode61 tokenizer handles them);
        // only the explicit punctuation rules apply.
        assert_eq!(normalize_tags_for_fts(r#"["café","naïve"]"#), "café naïve");
    }

    #[test]
    fn non_array_json_object_treated_as_text() {
        // {"k":"v"} → strip quotes; the function does NOT translate { or }
        // (only [ and ]). Documented behavior: braces survive verbatim.
        let out = normalize_tags_for_fts(r#"{"k":"v"}"#);
        assert!(!out.contains('"'), "quotes must be stripped, got: {out:?}");
        assert!(
            out.contains('{'),
            "function does not translate braces; '{{' / '}}' survive — got: {out:?}"
        );
    }
}
