//! Session-digest construction. A `SessionDigest` is the 10-30 KB structured
//! view a `ModelClient` sees: user prompts, assistant prose, a compressed
//! tool-call summary, the final plan state, and git metadata.
