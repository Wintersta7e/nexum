//! TOML configuration types and I/O for `~/.nexum/config.toml`.
//!
//! `Config` is the top-level serde type. `write_seed` writes the initial file
//! on `nexum init`; `load` reads it back. The §8 "Initial config.toml" block
//! is the canonical source for field names and defaults.

pub mod io;
pub mod types;

pub use types::Config;
// re-exports unblocked in Task 3 once io.rs lands
// pub use io::{load, write_seed, ConfigError};
