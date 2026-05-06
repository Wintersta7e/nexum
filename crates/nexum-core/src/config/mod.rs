//! TOML configuration types and I/O for `~/.nexum/config.toml`.
//!
//! `Config` is the top-level serde type. `write_seed` writes the initial file
//! on `nexum init`; `load` reads it back. Field names and defaults match the
//! seed shape produced by `Config::seed()`.

pub mod io;
pub mod types;

pub use io::{ConfigError, load, write_seed};
pub use types::Config;
