//! Integration tests for the §7 index DDL applied to a real `SQLite` connection.
//! Uses `NexumTestHome` to create an isolated temp dir for the database file,
//! and the sqlite-vec extension is loaded via `auto_extension` before the connection
//! opens (vec0 is required by the DDL).

mod common;

use common::NexumTestHome;
use nexum_core::index::schema;
use rusqlite::Connection;
use std::os::raw::{c_char, c_int};

fn register_sqlite_vec() {
    type RusqliteExtInit = unsafe extern "C" fn(
        *mut rusqlite::ffi::sqlite3,
        *mut *mut c_char,
        *const rusqlite::ffi::sqlite3_api_routines,
    ) -> c_int;
    // SAFETY: sqlite3_auto_extension registers an init function that SQLite invokes
    // when each new connection is opened. sqlite_vec::sqlite3_vec_init is the standard
    // sqlite-vec entry point and is ABI-compatible with the SQLite-extension init
    // signature — but its rustc-visible type uses sqlite-vec's bindgen-generated
    // `sqlite3` opaque alias rather than rusqlite's, so the transmute bridges the two
    // ABI-equivalent function-pointer types. This is the pattern documented by
    // sqlite-vec for static linking with rusqlite (same pattern used in spike S1).
    unsafe {
        let init_fn: RusqliteExtInit =
            std::mem::transmute(sqlite_vec::sqlite3_vec_init as *const ());
        rusqlite::ffi::sqlite3_auto_extension(Some(init_fn));
    }
}

#[test]
fn apply_succeeds_on_fresh_connection() {
    register_sqlite_vec();
    let home = NexumTestHome::new().expect("create test home");
    let conn = Connection::open(home.paths().index_db).expect("open temp db");
    schema::apply(&conn).expect("apply DDL");
}
