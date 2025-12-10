//! Test utilities for server-core tests.
//!
//! This module provides helper functions to ensure consistent test setup,
//! particularly for database isolation.

/// Set up test environment with in-memory databases for both server and audit.
///
/// This function sets both `RB_SERVER_DB_URL` and `RB_AUDIT_DB_URL` environment
/// variables to use in-memory SQLite databases with unique names based on the
/// provided test identifier.
///
/// # Safety
/// This function uses `std::env::set_var` which is unsafe in multi-threaded
/// contexts. Tests using this should be marked with `#[serial]`.
///
/// # Example
/// ```ignore
/// set_test_db_env("my_test");
/// // Now RB_SERVER_DB_URL = "sqlite:file:my_test?mode=memory&cache=shared"
/// // And RB_AUDIT_DB_URL = "sqlite:file:my_test_audit?mode=memory&cache=shared"
/// ```
pub fn set_test_db_env(test_name: &str) {
    unsafe {
        std::env::set_var("RB_SERVER_DB_URL", format!("sqlite:file:{}?mode=memory&cache=shared", test_name));
        std::env::set_var(
            "RB_AUDIT_DB_URL",
            format!("sqlite:file:{}_audit?mode=memory&cache=shared", test_name),
        );
    }
}
