pub mod session_dock;
pub mod session_window;
pub mod global_chrome;

// connection_drawer was planned but we reused RelayDrawer directly in global_chrome
// so we don't strictly need it unless we want to alias it.
// keeping it clean.
