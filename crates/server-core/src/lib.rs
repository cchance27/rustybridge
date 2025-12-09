//! Embedded SSH server entry point and module wiring.
//!
//! This module intentionally keeps the public surface small: `run_server` wires up the russh
//! configuration, while the heavy lifting lives in the submodules.

pub mod macros;

pub mod api;
pub mod audit;
pub mod auth;
pub mod error;
mod handler;
pub mod relay;
pub use relay::connect_to_relay_local;
pub mod secrets;
mod server_manager;

// Re-export functionality from new modules
pub mod credential;
pub mod group;
pub mod relay_host;
pub mod role;
pub mod session_recorder;
pub mod sessions;

pub mod ssh_server;
pub mod startup_cleanup;
pub mod tui;
pub mod user;

// Top level exports for backwards compatability we should likely update callsights in future.
pub use api::{
    SessionChunk, SessionQuery, SessionQueryResult, SessionSummary, add_claim_to_role, add_user_public_key_by_id, assign_role_to_group_by_ids, assign_role_to_user, audit_db_handle, create_role, delete_role, delete_user_public_key_by_id, display_server_db_path, fetch_relay_by_id, fetch_relay_by_name, get_credential_meta, get_group_claims_by_id, get_group_id_by_name, get_relay_credential_by_id, get_relay_credential_by_name, get_role_id_by_name, get_user_claims_by_id, get_user_id_by_name, list_group_members_by_id, list_groups_overview, list_relay_hosts_with_details, list_role_groups_by_id, list_role_users_by_id, list_roles, list_roles_with_details, list_user_public_keys_by_id, list_usernames, list_users_overview, migrate_server_db, query_audit_events, query_recent_audit_events, query_sessions, record_connection_disconnection, record_ssh_connection, record_web_connection, record_web_connection_with_context, remove_claim_from_role, revoke_role_from_group_by_ids, revoke_role_from_user, server_db_handle, update_relay_host_by_id, user_has_relay_access
};
pub use credential::*;
pub use group::*;
pub use relay_host::{access::*, management::*, options::*};
pub use role::*;
pub use ssh_server::*;
pub use tui::*;
pub use user::*;
