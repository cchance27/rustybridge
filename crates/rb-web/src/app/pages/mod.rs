pub mod access;
pub mod admin;
pub mod credentials;

pub mod dashboard;
pub mod login;
pub mod logout;
pub mod not_found;
pub mod oidc_error;
pub mod profile;
pub mod relays;
pub mod ssh_success;
pub mod system;

pub use access::AccessPage;
pub use admin::{AuditEvents, SessionHistory};
pub use credentials::CredentialsPage;
pub use dashboard::DashboardPage;
pub use login::LoginPage;
pub use logout::LogoutPage;
pub use not_found::NotFoundPage;
pub use oidc_error::OidcErrorPage;
pub use profile::ProfilePage;
pub use relays::RelaysPage;
pub use ssh_success::SshSuccessPage;
pub use system::{SystemStatusPage, SystemSettings as SystemSettingsPage, SystemTasks as SystemTasksPage};
