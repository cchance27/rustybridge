pub mod access;
pub mod credentials;
pub mod dashboard;
pub mod login;
pub mod logout;
pub mod not_found;
pub mod oidc_error;
pub mod relays;

pub use access::AccessPage;
pub use credentials::CredentialsPage;
pub use dashboard::DashboardPage;
pub use login::LoginPage;
pub use logout::LogoutPage;
pub use not_found::NotFoundPage;
pub use oidc_error::OidcErrorPage;
pub use relays::RelaysPage;
