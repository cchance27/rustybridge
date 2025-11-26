use serde::{Deserialize, Serialize};

/// SSH authentication session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshAuthSession {
    /// Cryptographically secure 32-character session code
    pub code: String,
    /// Full authentication URL for user to visit
    pub auth_url: String,
    /// Unix timestamp when session expires
    pub expires_at: i64,
}

/// Status of an SSH authentication session
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SshAuthStatus {
    /// Session is waiting for authentication
    Pending,
    /// Session has been authenticated (contains user_id)
    Authenticated(i64),
    /// Session was rejected
    Rejected,
    /// Session was abandoned by user
    Abandoned,
    /// Session has expired
    Expired,
    /// Session has already been used (one-time use enforcement)
    Used,
}

impl SshAuthStatus {
    /// Parse status from database string
    pub fn from_db_string(status: &str, user_id: Option<i64>) -> Self {
        match status {
            "pending" => SshAuthStatus::Pending,
            "authenticated" if user_id.is_some() => SshAuthStatus::Authenticated(user_id.unwrap()),
            "rejected" => SshAuthStatus::Rejected,
            "abandoned" => SshAuthStatus::Abandoned,
            "expired" => SshAuthStatus::Expired,
            "used" => SshAuthStatus::Used,
            _ => SshAuthStatus::Rejected, // Default to rejected for unknown states
        }
    }

    /// Convert status to database string
    pub fn to_db_string(&self) -> &'static str {
        match self {
            SshAuthStatus::Pending => "pending",
            SshAuthStatus::Authenticated(_) => "authenticated",
            SshAuthStatus::Rejected => "rejected",
            SshAuthStatus::Abandoned => "abandoned",
            SshAuthStatus::Expired => "expired",
            SshAuthStatus::Used => "used",
        }
    }
}

/// User SSH public key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPublicKey {
    pub id: i64,
    pub user_id: i64,
    pub public_key: String,
    pub comment: Option<String>,
    pub created_at: i64,
}
