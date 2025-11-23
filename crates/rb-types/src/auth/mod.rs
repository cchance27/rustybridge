mod claims;

pub use claims::{ClaimLevel, ClaimType};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LoginResponse {
    pub success: bool,
    pub message: String,
    pub user: Option<AuthUserInfo>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthUserInfo {
    pub id: i64,
    pub username: String,
    pub claims: Vec<ClaimType>,
    pub has_management_access: bool,
}
