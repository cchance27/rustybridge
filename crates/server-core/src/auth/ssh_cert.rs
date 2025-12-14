use crate::error::ServerResult;
use ssh_key::{Certificate, PublicKey};

// TODO: Implement proper SSH certificate validation
// The ssh-key crate API may have changed or we need to use a different approach
// For now, this is a placeholder that will reject all certificates

pub fn validate_certificate(_cert_key: &PublicKey, _ca_key: &PublicKey) -> ServerResult<Certificate> {
    Err(crate::error::ServerError::Internal(
        "SSH certificate validation not yet implemented".to_string(),
    ))
}

pub fn extract_principals(_cert: &Certificate) -> Vec<String> {
    // TODO: Extract principals from certificate
    vec![]
}
