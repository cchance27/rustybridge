use std::{
    fs, path::{Path, PathBuf}
};

use argon2::{
    Algorithm, Argon2, Params, Version, password_hash::{PasswordHasher, SaltString}
};
use base64::Engine;
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce, aead::{Aead, KeyInit, OsRng}
};
use hkdf::Hkdf;
use once_cell::sync::Lazy;
use rand::{Rng, RngCore};
use secrecy::ExposeSecret;
use sha2::Sha256;

use crate::error::{ServerError, ServerResult};

pub type SecretString = secrecy::SecretBox<String>;
pub type SecretVec<T> = secrecy::SecretBox<Vec<T>>;

const MASTER_KEY_ENV: &str = "RB_SERVER_SECRETS_KEY"; // base64 32 bytes
const MASTER_PASSPHRASE_ENV: &str = "RB_SERVER_SECRETS_PASSPHRASE"; // string
const SALT_FILE_ENV: &str = "RB_SERVER_SECRETS_SALT_FILE";

const ENC_PREFIX_V1: &str = "enc:v1:";
const ENC_PREFIX_V2: &str = "enc:v2:";

static MASTER_KEY: Lazy<ServerResult<SecretVec<u8>>> = Lazy::new(load_master_key);

pub struct EncryptedBlob {
    pub salt: Vec<u8>,       // KDF salt (16 bytes)
    pub nonce: Vec<u8>,      // XChaCha20-Poly1305 nonce (24 bytes)
    pub ciphertext: Vec<u8>, // ciphertext + tag
}

fn load_master_key() -> ServerResult<SecretVec<u8>> {
    // Try explicit 32-byte master key (base64-encoded)
    if let Ok(mut key_b64) = std::env::var(MASTER_KEY_ENV) {
        key_b64 = key_b64.trim().to_string();
        if !key_b64.is_empty() {
            let master = base64::engine::general_purpose::STANDARD
                .decode(&key_b64)
                .map_err(|e| ServerError::Base64(format!("RB_SERVER_SECRETS_KEY must be base64-encoded 32 bytes: {e}")))?;
            if master.len() != 32 {
                return Err(ServerError::InvalidMasterSecret);
            }
            return Ok(SecretVec::new(Box::new(master)));
        }
    }

    // Try passphrase with Argon2id KDF (uses dynamic salt file)
    if let Ok(pass) = std::env::var(MASTER_PASSPHRASE_ENV) {
        let pass = pass.trim().to_string();
        if !pass.is_empty() {
            let salt = get_or_create_master_salt()?;
            // Hardened Argon2id: 64MB memory, 4 iterations, 1 lane
            let params = Params::new(64 * 1024, 4, 1, Some(32)).map_err(|e| ServerError::Crypto(e.to_string()))?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            let salt_string = SaltString::encode_b64(&salt).map_err(|e| ServerError::Crypto(format!("invalid salt: {e}")))?;
            let hash = argon2
                .hash_password(pass.as_bytes(), &salt_string)
                .map_err(|e| ServerError::Crypto(format!("kdf failed: {e}")))?;

            let raw = hash
                .hash
                .ok_or_else(|| ServerError::Crypto("argon2 produced no hash".to_string()))?;
            let bytes = raw.as_bytes();
            if bytes.len() < 32 {
                return Err(ServerError::Crypto("argon2 output too short".to_string()));
            }
            return Ok(SecretVec::new(Box::new(bytes[..32].to_vec())));
        }
    }

    Err(ServerError::MissingEnvVar(
        "set RB_SERVER_SECRETS_KEY (base64 32 bytes) or RB_SERVER_SECRETS_PASSPHRASE".to_string(),
    ))
}

fn get_or_create_master_salt() -> ServerResult<Vec<u8>> {
    let path = if let Ok(path_str) = std::env::var(SALT_FILE_ENV) {
        PathBuf::from(path_str)
    } else {
        // Default: store salt file alongside server.db
        state_store::server_db_dir().join("secrets.salt")
    };

    if path.exists() {
        let content = fs::read(&path).map_err(ServerError::Io)?;
        if content.len() != 32 {
            return Err(ServerError::Crypto(format!(
                "Existing salt file {} is not 32 bytes",
                path.display()
            )));
        }

        // Check and fix permissions on existing salt file
        if let Ok(changed) = ensure_secure_permissions(&path)
            && changed
        {
            tracing::warn!(
                salt_file = %path.display(),
                "Fixed insecure salt file permissions to 0600"
            );
        }

        Ok(content)
    } else {
        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(ServerError::Io)?;
        }

        let salt = random_bytes(32);

        // Write with secure permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut options = fs::OpenOptions::new();
            options.create_new(true).write(true).mode(0o600);
            let mut file = options.open(&path).map_err(ServerError::Io)?;
            std::io::Write::write_all(&mut file, &salt).map_err(ServerError::Io)?;
        }

        #[cfg(not(unix))]
        {
            fs::write(&path, &salt).map_err(|e| ServerError::Io(e))?;
        }

        Ok(salt)
    }
}

/// Ensure a file has secure permissions (0600 on Unix)
/// Returns true if permissions were changed
fn ensure_secure_permissions(path: &Path) -> ServerResult<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let metadata = fs::metadata(path).map_err(ServerError::Io)?;
        let current_mode = metadata.permissions().mode() & 0o777;

        if current_mode != 0o600 {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(path, perms).map_err(ServerError::Io)?;
            return Ok(true);
        }
        Ok(false)
    }

    #[cfg(not(unix))]
    {
        // On non-Unix platforms, we can't check/set permissions
        Ok(false)
    }
}

pub fn encrypt_secret(plaintext: &[u8]) -> ServerResult<EncryptedBlob> {
    let master_key = MASTER_KEY
        .as_ref()
        .map_err(|e| ServerError::Crypto(format!("Master key init failed: {e}")))?;

    let salt = random_bytes(16);
    let nonce = random_bytes(24);

    // Derive per-record encryption key using HKDF-SHA256
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), master_key.expose_secret());
    let mut key = [0u8; 32];
    hkdf.expand(b"rb-secret-v2", &mut key)
        .map_err(|_| ServerError::Crypto("HKDF expansion failed".to_string()))?;

    // Add random padding (1-32 bytes) for length obfuscation
    let mut padded_pt = plaintext.to_vec();
    let pad_len = rand::thread_rng().gen_range(1..=32) as u8;
    let padding = random_bytes(pad_len as usize);
    padded_pt.extend_from_slice(&padding);
    padded_pt.push(pad_len); // Store padding length as last byte

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), padded_pt.as_slice())
        .map_err(|e| ServerError::secret_op("encrypt", e.to_string()))?;

    Ok(EncryptedBlob {
        salt,
        nonce,
        ciphertext: ct,
    })
}

pub fn decrypt_secret(salt: &[u8], nonce: &[u8], ciphertext: &[u8]) -> ServerResult<(SecretVec<u8>, bool)> {
    // Attempt v2 decryption (HKDF-based key derivation)
    let master_key = MASTER_KEY
        .as_ref()
        .map_err(|e| ServerError::Crypto(format!("Master key init failed: {e}")))?;

    let hkdf = Hkdf::<Sha256>::new(Some(salt), master_key.expose_secret());
    let mut key = [0u8; 32];
    hkdf.expand(b"rb-secret-v2", &mut key)
        .map_err(|_| ServerError::Crypto("HKDF expansion failed".to_string()))?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));

    match cipher.decrypt(XNonce::from_slice(nonce), ciphertext) {
        Ok(pt) => Ok((remove_padding(pt), false)),
        Err(_) => {
            // Fall back to v1 decryption for backward compatibility
            match decrypt_secret_v1(salt, nonce, ciphertext) {
                Ok(pt) => Ok((pt, true)), // true = legacy v1 secret
                Err(_) => Err(ServerError::secret_op("decrypt", "decryption failed (v2 and v1)".to_string())),
            }
        }
    }
}

/// Remove padding from decrypted plaintext (v2 format)
/// Last byte indicates padding length; returns plaintext without padding
fn remove_padding(pt: Vec<u8>) -> SecretVec<u8> {
    // Remove padding: last byte indicates padding length
    if let Some(&pad_len) = pt.last() {
        let len = pad_len as usize;
        if len > 0 && len < pt.len() {
            let real_len = pt.len() - len - 1;
            return SecretVec::new(Box::new(pt[..real_len].to_vec()));
        }
    }
    // Return as-is if padding appears invalid
    SecretVec::new(Box::new(pt))
}

/// Decrypt using legacy v1 method (Argon2-based key derivation)
fn decrypt_secret_v1(salt: &[u8], nonce: &[u8], ciphertext: &[u8]) -> ServerResult<SecretVec<u8>> {
    let key = derive_record_key_v1(salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.expose_secret()));
    let pt = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|e| ServerError::secret_op("decrypt", e.to_string()))?;
    Ok(SecretVec::new(Box::new(pt)))
}

/// Derive encryption key using v1 method (Argon2 KDF) for backward compatibility
fn derive_record_key_v1(salt: &[u8]) -> ServerResult<SecretVec<u8>> {
    if let Ok(mut key_b64) = std::env::var(MASTER_KEY_ENV) {
        key_b64 = key_b64.trim().to_string();
        if !key_b64.is_empty() {
            let master = base64::engine::general_purpose::STANDARD
                .decode(&key_b64)
                .map_err(|e| ServerError::Base64(format!("RB_SERVER_SECRETS_KEY invalid: {e}")))?;
            return kdf_argon2(&master, salt);
        }
    }
    if let Ok(pass) = std::env::var(MASTER_PASSPHRASE_ENV) {
        let pass = pass.trim().to_string();
        if !pass.is_empty() {
            return kdf_argon2(pass.as_bytes(), salt);
        }
    }
    Err(ServerError::InvalidMasterSecret)
}

/// Argon2 KDF helper for v1 decryption
fn kdf_argon2(secret: &[u8], salt: &[u8]) -> ServerResult<SecretVec<u8>> {
    let salt_string = SaltString::encode_b64(salt).map_err(|e| ServerError::Crypto(format!("invalid salt: {e}")))?;
    let hash = Argon2::default()
        .hash_password(secret, &salt_string)
        .map_err(|e| ServerError::Crypto(format!("kdf failed: {e}")))?;
    let raw = hash
        .hash
        .ok_or_else(|| ServerError::Crypto("argon2 produced no hash".to_string()))?;
    Ok(SecretVec::new(Box::new(raw.as_bytes()[..32].to_vec())))
}

/// Encrypt with an explicit master key (for testing/manual use)
pub fn encrypt_secret_with(plaintext: &[u8], master: &[u8]) -> ServerResult<EncryptedBlob> {
    let salt = random_bytes(16);
    let nonce = random_bytes(24);

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), master);
    let mut key = [0u8; 32];
    hkdf.expand(b"rb-secret-v2", &mut key)
        .map_err(|_| ServerError::Crypto("HKDF expansion failed".to_string()))?;

    // Add random padding (1-32 bytes) for length obfuscation
    let mut padded_pt = plaintext.to_vec();
    let pad_len = rand::thread_rng().gen_range(1..=32) as u8;
    let padding = random_bytes(pad_len as usize);
    padded_pt.extend_from_slice(&padding);
    padded_pt.push(pad_len); // Store padding length as last byte

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), padded_pt.as_slice())
        .map_err(|e| ServerError::secret_op("encrypt", e.to_string()))?;
    Ok(EncryptedBlob {
        salt,
        nonce,
        ciphertext: ct,
    })
}

pub fn decrypt_secret_with(salt: &[u8], nonce: &[u8], ciphertext: &[u8], master: &[u8]) -> ServerResult<SecretVec<u8>> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master);
    let mut key = [0u8; 32];
    hkdf.expand(b"rb-secret-v2", &mut key)
        .map_err(|_| ServerError::Crypto("HKDF expansion failed".to_string()))?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let pt = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|e| ServerError::secret_op("decrypt", e.to_string()))?;

    Ok(remove_padding(pt))
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    buf
}

pub fn encrypt_string(value: SecretString) -> ServerResult<String> {
    let blob = encrypt_secret(value.expose_secret().as_bytes())?;
    let mut raw = Vec::with_capacity(16 + 24 + blob.ciphertext.len());
    raw.extend_from_slice(&blob.salt);
    raw.extend_from_slice(&blob.nonce);
    raw.extend_from_slice(&blob.ciphertext);
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(raw);
    Ok(format!("{ENC_PREFIX_V2}{b64}"))
}

pub fn decrypt_string_if_encrypted(value: &str) -> ServerResult<(SecretString, bool)> {
    if let Some(rest) = value.strip_prefix(ENC_PREFIX_V2) {
        let raw = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(rest)
            .map_err(|e| ServerError::Base64(format!("invalid encrypted value: {e}")))?;
        if raw.len() < 16 + 24 {
            return Err(ServerError::Crypto("encrypted value too short".to_string()));
        }
        let (salt, rest) = raw.split_at(16);
        let (nonce, ct) = rest.split_at(24);
        let (pt, is_legacy) = decrypt_secret(salt, nonce, ct)?;
        // Respect the legacy flag from decrypt_secret (handles edge case where v2 prefix falls back to v1)
        return String::from_utf8(pt.expose_secret().clone())
            .map(|s| (SecretString::new(Box::new(s)), is_legacy))
            .map_err(|_| ServerError::Crypto("decrypted value is not valid UTF-8".to_string()));
    } else if let Some(rest) = value.strip_prefix(ENC_PREFIX_V1) {
        // Handle v1 prefix explicitly
        let raw = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(rest)
            .map_err(|e| ServerError::Base64(format!("invalid encrypted value: {e}")))?;
        if raw.len() < 16 + 24 {
            return Err(ServerError::Crypto("encrypted value too short".to_string()));
        }
        let (salt, rest) = raw.split_at(16);
        let (nonce, ct) = rest.split_at(24);
        let pt = decrypt_secret_v1(salt, nonce, ct)?;
        return String::from_utf8(pt.expose_secret().clone())
            .map(|s| (SecretString::new(Box::new(s)), true))
            .map_err(|_| ServerError::Crypto("decrypted value is not valid UTF-8".to_string()));
    }

    Ok((SecretString::new(Box::new(value.to_string())), false))
}

pub fn is_encrypted_marker(value: &str) -> bool {
    value.starts_with(ENC_PREFIX_V2) || value.starts_with(ENC_PREFIX_V1)
}

pub fn encrypt_string_with(value: SecretString, master: &[u8]) -> ServerResult<String> {
    let blob = encrypt_secret_with(value.expose_secret().as_bytes(), master)?;
    let mut raw = Vec::with_capacity(16 + 24 + blob.ciphertext.len());
    raw.extend_from_slice(&blob.salt);
    raw.extend_from_slice(&blob.nonce);
    raw.extend_from_slice(&blob.ciphertext);
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(raw);
    Ok(format!("{ENC_PREFIX_V2}{b64}"))
}

pub fn decrypt_string_with(value: &str, master: &[u8]) -> ServerResult<SecretString> {
    // This assumes v2 for manual calls with master key
    let rest = value
        .strip_prefix(ENC_PREFIX_V2)
        .or_else(|| value.strip_prefix(ENC_PREFIX_V1)) // Try v1 prefix too? But v1 needs ARGON2, not HKDF.
        // If we pass "master" here, what is it?
        // If it's the raw 32-byte key, v2 works.
        // If it's the passphrase, v1 works.
        // The signature says `master: &[u8]`.
        // Usually this is used for testing. I'll support v2 only for now to be safe, or check prefix.
        .ok_or_else(|| ServerError::Crypto("value is not encrypted".to_string()))?;

    // If it was v1, we can't easily decrypt with just a "key" unless that key IS the passphrase?
    // But `decrypt_secret_with` uses HKDF now.
    // I'll stick to v2 support here.

    let raw = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(rest)
        .map_err(|e| ServerError::Base64(format!("invalid encrypted value: {e}")))?;
    if raw.len() < 16 + 24 {
        return Err(ServerError::Crypto("encrypted value too short".to_string()));
    }
    let (salt, rest) = raw.split_at(16);
    let (nonce, ct) = rest.split_at(24);
    let pt = decrypt_secret_with(salt, nonce, ct, master)?;
    String::from_utf8(pt.expose_secret().clone())
        .map(|s| SecretString::new(Box::new(s)))
        .map_err(|_| ServerError::Crypto("decrypted value is not valid UTF-8".to_string()))
}

pub fn normalize_master_input(input: &str) -> Vec<u8> {
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(input)
        && decoded.len() == 32
    {
        return decoded;
    }
    input.as_bytes().to_vec()
}

/// Derive a master key from a passphrase using the same Argon2id KDF as load_master_key.
/// This is used for secret rotation to ensure compatibility.
pub fn derive_master_key_from_passphrase(passphrase: &str) -> ServerResult<Vec<u8>> {
    let salt = get_or_create_master_salt()?;
    // Hardened Argon2id: 64MB memory, 4 iterations, 1 lane (matches load_master_key)
    let params = Params::new(64 * 1024, 4, 1, Some(32)).map_err(|e| ServerError::Crypto(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let salt_string = SaltString::encode_b64(&salt).map_err(|e| ServerError::Crypto(format!("invalid salt: {e}")))?;
    let hash = argon2
        .hash_password(passphrase.as_bytes(), &salt_string)
        .map_err(|e| ServerError::Crypto(format!("kdf failed: {e}")))?;

    let raw = hash
        .hash
        .ok_or_else(|| ServerError::Crypto("argon2 produced no hash".to_string()))?;
    let bytes = raw.as_bytes();
    if bytes.len() < 32 {
        return Err(ServerError::Crypto("argon2 output too short".to_string()));
    }
    Ok(bytes[..32].to_vec())
}

#[cfg(test)]
mod tests {
    use serial_test::serial;

    use super::*;

    // Helper to reset state if needed (though Lazy is hard to reset)
    // We can mock env vars.

    #[test]
    #[serial]
    fn test_encrypt_decrypt_v2_roundtrip() {
        // Set up env for master key
        unsafe {
            std::env::set_var("RB_SERVER_SECRETS_KEY", "dGVzdF9tYXN0ZXJfa2V5XzMyX2J5dGVzX2xvbmdfMTI=");
        } // "test_master_key_32_bytes_long_12" base64

        // Force lazy init? It happens on first access.

        let secret = "Hello World".to_string();
        let secret_box = SecretString::new(Box::new(secret.clone()));

        let encrypted = encrypt_string(secret_box).expect("Encrypt failed");
        assert!(encrypted.starts_with(ENC_PREFIX_V2));

        let (decrypted, is_legacy) = decrypt_string_if_encrypted(&encrypted).expect("Decrypt failed");
        assert_eq!(decrypted.expose_secret(), &secret);
        assert!(!is_legacy);
    }

    #[test]
    #[serial]
    fn test_padding_variation() {
        unsafe {
            std::env::set_var("RB_SERVER_SECRETS_KEY", "dGVzdF9tYXN0ZXJfa2V5XzMyX2J5dGVzX2xvbmdfMTI=");
        }

        let secret = "Short".to_string();
        let _secret_box = SecretString::new(Box::new(secret.clone()));

        let enc1 = encrypt_string(SecretString::new(Box::new(secret.clone()))).expect("Enc1");
        let enc2 = encrypt_string(SecretString::new(Box::new(secret.clone()))).expect("Enc2");

        // They should be different (salt + nonce + padding)
        assert_ne!(enc1, enc2);

        // Lengths might differ due to random padding (1-32 bytes)
        // It's possible they are same length, but unlikely to be *always* same if we run many times.
        // We just check they decrypt correctly.

        let (dec1, _) = decrypt_string_if_encrypted(&enc1).expect("Dec1");
        let (dec2, _) = decrypt_string_if_encrypted(&enc2).expect("Dec2");

        assert_eq!(dec1.expose_secret(), "Short");
        assert_eq!(dec2.expose_secret(), "Short");
    }

    #[test]
    #[serial]
    fn test_v1_compat() {
        // We need to manually construct a v1 string or use the old logic if we had it exposed.
        // Since we replaced the code, we can't call old `encrypt_string`.
        // But we can manually construct the blob if we know the key.
        // v1: Argon2(Passphrase, Salt) -> Key. XChaCha20(Key, Nonce) -> Ciphertext.

        unsafe {
            std::env::set_var("RB_SERVER_SECRETS_PASSPHRASE", "password123");
            // Clear KEY env to force Passphrase usage
            std::env::remove_var("RB_SERVER_SECRETS_KEY");
        }

        // We need to simulate v1 encryption.
        // 1. Derive key using Argon2 (old params: default).
        let salt = vec![1u8; 16];
        let nonce = vec![2u8; 24];
        let plaintext = b"LegacyData";

        // Manually derive key using the helper we kept: kdf_argon2
        // Note: kdf_argon2 in new code uses Argon2::default(), which matches old code.
        let key = kdf_argon2(b"password123", &salt).expect("KDF failed");

        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.expose_secret()));
        let ct = cipher.encrypt(XNonce::from_slice(&nonce), plaintext.as_ref()).expect("Encrypt");

        // Construct v1 string
        let mut raw = Vec::new();
        raw.extend_from_slice(&salt);
        raw.extend_from_slice(&nonce);
        raw.extend_from_slice(&ct);
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(raw);
        let v1_string = format!("{}{}", ENC_PREFIX_V1, b64);

        // Decrypt using new code
        let (decrypted, is_legacy) = decrypt_string_if_encrypted(&v1_string).expect("Decrypt v1 failed");
        assert_eq!(decrypted.expose_secret(), "LegacyData");
        assert!(is_legacy);
    }
}

pub fn require_master_secret() -> ServerResult<()> {
    // Just trigger the lazy load to check
    MASTER_KEY.as_ref().map(|_| ()).map_err(|e| ServerError::Crypto(e.to_string()))
}
