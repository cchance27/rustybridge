use argon2::{
    Argon2, password_hash::{PasswordHasher, SaltString}
};
use base64::Engine;
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce, aead::{Aead, KeyInit, OsRng}
};
use rand::RngCore;
use secrecy::ExposeSecret;

pub type SecretString = secrecy::SecretBox<String>;
pub type SecretVec<T> = secrecy::SecretBox<Vec<T>>;

use crate::error::{ServerError, ServerResult};

const MASTER_KEY_ENV: &str = "RB_SERVER_SECRETS_KEY"; // base64 32 bytes
const MASTER_PASSPHRASE_ENV: &str = "RB_SERVER_SECRETS_PASSPHRASE"; // string

pub struct EncryptedBlob {
    pub salt: Vec<u8>,       // KDF salt (16 bytes)
    pub nonce: Vec<u8>,      // XChaCha20-Poly1305 nonce (24 bytes)
    pub ciphertext: Vec<u8>, // ciphertext + tag
}

pub fn encrypt_secret(plaintext: &[u8]) -> ServerResult<EncryptedBlob> {
    let salt = random_bytes(16);
    let key = derive_record_key(&salt)?;
    let nonce = random_bytes(24);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.expose_secret()));
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|e| ServerError::secret_op("encrypt", e.to_string()))?;
    Ok(EncryptedBlob {
        salt,
        nonce,
        ciphertext: ct,
    })
}

pub fn decrypt_secret(salt: &[u8], nonce: &[u8], ciphertext: &[u8]) -> ServerResult<SecretVec<u8>> {
    let key = derive_record_key(salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.expose_secret()));
    let pt = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|e| ServerError::secret_op("decrypt", e.to_string()))?;
    Ok(SecretVec::new(Box::new(pt)))
}

pub fn encrypt_secret_with(plaintext: &[u8], master: &[u8]) -> ServerResult<EncryptedBlob> {
    let salt = random_bytes(16);
    let key = derive_record_key_with_secret(master, &salt)?;
    let nonce = random_bytes(24);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.expose_secret()));
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|e| ServerError::secret_op("encrypt", e.to_string()))?;
    Ok(EncryptedBlob {
        salt,
        nonce,
        ciphertext: ct,
    })
}

pub fn decrypt_secret_with(salt: &[u8], nonce: &[u8], ciphertext: &[u8], master: &[u8]) -> ServerResult<SecretVec<u8>> {
    let key = derive_record_key_with_secret(master, salt)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.expose_secret()));
    let pt = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|e| ServerError::secret_op("decrypt", e.to_string()))?;
    Ok(SecretVec::new(Box::new(pt)))
}

fn derive_record_key(salt: &[u8]) -> ServerResult<SecretVec<u8>> {
    if let Ok(key_b64) = std::env::var(MASTER_KEY_ENV) {
        // Derive per-record key from master key via Argon2 using per-record salt.
        let master = base64::engine::general_purpose::STANDARD
            .decode(key_b64)
            .map_err(|e| ServerError::Base64(format!("RB_SERVER_SECRETS_KEY must be base64-encoded 32 bytes: {e}")))?;
        if master.len() != 32 {
            return Err(ServerError::InvalidMasterSecret);
        }
        return kdf_argon2(&master, salt);
    }
    if let Ok(pass) = std::env::var(MASTER_PASSPHRASE_ENV) {
        return kdf_argon2(pass.as_bytes(), salt);
    }
    Err(ServerError::MissingEnvVar(
        "set RB_SERVER_SECRETS_KEY (base64 32 bytes) or RB_SERVER_SECRETS_PASSPHRASE".to_string(),
    ))
}

pub fn derive_record_key_with_secret(master_secret: &[u8], salt: &[u8]) -> ServerResult<SecretVec<u8>> {
    kdf_argon2(master_secret, salt)
}

fn kdf_argon2(secret: &[u8], salt: &[u8]) -> ServerResult<SecretVec<u8>> {
    // Use Argon2id default with OS RNG salt already provided per record.
    // We map to PasswordHasher API by constructing a SaltString from raw salt.
    let salt_string = SaltString::encode_b64(salt).map_err(|e| ServerError::Crypto(format!("invalid salt: {e}")))?;
    let hash = Argon2::default()
        .hash_password(secret, &salt_string)
        .map_err(|e| ServerError::Crypto(format!("kdf failed: {e}")))?;
    // Extract 32 bytes from the hash's hash output (PHC format). Use Blake3 if needed later.
    let raw = hash
        .hash
        .ok_or_else(|| ServerError::Crypto("argon2 produced no hash".to_string()))?;
    let bytes = raw.as_bytes();
    if bytes.len() < 32 {
        return Err(ServerError::Crypto("argon2 output too short".to_string()));
    }
    Ok(SecretVec::new(Box::new(bytes[..32].to_vec())))
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    buf
}

const ENC_PREFIX: &str = "enc:v1:";

pub fn encrypt_string(value: SecretString) -> ServerResult<String> {
    let blob = encrypt_secret(value.expose_secret().as_bytes())?;
    let mut raw = Vec::with_capacity(16 + 24 + blob.ciphertext.len());
    raw.extend_from_slice(&blob.salt);
    raw.extend_from_slice(&blob.nonce);
    raw.extend_from_slice(&blob.ciphertext);
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(raw);
    Ok(format!("{ENC_PREFIX}{b64}"))
}

pub fn decrypt_string_if_encrypted(value: &str) -> ServerResult<SecretString> {
    if let Some(rest) = value.strip_prefix(ENC_PREFIX) {
        let raw = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(rest)
            .map_err(|e| ServerError::Base64(format!("invalid encrypted value: {e}")))?;
        if raw.len() < 16 + 24 {
            return Err(ServerError::Crypto("encrypted value too short".to_string()));
        }
        let (salt, rest) = raw.split_at(16);
        let (nonce, ct) = rest.split_at(24);
        let pt = decrypt_secret(salt, nonce, ct)?;
        return String::from_utf8(pt.expose_secret().clone())
            .map(|s| SecretString::new(Box::new(s)))
            .map_err(|_| ServerError::Crypto("decrypted value is not valid UTF-8".to_string()));
    }
    Ok(SecretString::new(Box::new(value.to_string())))
}

pub fn is_encrypted_marker(value: &str) -> bool {
    value.starts_with(ENC_PREFIX)
}

pub fn encrypt_string_with(value: SecretString, master: &[u8]) -> ServerResult<String> {
    let blob = encrypt_secret_with(value.expose_secret().as_bytes(), master)?;
    let mut raw = Vec::with_capacity(16 + 24 + blob.ciphertext.len());
    raw.extend_from_slice(&blob.salt);
    raw.extend_from_slice(&blob.nonce);
    raw.extend_from_slice(&blob.ciphertext);
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(raw);
    Ok(format!("{ENC_PREFIX}{b64}"))
}

pub fn decrypt_string_with(value: &str, master: &[u8]) -> ServerResult<SecretString> {
    let rest = value
        .strip_prefix(ENC_PREFIX)
        .ok_or_else(|| ServerError::Crypto("value is not encrypted".to_string()))?;
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
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(input) && decoded.len() == 32 {
        return decoded;
    }
    input.as_bytes().to_vec()
}
