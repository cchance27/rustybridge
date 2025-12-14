use crate::error::{SshCoreError, SshResult};
use base64::Engine;
use cbc::{
    Decryptor,
    cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7},
};
use des::TdesEde3;
use hex::FromHex;
use md5;
use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey, pkcs8::EncodePrivateKey};
use russh::keys;
use std::collections::HashMap;

/// Load a private key from string data, supporting:
/// - OpenSSH keys
/// - PKCS#8 (encrypted/unencrypted)
/// - Traditional PEM "BEGIN RSA PRIVATE KEY" (encrypted with DES-EDE3-CBC or unencrypted)
///
/// If the key is encrypted, provide `passphrase` or an error is returned.
pub fn load_private_key_from_str(data: &str, passphrase: Option<&str>) -> SshResult<keys::PrivateKey> {
    // Try OpenSSH first
    if let Ok(key) = keys::PrivateKey::from_openssh(data) {
        return Ok(key);
    }

    // Try PKCS#8 decode (handles encrypted OpenSSH/PKCS8 formats via russh)
    match keys::decode_secret_key(data, passphrase) {
        Ok(key) => return Ok(key),
        Err(keys::Error::KeyIsEncrypted) => {
            // If no passphrase provided, bail early
            if passphrase.is_none() {
                return Err(SshCoreError::Other("encrypted private key requires a passphrase".into()));
            }
        }
        Err(_) => { /* fall through to legacy PEM */ }
    }

    // Legacy "traditional" PEM (BEGIN RSA PRIVATE KEY)
    if let Some(parts) = parse_rsa_pem(data) {
        let PemParts { headers, body } = parts;
        let mut der = base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|e| SshCoreError::Other(format!("base64 decode error: {e}")))?;

        if is_encrypted(&headers) {
            let dek_info = headers
                .get("DEK-Info")
                .ok_or_else(|| SshCoreError::Other("missing DEK-Info header in legacy PEM".into()))?;
            let mut parts = dek_info.split(',');
            let algo = parts.next().unwrap_or_default().trim();
            let iv_hex = parts.next().unwrap_or_default().trim();
            let iv = Vec::from_hex(iv_hex).map_err(|_| SshCoreError::Other("invalid DEK-Info IV in legacy PEM".into()))?;
            match algo {
                "DES-EDE3-CBC" => {
                    let pass = passphrase.ok_or_else(|| SshCoreError::Other("encrypted legacy PEM requires passphrase".into()))?;
                    der = decrypt_des_ede3(&der, &iv, pass)?;
                }
                other => {
                    return Err(SshCoreError::Other(format!("unsupported legacy PEM cipher {other}")));
                }
            }
        }

        return load_pkcs1(&der);
    }

    Err(SshCoreError::Other("not a valid OpenSSH, PKCS#8, or legacy PEM private key".into()))
}

struct PemParts {
    headers: HashMap<String, String>,
    body: String,
}

fn parse_rsa_pem(data: &str) -> Option<PemParts> {
    let begin = "-----BEGIN RSA PRIVATE KEY-----";
    let end = "-----END RSA PRIVATE KEY-----";
    let start = data.find(begin)? + begin.len();
    let end_idx = data.find(end)?;
    let section = &data[start..end_idx];
    let mut headers = HashMap::new();
    let mut body = String::new();
    let mut in_headers = true;
    let mut saw_header = false;
    for line in section.lines() {
        let line = line.trim();
        if in_headers {
            if line.is_empty() {
                if saw_header {
                    in_headers = false;
                }
                continue;
            }
            if let Some((key, value)) = line.split_once(':') {
                headers.insert(key.trim().to_string(), value.trim().to_string());
                saw_header = true;
                continue;
            }
            in_headers = false;
        }
        if !line.is_empty() {
            body.push_str(line);
        }
    }
    Some(PemParts { headers, body })
}

fn is_encrypted(headers: &HashMap<String, String>) -> bool {
    matches!(headers.get("Proc-Type"), Some(value) if value.contains("ENCRYPTED"))
}

fn decrypt_des_ede3(ciphertext: &[u8], iv: &[u8], passphrase: &str) -> SshResult<Vec<u8>> {
    if iv.len() < 8 {
        return Err(SshCoreError::Other("invalid IV for DES-EDE3-CBC".into()));
    }
    let salt = &iv[..8];
    let key = evp_bytes_to_key(passphrase.as_bytes(), salt, 24);
    let cipher = Decryptor::<TdesEde3>::new_from_slices(&key, &iv[..8])
        .map_err(|err| SshCoreError::Other(format!("unable to init DES-EDE3: {err}")))?;
    let mut buf = ciphertext.to_vec();
    let decrypted = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|err| SshCoreError::Other(format!("failed to decrypt legacy PEM: {err}")))?
        .to_vec();
    Ok(decrypted)
}

fn evp_bytes_to_key(passphrase: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut prev: Option<[u8; 16]> = None;
    while key.len() < key_len {
        let mut data = Vec::new();
        if let Some(ref digest) = prev {
            data.extend_from_slice(digest);
        }
        data.extend_from_slice(passphrase);
        data.extend_from_slice(salt);
        let digest = md5::compute(&data).0;
        prev = Some(digest);
        key.extend_from_slice(&digest);
    }
    key.truncate(key_len);
    key
}

fn load_pkcs1(der: &[u8]) -> SshResult<keys::PrivateKey> {
    let rsa = RsaPrivateKey::from_pkcs1_der(der).map_err(|e| SshCoreError::Other(format!("PKCS1 decode error: {e}")))?;
    let pkcs8 = rsa
        .to_pkcs8_pem(Default::default())
        .map_err(|e| SshCoreError::Other(format!("PKCS8 encode error: {e}")))?;
    let key = keys::decode_secret_key(pkcs8.as_str(), None).map_err(|e| SshCoreError::Other(e.to_string()))?;
    Ok(key)
}
