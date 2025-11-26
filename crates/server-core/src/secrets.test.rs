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