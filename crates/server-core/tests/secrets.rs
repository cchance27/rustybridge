use secrecy::ExposeSecret;
use server_core::secrets::{self, SecretBoxedString, decrypt_secret_with, decrypt_string_with, encrypt_secret_with, encrypt_string_with};

#[test]
fn encrypt_string_roundtrip_with_master_key() {
    let master = b"0123456789abcdef0123456789abcdef"; // 32 bytes
    let pt = "s3cr3t-P@ssw0rd!";
    let enc = encrypt_string_with(SecretBoxedString::new(Box::new(pt.to_string())), master).expect("encrypt");
    assert!(secrets::is_encrypted_marker(&enc));
    let dec = decrypt_string_with(&enc, master).expect("decrypt");
    assert_eq!(&**dec.expose_secret(), pt);
}

#[test]
fn encrypt_secret_roundtrip_with_master_key() {
    let master = b"fedcba9876543210fedcba9876543210"; // 32 bytes
    let pt = b"hello-bytes";
    let blob = encrypt_secret_with(pt, master).expect("encrypt");
    let dec = decrypt_secret_with(&blob.salt, &blob.nonce, &blob.ciphertext, master).expect("decrypt");
    assert_eq!(dec.expose_secret().as_slice(), pt);
}
