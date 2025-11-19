use base64::Engine;
use cbc::{
    Encryptor, cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7}
};
use des::TdesEde3;
use rand::RngCore;
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey};

fn to_pem(label: &str, data: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(data);
    let mut pem = String::new();
    pem.push_str(&format!("-----BEGIN {}-----\n", label));
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", label));
    pem
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

#[test]
fn loads_unencrypted_legacy_pem() {
    // Generate a small RSA key for test and encode as PKCS#1 (legacy PEM)
    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, 512).expect("generate");
    let der = key.to_pkcs1_der().expect("der");
    let pem = to_pem("RSA PRIVATE KEY", der.as_bytes());

    let loaded = ssh_core::keys::load_private_key_from_str(&pem, None).expect("load legacy pem");
    assert!(loaded.algorithm().is_rsa());
}

#[test]
fn loads_encrypted_legacy_pem_des_ede3() {
    // Generate key and encrypt legacy PKCS#1 with DES-EDE3-CBC using OpenSSL-compatible KDF
    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, 512).expect("generate");
    let der = key.to_pkcs1_der().expect("der");

    // IV (16 hex) corresponds to 8 bytes; first 8 used for salt and IV per PEM convention
    let mut iv = [0u8; 8];
    rng.fill_bytes(&mut iv);
    let pass = b"test-pass";
    let k = evp_bytes_to_key(pass, &iv[..], 24);
    let cipher = Encryptor::<TdesEde3>::new_from_slices(&k, &iv).expect("cipher");
    let mut buf = der.as_bytes().to_vec();
    let in_len = buf.len();
    // Reserve one block for PKCS#7 padding when encrypting in-place
    buf.extend_from_slice(&[0u8; 8]);
    let ct = cipher.encrypt_padded_mut::<Pkcs7>(&mut buf, in_len).expect("enc").to_vec();

    let mut pem = String::new();
    pem.push_str("-----BEGIN RSA PRIVATE KEY-----\n");
    pem.push_str("Proc-Type: 4,ENCRYPTED\n");
    pem.push_str(&format!("DEK-Info: DES-EDE3-CBC,{}\n\n", hex::encode_upper(iv)));
    let b64 = base64::engine::general_purpose::STANDARD.encode(ct);
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END RSA PRIVATE KEY-----\n");

    let loaded = ssh_core::keys::load_private_key_from_str(&pem, Some("test-pass")).expect("load encrypted legacy pem");
    assert!(loaded.algorithm().is_rsa());
}
