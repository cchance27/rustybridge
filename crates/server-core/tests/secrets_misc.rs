use base64::Engine;
use server_core::secrets;

#[test]
fn decrypt_passthrough_for_plain_value() {
    let s = "plain-value";
    let out = secrets::decrypt_string_if_encrypted(s).expect("ok");
    assert_eq!(out, s);
}

#[test]
fn normalize_master_input_prefers_base64_key() {
    let key32 = [0x42u8; 32];
    let b64 = base64::engine::general_purpose::STANDARD.encode(key32);
    let out = secrets::normalize_master_input(&b64);
    assert_eq!(out, key32);
    // Non-base64 or wrong length falls back to passphrase bytes
    let pass = "secret-pass";
    let out2 = secrets::normalize_master_input(pass);
    assert_eq!(out2, pass.as_bytes());
}
