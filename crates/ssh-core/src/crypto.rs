use russh::{
    Preferred,
    keys::{Algorithm, HashAlg},
};
use std::borrow::Cow;

pub fn default_preferred() -> Preferred {
    Preferred::DEFAULT.clone()
}

pub fn legacy_preferred() -> Preferred {
    Preferred {
        kex: Cow::Owned(vec![russh::kex::DH_G1_SHA1, russh::kex::DH_G14_SHA1, russh::kex::CURVE25519]),
        key: Cow::Owned(vec![
            Algorithm::Dsa,
            Algorithm::Rsa { hash: None },
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            Algorithm::Ed25519,
        ]),
        cipher: Cow::Owned(vec![
            russh::cipher::AES_128_CBC,
            russh::cipher::TRIPLE_DES_CBC,
            russh::cipher::AES_128_CTR,
            russh::cipher::CHACHA20_POLY1305,
        ]),
        mac: Cow::Owned(vec![russh::mac::HMAC_SHA1, russh::mac::HMAC_SHA256, russh::mac::HMAC_SHA512]),
        compression: Preferred::DEFAULT.compression,
    }
}
