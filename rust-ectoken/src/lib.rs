extern crate base64;
extern crate crypto;

use crypto::aead::{AeadEncryptor,AeadDecryptor};
use crypto::aes;
use crypto::aes_gcm::AesGcm;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::error::Error;

pub fn init() {
}

pub fn encrypt_v3(_key: &str, _token: &str) -> String {
    let s = String::new();

    s
}

pub fn decrypt_v3(key: &str, token: &str) -> Result<String, Box<dyn Error>> {
    let chars = base64::decode_config(token, base64::URL_SAFE_NO_PAD)?;

    let mut hasher = Sha256::new();
    hasher.input_str(key);
    let mut key_hash = Vec::new();
    hasher.result(&mut key_hash);

    let mut crypto = AesGcm::new(aes::KeySize::KeySize256, &key_hash, &chars[..16], &vec![]);

    let mut output = Vec::new();
    crypto.decrypt(&chars[16..], &mut output, &vec![]);

    let s = String::from_utf8(output)?;

    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_returns_err_on_invalid_base64_string() {
        let decrypted = decrypt_v3("testkey123", "af0c6acf7906cd500aee63a4dd2e97ddcb0142601cf83aa9d622289718c4c85413");

        assert!(decrypted.is_err(), "decryption should be an Error with invalid base64 encoded string");
    }

    #[test]
    fn it_decrypt_as_expected() {
        let decrypted = decrypt_v3("testkey123", "bs4W7wyy0OjyBQMhAaahSVo2sG4gKEzuOegBf9kI-ZzG8Gz4FQuFud2ndvmuXkReeRnKFYXTJ7q5ynniGw").unwrap();
 
        assert_eq!("ec_expire=1257642471&ec_secure=33", decrypted);
    }
}