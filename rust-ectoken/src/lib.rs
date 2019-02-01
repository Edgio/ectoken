extern crate base64;
extern crate crypto;

use crypto::aead::AeadDecryptor;
use crypto::aes;
use crypto::aes_gcm::AesGcm;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::error;
use std::fmt;

pub fn init() {
}

pub fn encrypt_v3(_key: &str, _token: &str) -> String {
    String::new()
}

fn key_hash(key: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();

    hasher.input_str(key);

    let mut key_hash = Vec::new();
    hasher.result(&mut key_hash);

    key_hash
}

pub fn decrypt_v3(key: &str, token: &str) -> Result<String, DecryptionError> {
    let chars = base64::decode_config(token, base64::URL_SAFE_NO_PAD)?;
    
    if chars.len() < 16 {
        return Err(DecryptionError::IOError("invalid input length"));
    }

    let mut crypto = AesGcm::new(aes::KeySize::KeySize256, &key_hash(key), &chars[..16], &[]);
    let mut output = Vec::new();
    crypto.decrypt(&chars[16..], &mut output, &[]);
    let s = String::from_utf8(output)?;

    Ok(s)
}

/// Errors that can occur while decoding.
#[derive(Debug)]
pub enum DecryptionError {
    /// An invalid base64 string was found in the input.
    InvalidBase64(base64::DecodeError),
    /// An invalid UTF8 string was found once decrypted.
    InvalidUTF8(std::string::FromUtf8Error),
    /// An invalid input/output was
    IOError(&'static str),
}

impl fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DecryptionError::InvalidBase64(_) => write!(f, "Invalid base64."),
            DecryptionError::InvalidUTF8(_) => write!(f, "Invalid UTF8 string decrypted."),
            DecryptionError::IOError(description) => write!(f, "Input/Output error: {}", description),
        }
    }
}

impl error::Error for DecryptionError {
    fn description(&self) -> &str {
        match *self {
            DecryptionError::InvalidBase64(_) => "invalid base64",
            DecryptionError::InvalidUTF8(_) => "invalid UTF8 string decrypted",
            DecryptionError::IOError(_) => "input/output error",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            DecryptionError::InvalidBase64(ref previous) => Some(previous),
            DecryptionError::InvalidUTF8(ref previous) => Some(previous),
            _ => None,
        }
    }
}

impl From<base64::DecodeError> for DecryptionError {
    fn from(err: base64::DecodeError) -> DecryptionError {
        DecryptionError::InvalidBase64(err)
    }
}

impl From<std::string::FromUtf8Error> for DecryptionError {
    fn from(err: std::string::FromUtf8Error) -> DecryptionError {
        DecryptionError::InvalidUTF8(err)
    }
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
    fn it_returns_err_on_invalid_length() {
        let decrypted = decrypt_v3("testkey123", "bs4W7wyy");

        assert!(decrypted.is_err(), "decryption should be an Error with invalid length encoded string");
    }

    #[test]
    fn it_decrypt_as_expected() {
        let decrypted = decrypt_v3("testkey123", "bs4W7wyy0OjyBQMhAaahSVo2sG4gKEzuOegBf9kI-ZzG8Gz4FQuFud2ndvmuXkReeRnKFYXTJ7q5ynniGw").unwrap();
 
        assert_eq!("ec_expire=1257642471&ec_secure=33", decrypted);
    }
}