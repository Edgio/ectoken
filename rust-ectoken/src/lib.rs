extern crate base64;
extern crate crypto;

use std::error::Error;

pub fn init() {
}

pub fn encrypt_v3(_key: &str, _token: &str) -> String {
    let s = String::new();

    s
}

pub fn decrypt_v3(_key: &str, token: &str) -> Result<String, Box<dyn Error>> {
    let token = token.trim_right_matches("=");
    let chars = base64::decode(token);

    println!("{:?}", chars);
    let s = String::new();

    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_decrypt_as_expected() {
        let decrypted = decrypt_v3("testkey123", "af0c6acf7906cd500aee63a4dd2e97ddcb0142601cf83aa9d622289718c4c85413").unwrap();
 
        assert_eq!("ec_expire=1257642471&ec_secure=33", decrypted);
    }
}