/**
* Copyright (C) 2021 Verizon. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
use aes_gcm::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;
use base64;
use rand::Rng;
use sha2::{Digest, Sha256};

const G_IV_SIZE_BYTES: usize = 12;

// v3 encryption
pub fn encrypt(key: &str, token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let key = hasher.finalize();
    let cipher = Aes256Gcm::new(&key);

    let nonce = rand::thread_rng().gen::<[u8; G_IV_SIZE_BYTES]>();
    let nonce = GenericArray::from_slice(&nonce);

    let mut ciphertext = cipher
        .encrypt(nonce, token.as_bytes())
        .expect("encryption failure!");

    let mut iv_ciphertext: Vec<u8> = Vec::from(nonce.as_slice());
    iv_ciphertext.append(&mut ciphertext);

    base64::encode_config(iv_ciphertext, base64::URL_SAFE_NO_PAD)
}

pub fn decrypt(key: &str, token: &str) -> String {
    let token = base64::decode_config(token, base64::URL_SAFE_NO_PAD).expect("base64 failure");

    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let key = hasher.finalize();
    let cipher = Aes256Gcm::new(&key);

    let nonce = GenericArray::from_slice(&token[0..G_IV_SIZE_BYTES]);

    let ciphertext = &token[G_IV_SIZE_BYTES..];

    String::from_utf8_lossy(
        cipher
            .decrypt(nonce, ciphertext)
            .expect("decryption failure!")
            .as_ref(),
    )
    .to_string()

    //assert_eq!(&plaintext, b"plaintext message");
}
