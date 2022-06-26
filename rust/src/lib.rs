extern crate openssl;
use openssl::rand;
use openssl::symm;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn sha2(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.input_str(input);
    hasher.result_str()
}

#[wasm_bindgen]
pub fn aes(input: &str) -> String {
    let cipher = symm::Cipher::aes_256_ctr();

    let key = {
        let mut buf = vec![0; cipher.key_len()];
        rand::rand_bytes(buf.as_mut_slice());
        buf
    };

    let iv = {
        let mut buf = vec![0; cipher.iv_len().unwrap()];
        rand::rand_bytes(buf.as_mut_slice());
        buf
    };
    let test_data: &str = "some test data";

    let encrypted_message =
        symm::encrypt(cipher,
                      &key,
                      Some(iv.as_slice()),
                      test_data.as_bytes()).unwrap();
}