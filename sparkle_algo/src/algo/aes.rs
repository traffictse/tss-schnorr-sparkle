use crate::exn;
use aes_gcm::{
    aead::{Aead, NewAead, Payload},
    Aes256Gcm, Nonce,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use xuanmi_base_support::*;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> Outcome<AEAD> {
    let mut full_length_key: [u8; 32] = [0; 32];
    full_length_key[(32 - key.len())..].copy_from_slice(key); // pad key with zeros

    let aes_key = aes_gcm::Key::from_slice(full_length_key.as_slice());
    let cipher = Aes256Gcm::new(aes_key);

    let mut _buf = [0u8; 12];
    let nonce = {
        OsRng.fill_bytes(&mut _buf); // provided by Rng trait
        Nonce::from_slice(&_buf.as_slice())
    };

    // reserve for later changes when a non-empty aad could be imported
    let aad: Vec<u8> = std::iter::repeat(0).take(16).collect();
    let payload = Payload {
        msg: plaintext,
        aad: &aad.as_slice(),
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .catch(exn::AesGcmException, "")?;

    Ok(AEAD {
        ciphertext: ciphertext,
        tag: nonce.to_vec(),
    })
}

pub fn aes_decrypt(key: &[u8], aead_pack: &AEAD) -> Outcome<Vec<u8>> {
    let mut full_length_key: [u8; 32] = [0; 32];
    full_length_key[(32 - key.len())..].copy_from_slice(key); // Pad key with zeros

    let aes_key = aes_gcm::Key::from_slice(full_length_key.as_slice());
    let nonce = Nonce::from_slice(&aead_pack.tag);
    let gcm = Aes256Gcm::new(aes_key);

    // reserve for later changes when a non-empty aad could be imported
    let aad: Vec<u8> = std::iter::repeat(0).take(16).collect();
    let payload = Payload {
        msg: aead_pack.ciphertext.as_slice(),
        aad: aad.as_slice(),
    };

    // NOTE: no error reported but return a value NONE when decrypt key is wrong
    let out = gcm
        .decrypt(nonce, payload)
        .catch(exn::AesGcmException, "")?;
    Ok(out)
}
