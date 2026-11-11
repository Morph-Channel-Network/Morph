use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use blake2b_rs::Blake2bBuilder;
use zeroize::Zeroizing;

use crate::{MAX_PAYLOAD_BYTES, Result, StoreError};

/// No key accessor or Debug implementation. Gateway owners supply their existing
/// protected storage key; raw argv/env secret input is never part of this API.
pub struct Protection(Option<Zeroizing<[u8; 32]>>);
impl Protection {
    pub fn private_plaintext() -> Self {
        Self(None)
    }
    pub fn encrypted(key: [u8; 32]) -> Self {
        Self(Some(Zeroizing::new(key)))
    }
    pub(crate) fn is_encrypted(&self) -> bool {
        self.0.is_some()
    }

    pub(crate) fn seal(
        &self,
        store: &[u8; 32],
        family: &str,
        id: &str,
        revision: u64,
        bytes: &[u8],
    ) -> Result<Vec<u8>> {
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(StoreError::Invalid);
        }
        let aad = associated_data(store, family, id, revision);
        if let Some(key) = &self.0 {
            let cipher =
                Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| StoreError::Corrupt)?;
            let mut nonce = [0; 12];
            getrandom::fill(&mut nonce).map_err(|_| StoreError::Io)?;
            let encrypted = cipher
                .encrypt(
                    &Nonce::from(nonce),
                    Payload {
                        msg: bytes,
                        aad: &aad,
                    },
                )
                .map_err(|_| StoreError::Corrupt)?;
            let mut output = nonce.to_vec();
            output.extend(encrypted);
            Ok(output)
        } else {
            let mut material = Zeroizing::new(aad);
            material.extend_from_slice(bytes);
            let hash = digest(b"morph.runtime.plaintext.v1\0", &material);
            let mut output = hash.to_vec();
            output.extend_from_slice(bytes);
            Ok(output)
        }
    }

    pub(crate) fn open(
        &self,
        store: &[u8; 32],
        family: &str,
        id: &str,
        revision: u64,
        bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if bytes.len() > MAX_PAYLOAD_BYTES + 32 {
            return Err(StoreError::Corrupt);
        }
        let aad = associated_data(store, family, id, revision);
        if let Some(key) = &self.0 {
            if bytes.len() < 28 {
                return Err(StoreError::Corrupt);
            }
            let cipher =
                Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| StoreError::Corrupt)?;
            cipher
                .decrypt(
                    &Nonce::from(
                        <[u8; 12]>::try_from(&bytes[..12]).map_err(|_| StoreError::Corrupt)?,
                    ),
                    Payload {
                        msg: &bytes[12..],
                        aad: &aad,
                    },
                )
                .map(Zeroizing::new)
                .map_err(|_| StoreError::Corrupt)
        } else {
            if bytes.len() < 32 {
                return Err(StoreError::Corrupt);
            }
            let mut material = Zeroizing::new(aad);
            material.extend_from_slice(&bytes[32..]);
            if bytes[..32] != digest(b"morph.runtime.plaintext.v1\0", &material) {
                return Err(StoreError::Corrupt);
            }
            Ok(Zeroizing::new(bytes[32..].to_vec()))
        }
    }
}

fn associated_data(store: &[u8; 32], family: &str, id: &str, revision: u64) -> Vec<u8> {
    let mut result = b"morph.runtime.payload.v1\0".to_vec();
    result.extend(store);
    result.extend((family.len() as u64).to_le_bytes());
    result.extend(family.as_bytes());
    result.extend((id.len() as u64).to_le_bytes());
    result.extend(id.as_bytes());
    result.extend(revision.to_le_bytes());
    result
}

pub(crate) fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = [0; 32];
    let mut h = Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build();
    h.update(domain);
    h.update(bytes);
    h.finalize(&mut hash);
    hash
}
