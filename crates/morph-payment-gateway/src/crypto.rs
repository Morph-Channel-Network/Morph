use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::protocol::{decode_byte32, hex32};

pub const AES_GCM_NONCE_LEN: usize = 12;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid AES-256-GCM key or nonce")]
    InvalidKeyOrNonce,
    #[error("ciphertext authentication failed")]
    AuthenticationFailed,
    #[error("invalid base64 ciphertext")]
    InvalidEncoding,
    #[error("payment preimage does not match its hash")]
    InvalidPreimage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedPayload {
    /// 96-bit nonce encoded as lower-case hexadecimal with a `0x` prefix.
    pub nonce: String,
    /// AES-256-GCM ciphertext and authentication tag.
    pub ciphertext: String,
    pub plaintext_hash: String,
}

pub fn random_byte32() -> [u8; 32] {
    let mut value = [0_u8; 32];
    OsRng.fill_bytes(&mut value);
    value
}

pub fn sha256_bytes(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

pub fn sha256_hex(value: &[u8]) -> String {
    hex32(&sha256_bytes(value))
}

pub fn verify_preimage(payment_hash: &str, preimage: &str) -> Result<(), CryptoError> {
    let preimage = decode_byte32(preimage).map_err(|_| CryptoError::InvalidPreimage)?;
    let expected = decode_byte32(payment_hash).map_err(|_| CryptoError::InvalidPreimage)?;
    if sha256_bytes(&preimage) != expected {
        return Err(CryptoError::InvalidPreimage);
    }
    Ok(())
}

pub fn derive_store_key(root_secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"morph-payment-gateway-store-key-v1\0");
    hasher.update(root_secret);
    hasher.finalize().into()
}

pub fn encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<EncryptedPayload, CryptoError> {
    let mut nonce = [0_u8; AES_GCM_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = encrypt_with_nonce(key, &nonce, plaintext, associated_data)?;
    Ok(EncryptedPayload {
        nonce: format!("0x{}", hex::encode(nonce)),
        ciphertext: BASE64.encode(ciphertext),
        plaintext_hash: sha256_hex(plaintext),
    })
}

pub fn decrypt(
    key: &[u8; 32],
    payload: &EncryptedPayload,
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce = hex::decode(
        payload
            .nonce
            .strip_prefix("0x")
            .ok_or(CryptoError::InvalidKeyOrNonce)?,
    )
    .map_err(|_| CryptoError::InvalidKeyOrNonce)?;
    if nonce.len() != AES_GCM_NONCE_LEN {
        return Err(CryptoError::InvalidKeyOrNonce);
    }
    let ciphertext = BASE64
        .decode(&payload.ciphertext)
        .map_err(|_| CryptoError::InvalidEncoding)?;
    let plaintext = decrypt_with_nonce(key, &nonce, &ciphertext, associated_data)?;
    if sha256_hex(&plaintext) != payload.plaintext_hash {
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(plaintext)
}

pub(crate) fn encrypt_with_nonce(
    key: &[u8; 32],
    nonce: &[u8],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != AES_GCM_NONCE_LEN {
        return Err(CryptoError::InvalidKeyOrNonce);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyOrNonce)?;
    let nonce: [u8; AES_GCM_NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyOrNonce)?;
    cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}

pub(crate) fn decrypt_with_nonce(
    key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != AES_GCM_NONCE_LEN {
        return Err(CryptoError::InvalidKeyOrNonce);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyOrNonce)?;
    let nonce: [u8; AES_GCM_NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyOrNonce)?;
    cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Verify the hash-locked key, offer binding, AES-GCM authentication and result
/// commitment before returning an application's plaintext.
pub fn decrypt_fair_exchange(
    envelope: &crate::FairExchangeEnvelope,
    claim: &crate::FairExchangeClaim,
) -> Result<Vec<u8>, CryptoError> {
    if envelope.offer_id != claim.offer_id {
        return Err(CryptoError::AuthenticationFailed);
    }
    verify_preimage(&envelope.requirement.payment_hash, &claim.decryption_key)?;
    let key = crate::protocol::decode_byte32(&claim.decryption_key)
        .map_err(|_| CryptoError::InvalidKeyOrNonce)?;
    let associated = format!(
        "morph-fair-exchange-v1\0{}\0{}",
        envelope.offer_id, envelope.requirement.requirement_id
    );
    decrypt(
        &key,
        &EncryptedPayload {
            nonce: envelope.nonce.clone(),
            ciphertext: envelope.ciphertext.clone(),
            plaintext_hash: envelope.result_hash.clone(),
        },
        associated.as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_payload_is_bound_to_aad_and_hash() {
        let key = random_byte32();
        let encrypted = encrypt(&key, b"paid result", b"offer-1").unwrap();
        assert_eq!(
            decrypt(&key, &encrypted, b"offer-1").unwrap(),
            b"paid result"
        );
        assert!(decrypt(&key, &encrypted, b"offer-2").is_err());
    }

    #[test]
    fn payment_hash_uses_sha256_preimage() {
        let preimage = [7_u8; 32];
        verify_preimage(&sha256_hex(&preimage), &hex32(&preimage)).unwrap();
        assert!(verify_preimage(&hex32(&[0_u8; 32]), &hex32(&preimage)).is_err());
    }
}
