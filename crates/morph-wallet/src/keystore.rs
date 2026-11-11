//! Authenticated encryption, fixed bounded KDF parameters, no plaintext key serialization.
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use anyhow::{Result, anyhow, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use ckb_crypto::secp::Privkey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const SCHEMA: &str = "morph.local_wallet.v1";
const KDF: &str = "argon2id-v19-m65536-t3-p1";
const CIPHER: &str = "aes-256-gcm";
/// Only the dedicated wallet worker owns this object. Debug cannot reveal a key.
pub struct UnlockedKey(Zeroizing<[u8; 32]>);
impl std::fmt::Debug for UnlockedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UnlockedKey([REDACTED])")
    }
}
impl UnlockedKey {
    pub fn generate() -> Result<Self> {
        for _ in 0..16 {
            let mut raw = Zeroizing::new([0; 32]);
            getrandom::fill(raw.as_mut()).map_err(|_| anyhow!("wallet.random_unavailable"))?;
            if Privkey::from_slice(raw.as_slice()).pubkey().is_ok() {
                return Ok(Self(raw));
            }
        }
        Err(anyhow!("wallet.random_unavailable"))
    }
    pub fn import_file(path: &std::path::Path) -> Result<Self> {
        let secret = morph_key_input::read_secret_file(path)?;
        let mut raw = Zeroizing::new([0; 32]);
        hex::decode_to_slice(secret.trim_start_matches("0x"), raw.as_mut())?;
        Self::from_bytes(raw)
    }
    fn from_bytes(raw: Zeroizing<[u8; 32]>) -> Result<Self> {
        Privkey::from_slice(raw.as_slice())
            .pubkey()
            .map_err(|_| anyhow!("wallet.invalid_key"))?;
        Ok(Self(raw))
    }
    pub fn public_key(&self) -> Result<String> {
        let key = Privkey::from_slice(self.0.as_slice());
        Ok(hex::encode(
            key.pubkey()
                .map_err(|_| anyhow!("wallet.invalid_key"))?
                .serialize(),
        ))
    }
    pub fn lock_script(&self) -> Result<ckb_types::packed::Script> {
        morph_packages::multi_asset_funding::funding_wallet_lock(&hex::decode(self.public_key()?)?)
    }
    fn secret_cipher(&self) -> Result<Aes256Gcm> {
        let mut input = Zeroizing::new(b"MORPH_LOCAL_WALLET_INVOICE_SECRET_V1".to_vec());
        input.extend_from_slice(self.0.as_slice());
        let key = Zeroizing::new(morph_core::blake2b256(&input));
        Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| anyhow!("wallet.encryption_failed"))
    }
    pub fn new_invoice_secret(&self) -> Result<(EncryptedSecret, morph_key_input::SecretString)> {
        let mut raw = Zeroizing::new([0u8; 32]);
        getrandom::fill(raw.as_mut()).map_err(|_| anyhow!("wallet.random_unavailable"))?;
        let hash = morph_core::blake2b256(raw.as_slice());
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).map_err(|_| anyhow!("wallet.random_unavailable"))?;
        let ciphertext = self
            .secret_cipher()?
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: raw.as_slice(),
                    aad: &hash,
                },
            )
            .map_err(|_| anyhow!("wallet.encryption_failed"))?;
        Ok((
            EncryptedSecret {
                payment_hash: format!("0x{}", hex::encode(hash)),
                nonce: hex::encode(nonce),
                ciphertext: hex::encode(ciphertext),
            },
            morph_key_input::SecretString::new(format!("0x{}", hex::encode(raw.as_slice()))),
        ))
    }
    pub fn invoice_secret(
        &self,
        sealed: &EncryptedSecret,
    ) -> Result<morph_key_input::SecretString> {
        ensure!(
            sealed.payment_hash.len() == 66
                && sealed.payment_hash.starts_with("0x")
                && sealed.nonce.len() == 24
                && sealed.ciphertext.len() == 96,
            "wallet.invalid_secret"
        );
        let hash = hex::decode(&sealed.payment_hash[2..])?;
        let nonce: [u8; 12] = hex::decode(&sealed.nonce)?
            .try_into()
            .map_err(|_| anyhow!("wallet.invalid_secret"))?;
        let raw = Zeroizing::new(
            self.secret_cipher()?
                .decrypt(
                    &Nonce::from(nonce),
                    Payload {
                        msg: &hex::decode(&sealed.ciphertext)?,
                        aad: &hash,
                    },
                )
                .map_err(|_| anyhow!("wallet.invalid_secret"))?,
        );
        ensure!(
            raw.len() == 32 && morph_core::blake2b256(&raw).as_slice() == hash,
            "wallet.invalid_secret"
        );
        Ok(morph_key_input::SecretString::new(format!(
            "0x{}",
            hex::encode(raw.as_slice())
        )))
    }
    pub(crate) fn sign_digest(&self, digest: [u8; 32]) -> Result<[u8; 65]> {
        let key = Privkey::from_slice(self.0.as_slice());
        let sig = key
            .sign_recoverable(&digest.into())
            .map_err(|_| anyhow!("wallet.sign_failed"))?;
        sig.serialize()
            .try_into()
            .map_err(|_| anyhow!("wallet.sign_failed"))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedSecret {
    pub payment_hash: String,
    pub nonce: String,
    pub ciphertext: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keystore {
    pub schema: String,
    pub name: String,
    pub public_key: String,
    pub kdf: String,
    pub cipher: String,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}
impl Keystore {
    pub fn seal(name: &str, key: &UnlockedKey, password: &str) -> Result<Self> {
        ensure!(
            password.chars().count() >= 12 && password.len() <= 1024,
            "wallet.password_length"
        );
        ensure!(
            !name.trim().is_empty() && name.len() <= 128 && !name.chars().any(char::is_control),
            "wallet.name"
        );
        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut salt).map_err(|_| anyhow!("wallet.random_unavailable"))?;
        getrandom::fill(&mut nonce).map_err(|_| anyhow!("wallet.random_unavailable"))?;
        let mut store = Self {
            schema: SCHEMA.into(),
            name: name.trim().into(),
            public_key: key.public_key()?,
            kdf: KDF.into(),
            cipher: CIPHER.into(),
            salt: hex::encode(salt),
            nonce: hex::encode(nonce),
            ciphertext: String::new(),
        };
        let derived = derive(password, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(derived.as_slice())
            .map_err(|_| anyhow!("wallet.encryption_failed"))?;
        let encrypted = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: key.0.as_slice(),
                    aad: &store.aad()?,
                },
            )
            .map_err(|_| anyhow!("wallet.encryption_failed"))?;
        store.ciphertext = hex::encode(encrypted);
        Ok(store)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == SCHEMA && self.kdf == KDF && self.cipher == CIPHER,
            "wallet.unsupported_keystore"
        );
        ensure!(
            !self.name.trim().is_empty()
                && self.name.len() <= 128
                && !self.name.chars().any(char::is_control),
            "wallet.name"
        );
        ensure!(
            self.public_key.len() == 66
                && self.salt.len() == 64
                && self.nonce.len() == 24
                && self.ciphertext.len() == 96,
            "wallet.invalid_keystore"
        );
        ckb_crypto::secp::Pubkey::from_slice(&hex::decode(&self.public_key)?)
            .map_err(|_| anyhow!("wallet.invalid_keystore"))?;
        for value in [&self.salt, &self.nonce, &self.ciphertext] {
            ensure!(
                value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "wallet.invalid_keystore"
            );
        }
        Ok(())
    }
    fn aad(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            &self.schema,
            &self.name,
            &self.public_key,
            &self.kdf,
            &self.cipher,
            &self.salt,
        ))?)
    }
    pub fn unlock(&self, password: &str) -> Result<UnlockedKey> {
        self.validate()?;
        ensure!(password.len() <= 1024, "wallet.password_length");
        let salt = hex::decode(&self.salt)?;
        let nonce: [u8; 12] = hex::decode(&self.nonce)?
            .try_into()
            .map_err(|_| anyhow!("wallet.invalid_keystore"))?;
        let key = derive(password, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_slice())
            .map_err(|_| anyhow!("wallet.unlock_failed"))?;
        let clear = Zeroizing::new(
            cipher
                .decrypt(
                    &Nonce::from(nonce),
                    Payload {
                        msg: &hex::decode(&self.ciphertext)?,
                        aad: &self.aad()?,
                    },
                )
                .map_err(|_| anyhow!("wallet.unlock_failed"))?,
        );
        ensure!(clear.len() == 32, "wallet.unlock_failed");
        let mut raw = Zeroizing::new([0; 32]);
        raw.copy_from_slice(&clear);
        let unlocked = UnlockedKey::from_bytes(raw)?;
        ensure!(
            unlocked.public_key()? == self.public_key,
            "wallet.unlock_failed"
        );
        Ok(unlocked)
    }
}
fn derive(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(65536, 3, 1, Some(32)).map_err(|_| anyhow!("wallet.kdf_failed"))?;
    let mut key = Zeroizing::new([0; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|_| anyhow!("wallet.kdf_failed"))?;
    Ok(key)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keystore_authenticates_metadata_and_key_and_rejects_wrong_password() {
        let key = UnlockedKey::generate().unwrap();
        let store = Keystore::seal("本机钱包", &key, "correct test password").unwrap();
        assert_eq!(
            store
                .unlock("correct test password")
                .unwrap()
                .public_key()
                .unwrap(),
            key.public_key().unwrap()
        );
        assert!(store.unlock("incorrect password").is_err());
        let mut changed = store.clone();
        changed.name = "different wallet".into();
        assert!(changed.unlock("correct test password").is_err());
        let mut damaged = store.clone();
        damaged.kdf = "argon2-allocate-unlimited".into();
        assert!(damaged.unlock("correct test password").is_err());
        let text = serde_json::to_string(&store).unwrap();
        assert!(!text.contains(&hex::encode(key.0.as_slice())));
        assert_eq!(format!("{key:?}"), "UnlockedKey([REDACTED])");
    }
}
