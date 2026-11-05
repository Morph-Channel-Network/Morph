//! Shared public receipts and local-key matching. Receipt verification never
//! substitutes for the durable reservation held by a participant's journal.
use crate::multi_asset_packages::{canonical_hex, decode_hex};
use anyhow::{Result, anyhow, ensure};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::hazmat::PrehashVerifier};
use morph_core::{Bytes32, ParticipantSignature};
use serde::{Deserialize, Serialize};
pub(crate) const SIGNATURE_SCHEMA: &str = "morph.multi_asset_signature.v1";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignatureMessage {
    pub schema: String,
    pub signing_digest: String,
    pub pubkey: String,
    pub signature: String,
}
impl SignatureMessage {
    pub fn new(digest: &Bytes32, signature: &ParticipantSignature) -> Self {
        Self {
            schema: SIGNATURE_SCHEMA.to_string(),
            signing_digest: canonical_hex(digest),
            pubkey: canonical_hex(&signature.pubkey_sec1),
            signature: canonical_hex(&signature.signature),
        }
    }
    pub fn verify(
        &self,
        digest: &Bytes32,
        participants: &[String; 2],
    ) -> Result<ParticipantSignature> {
        ensure!(
            self.schema == SIGNATURE_SCHEMA && self.signing_digest == canonical_hex(digest),
            "signature receipt is for another target"
        );
        let signature = ParticipantSignature {
            pubkey_sec1: decode_hex(&self.pubkey, 33)?,
            signature: decode_hex(&self.signature, 64)?,
        };
        verify_participant(digest, participants, &signature)?;
        Ok(signature)
    }
}
pub(crate) fn verify_participant(
    digest: &Bytes32,
    participants: &[String; 2],
    signature: &ParticipantSignature,
) -> Result<()> {
    ensure!(
        participants.contains(&canonical_hex(&signature.pubkey_sec1)),
        "signature is not from a participant"
    );
    let key = VerifyingKey::from_sec1_bytes(&signature.pubkey_sec1)
        .map_err(|_| anyhow!("invalid participant public key"))?;
    let signature = Signature::try_from(signature.signature.as_slice())
        .map_err(|_| anyhow!("invalid participant signature encoding"))?;
    key.verify_prehash(digest, &signature)
        .map_err(|_| anyhow!("invalid participant signature"))
}
pub(crate) fn channel_signing_key(private_key: &str, expected: &[u8]) -> Result<SigningKey> {
    let raw = zeroize::Zeroizing::new(
        hex::decode(private_key.strip_prefix("0x").unwrap_or(private_key))
            .map_err(|_| anyhow!("invalid channel signing key"))?,
    );
    let key = SigningKey::from_slice(&raw).map_err(|_| anyhow!("invalid channel signing key"))?;
    ensure!(
        key.verifying_key().to_encoded_point(true).as_bytes() == expected,
        "key does not match session's local signer"
    );
    Ok(key)
}
