//! Sole bounded cooperative terminal-close frame. Ordinary votes are not close authority.
use crate::multi_asset::{
    MULTI_ASSET_MAX_WITNESS_LEN, MULTI_ASSET_STATE_HEADER_LEN, MultiAssetStateHeader,
    MultiAssetWitness, verify_multi_asset_signatures,
};
use crate::{
    BILATERAL_SIGNATURE_WITNESS_LEN, BilateralSignatureWitness, PHASE_SETTLING, Result,
    ScriptError, blake2b256, read_u16, read_u32,
};

pub const MULTI_ASSET_CLOSE_DOMAIN: &[u8] = b"CKB_MORPH_MULTI_ASSET_CLOSE_V1";
pub const MULTI_ASSET_CLOSE_MAGIC: &[u8; 8] = b"MORPHMC!";
pub const MULTI_ASSET_CLOSE_FORMAT: u16 = 1;
pub const MULTI_ASSET_CLOSE_PREFIX_LEN: usize = 16;
pub const MULTI_ASSET_CLOSE_FIXED_LEN: usize = MULTI_ASSET_CLOSE_PREFIX_LEN
    + 32
    + MULTI_ASSET_STATE_HEADER_LEN
    + BILATERAL_SIGNATURE_WITNESS_LEN;
pub const MULTI_ASSET_CLOSE_MAX_LEN: usize =
    MULTI_ASSET_CLOSE_FIXED_LEN + MULTI_ASSET_MAX_WITNESS_LEN;

/// Signatures and evidence are outside the raw transaction identity; the target
/// header commits the complete settlement evidence and original custody context.
pub fn multi_asset_close_digest(
    target: &MultiAssetStateHeader,
    tx_hash: &[u8; 32],
) -> Result<[u8; 32]> {
    if target.phase() != PHASE_SETTLING
        || target.state_number() == 0
        || !target.vaults_are_bound()
        || tx_hash.iter().all(|byte| *byte == 0)
    {
        return Err(ScriptError::MultiAssetCloseMismatch);
    }
    Ok(blake2b256(&[
        MULTI_ASSET_CLOSE_DOMAIN,
        &target.signing_digest(),
        tx_hash,
    ]))
}

#[derive(Debug, Clone, Copy)]
pub struct MultiAssetCloseWitness<'a> {
    raw: &'a [u8],
    target: MultiAssetStateHeader<'a>,
    signatures: BilateralSignatureWitness<'a>,
    evidence: MultiAssetWitness<'a>,
}

impl<'a> MultiAssetCloseWitness<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() < MULTI_ASSET_CLOSE_FIXED_LEN
            || raw.len() > MULTI_ASSET_CLOSE_MAX_LEN
            || &raw[..8] != MULTI_ASSET_CLOSE_MAGIC
            || read_u16(raw, 8) != MULTI_ASSET_CLOSE_FORMAT
            || read_u16(raw, 10) != 0
            || read_u32(raw, 12) as usize != raw.len() - MULTI_ASSET_CLOSE_FIXED_LEN
        {
            return Err(ScriptError::MultiAssetCloseEncoding);
        }
        let target_end = 48 + MULTI_ASSET_STATE_HEADER_LEN;
        let target = MultiAssetStateHeader::parse(&raw[48..target_end])?;
        let signatures =
            BilateralSignatureWitness::parse(&raw[target_end..MULTI_ASSET_CLOSE_FIXED_LEN])?;
        let evidence = MultiAssetWitness::parse(&raw[MULTI_ASSET_CLOSE_FIXED_LEN..])?;
        evidence.validate_header(&target)?;
        let frame = Self {
            raw,
            target,
            signatures,
            evidence,
        };
        multi_asset_close_digest(&target, &frame.transaction_hash())?;
        Ok(frame)
    }
    pub fn transaction_hash(&self) -> [u8; 32] {
        let mut hash = [0; 32];
        hash.copy_from_slice(&self.raw[16..48]);
        hash
    }
    pub fn target(&self) -> &MultiAssetStateHeader<'a> {
        &self.target
    }
    pub fn evidence(&self) -> &MultiAssetWitness<'a> {
        &self.evidence
    }
    pub fn validate_source(&self, source: &MultiAssetStateHeader) -> Result<()> {
        validate_multi_asset_close_source(source, &self.target)?;
        verify_multi_asset_signatures(
            source.participants_commitment(),
            &multi_asset_close_digest(&self.target, &self.transaction_hash())?,
            &self.signatures,
        )
    }
}

/// Shared source/target progress rule; authenticity still requires actual chain
/// provenance and the role-specific signatures checked by the caller.
pub fn validate_multi_asset_close_source(
    source: &MultiAssetStateHeader,
    target: &MultiAssetStateHeader,
) -> Result<()> {
    if !source.vaults_are_bound()
        || !source.same_context_except_progress(target)
        || source.state_number() > target.state_number()
        || (source.state_number() == target.state_number()
            && source.as_bytes() != target.as_bytes())
    {
        return Err(ScriptError::MultiAssetCloseMismatch);
    }
    Ok(())
}

/// The host writes this same format, into a caller-owned bounded buffer. This
/// checks encoding and commitments; source provenance and signatures are checked
/// by `validate_source` and the complete runtime verifier, never by encoding alone.
pub fn encode_multi_asset_close(
    out: &mut [u8],
    tx_hash: &[u8; 32],
    target: &[u8],
    signatures: &[u8],
    evidence: &[u8],
) -> Result<()> {
    if target.len() != MULTI_ASSET_STATE_HEADER_LEN
        || signatures.len() != BILATERAL_SIGNATURE_WITNESS_LEN
        || evidence.len() > MULTI_ASSET_MAX_WITNESS_LEN
        || out.len() != MULTI_ASSET_CLOSE_FIXED_LEN + evidence.len()
    {
        return Err(ScriptError::MultiAssetCloseEncoding);
    }
    out[..8].copy_from_slice(MULTI_ASSET_CLOSE_MAGIC);
    out[8..10].copy_from_slice(&MULTI_ASSET_CLOSE_FORMAT.to_le_bytes());
    out[10..12].fill(0);
    out[12..16].copy_from_slice(&(evidence.len() as u32).to_le_bytes());
    out[16..48].copy_from_slice(tx_hash);
    let target_end = 48 + MULTI_ASSET_STATE_HEADER_LEN;
    out[48..target_end].copy_from_slice(target);
    out[target_end..MULTI_ASSET_CLOSE_FIXED_LEN].copy_from_slice(signatures);
    out[MULTI_ASSET_CLOSE_FIXED_LEN..].copy_from_slice(evidence);
    MultiAssetCloseWitness::parse(out).map(|_| ())
}
