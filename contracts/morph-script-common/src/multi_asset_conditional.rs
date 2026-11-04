//! Explicit CKB conditional capability for the sole current Vault-set descriptor.
//!
//! The Batch executor is a separate capability, not a second State/Vault
//! lifecycle. Its bounded transfer parser and resolution rules are shared with
//! the Batch lock. All capability bytes belong to the signed descriptor.
use crate::{
    BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_LEN, BilateralCkbConditionalDescriptor, Result,
    ScriptError, blake2b256, read_u16, write_u16, write_u32,
};

pub const MULTI_ASSET_SETTLEMENT_ORDINARY: u8 = 0;
pub const MULTI_ASSET_SETTLEMENT_CKB_CONDITIONAL: u8 = 1;
pub const MULTI_ASSET_CONDITIONAL_VERSION: u16 = 1;
pub const MULTI_ASSET_CONDITIONAL_PREFIX_LEN: usize = 36;
pub const MULTI_ASSET_CONDITIONAL_LEN: usize =
    MULTI_ASSET_CONDITIONAL_PREFIX_LEN + BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_LEN;
pub const MULTI_ASSET_BATCH_ARGS_LEN: usize = 32 + 32 + 8 + 32;
pub const MULTI_ASSET_BATCH_SCRIPT_LEN: usize = 53 + MULTI_ASSET_BATCH_ARGS_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiAssetConditional<'a> {
    raw: &'a [u8],
    batch: BilateralCkbConditionalDescriptor<'a>,
}
impl<'a> MultiAssetConditional<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != MULTI_ASSET_CONDITIONAL_LEN
            || read_u16(raw, 0) != MULTI_ASSET_CONDITIONAL_VERSION
            || raw[2] != 0
            || !matches!(raw[3], 0 | 1 | 2 | 4)
            || raw[4..36].iter().all(|byte| *byte == 0)
        {
            return Err(ScriptError::ConditionalDescriptorEncoding);
        }
        let batch = BilateralCkbConditionalDescriptor::parse(&raw[36..])?;
        if batch.transfer_count() == 0 {
            return Err(ScriptError::ConditionalDescriptorEncoding);
        }
        Ok(Self { raw, batch })
    }
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }
    pub fn batch(&self) -> &BilateralCkbConditionalDescriptor<'a> {
        &self.batch
    }
    pub fn code_hash(&self) -> &'a [u8] {
        &self.raw[4..36]
    }
    pub fn hash_type(&self) -> u8 {
        self.raw[3]
    }
    pub fn pending_capacity(&self) -> Result<u64> {
        let mut pending = 0u64;
        for index in 0..self.batch.transfer_count() as usize {
            pending = pending
                .checked_add(self.batch.transfer(index)?.amount())
                .ok_or(ScriptError::ConditionalValueMismatch)?;
        }
        Ok(pending)
    }
    /// Canonical Molecule Script for the Batch executor. Arguments bind both
    /// the current channel/state and the complete signed Batch terms.
    pub fn batch_script(
        &self,
        channel_id: &[u8],
        funding_context_id: &[u8],
        state_number: u64,
    ) -> Result<[u8; MULTI_ASSET_BATCH_SCRIPT_LEN]> {
        if channel_id.len() != 32
            || channel_id.iter().all(|byte| *byte == 0)
            || funding_context_id.len() != 32
            || funding_context_id.iter().all(|byte| *byte == 0)
        {
            return Err(ScriptError::ConditionalBatchLockMismatch);
        }
        let mut raw = [0; MULTI_ASSET_BATCH_SCRIPT_LEN];
        write_u32(&mut raw, 0, MULTI_ASSET_BATCH_SCRIPT_LEN as u32);
        write_u32(&mut raw, 4, 16);
        write_u32(&mut raw, 8, 48);
        write_u32(&mut raw, 12, 49);
        raw[16..48].copy_from_slice(&self.raw[4..36]);
        raw[48] = self.raw[3];
        write_u32(&mut raw, 49, (MULTI_ASSET_BATCH_SCRIPT_LEN - 53) as u32);
        raw[53..85].copy_from_slice(channel_id);
        raw[85..117].copy_from_slice(funding_context_id);
        raw[117..125].copy_from_slice(&state_number.to_le_bytes());
        raw[125..].copy_from_slice(&self.batch.commitment());
        Ok(raw)
    }
    pub fn batch_lock_hash(
        &self,
        channel_id: &[u8],
        funding_context_id: &[u8],
        state_number: u64,
    ) -> Result<[u8; 32]> {
        Ok(blake2b256(&[&self.batch_script(
            channel_id,
            funding_context_id,
            state_number,
        )?]))
    }
}

pub fn encode_multi_asset_conditional(
    code_hash: &[u8; 32],
    hash_type: u8,
    batch_descriptor: &[u8],
) -> Result<[u8; MULTI_ASSET_CONDITIONAL_LEN]> {
    if batch_descriptor.len() != BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_LEN {
        return Err(ScriptError::ConditionalDescriptorEncoding);
    }
    let mut raw = [0; MULTI_ASSET_CONDITIONAL_LEN];
    write_u16(&mut raw, 0, MULTI_ASSET_CONDITIONAL_VERSION);
    raw[3] = hash_type;
    raw[4..36].copy_from_slice(code_hash);
    raw[36..].copy_from_slice(batch_descriptor);
    MultiAssetConditional::parse(&raw)?;
    Ok(raw)
}
