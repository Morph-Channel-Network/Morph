//! Asset-bound conditional capability of the sole current Vault-set descriptor.
//! One Batch per exact asset, sorted by the same identity as its Vault. Parsing
//! and resolution never add quantities across Types or borrow payout reserves.
use crate::multi_asset::{MULTI_ASSET_MAX_VAULTS, MultiAssetId};
use crate::{
    CONDITIONAL_BATCH_DESCRIPTOR_LEN, ConditionalBatchDescriptor, Result, ScriptError, blake2b256,
    read_u16, write_u16, write_u32,
};
use alloc::vec;
use alloc::vec::Vec;

pub const MULTI_ASSET_SETTLEMENT_ORDINARY: u8 = 0;
pub const MULTI_ASSET_SETTLEMENT_CONDITIONAL: u8 = 1;
pub const MULTI_ASSET_CONDITIONAL_VERSION: u16 = 2;
pub const MULTI_ASSET_CONDITIONAL_PREFIX_LEN: usize = 40;
pub const MULTI_ASSET_CONDITIONAL_MAX_LEN: usize =
    MULTI_ASSET_CONDITIONAL_PREFIX_LEN + MULTI_ASSET_MAX_VAULTS * CONDITIONAL_BATCH_DESCRIPTOR_LEN;
pub const MULTI_ASSET_BATCH_ARGS_LEN: usize = 32 + 32 + 8 + 32;
pub const MULTI_ASSET_BATCH_SCRIPT_LEN: usize = 53 + MULTI_ASSET_BATCH_ARGS_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiAssetConditional<'a> {
    raw: &'a [u8],
}

impl<'a> MultiAssetConditional<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() < MULTI_ASSET_CONDITIONAL_PREFIX_LEN
            || read_u16(raw, 0) != MULTI_ASSET_CONDITIONAL_VERSION
            || !(1..=MULTI_ASSET_MAX_VAULTS).contains(&(raw[2] as usize))
            || raw.len()
                != MULTI_ASSET_CONDITIONAL_PREFIX_LEN
                    + raw[2] as usize * CONDITIONAL_BATCH_DESCRIPTOR_LEN
            || !matches!(raw[3], 0 | 1 | 2 | 4)
            || raw[4..36].iter().all(|byte| *byte == 0)
            || raw[36..40].iter().any(|byte| *byte != 0)
        {
            return Err(ScriptError::ConditionalDescriptorEncoding);
        }
        let value = Self { raw };
        let mut previous = None;
        for index in 0..value.count() {
            let batch = value.batch(index)?;
            let asset = batch.asset()?;
            if batch.transfer_count() == 0 || previous.is_some_and(|before| before >= asset) {
                return Err(ScriptError::ConditionalDescriptorEncoding);
            }
            for earlier in 0..index {
                if value.batch(earlier)?.batch_id() == batch.batch_id() {
                    return Err(ScriptError::ConditionalDescriptorEncoding);
                }
            }
            previous = Some(asset);
        }
        Ok(value)
    }
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }
    pub fn count(&self) -> usize {
        self.raw[2] as usize
    }
    pub fn batch(&self, index: usize) -> Result<ConditionalBatchDescriptor<'a>> {
        if index >= self.count() {
            return Err(ScriptError::IndexOutOfBounds);
        }
        let offset = MULTI_ASSET_CONDITIONAL_PREFIX_LEN + index * CONDITIONAL_BATCH_DESCRIPTOR_LEN;
        ConditionalBatchDescriptor::parse(
            &self.raw[offset..offset + CONDITIONAL_BATCH_DESCRIPTOR_LEN],
        )
    }
    pub fn index_of(&self, asset: MultiAssetId) -> Result<Option<usize>> {
        for index in 0..self.count() {
            if self.batch(index)?.asset()? == asset {
                return Ok(Some(index));
            }
        }
        Ok(None)
    }
    pub fn code_hash(&self) -> &'a [u8] {
        &self.raw[4..36]
    }
    pub fn hash_type(&self) -> u8 {
        self.raw[3]
    }
    pub fn pending_amount(&self, asset: MultiAssetId) -> Result<u128> {
        match self.index_of(asset)? {
            Some(index) => self.batch(index)?.checked_pending_amount(),
            None => Ok(0),
        }
    }
    pub fn pending_capacity(&self) -> Result<u64> {
        u64::try_from(self.pending_amount(MultiAssetId::CKB)?)
            .map_err(|_| ScriptError::ConditionalValueMismatch)
    }
    /// The terms commitment includes the exact Type and all quantities.
    pub fn batch_script(
        &self,
        index: usize,
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
        let batch = self.batch(index)?;
        let mut raw = [0; MULTI_ASSET_BATCH_SCRIPT_LEN];
        write_u32(&mut raw, 0, MULTI_ASSET_BATCH_SCRIPT_LEN as u32);
        write_u32(&mut raw, 4, 16);
        write_u32(&mut raw, 8, 48);
        write_u32(&mut raw, 12, 49);
        raw[16..48].copy_from_slice(self.code_hash());
        raw[48] = self.hash_type();
        write_u32(&mut raw, 49, MULTI_ASSET_BATCH_ARGS_LEN as u32);
        raw[53..85].copy_from_slice(channel_id);
        raw[85..117].copy_from_slice(funding_context_id);
        raw[117..125].copy_from_slice(&state_number.to_le_bytes());
        raw[125..].copy_from_slice(&batch.commitment());
        Ok(raw)
    }
    pub fn batch_lock_hash(
        &self,
        index: usize,
        channel_id: &[u8],
        funding_context_id: &[u8],
        state_number: u64,
    ) -> Result<[u8; 32]> {
        Ok(blake2b256(&[&self.batch_script(
            index,
            channel_id,
            funding_context_id,
            state_number,
        )?]))
    }
}

pub fn encode_multi_asset_conditional(
    code_hash: &[u8; 32],
    hash_type: u8,
    batches: &[&[u8]],
) -> Result<Vec<u8>> {
    if !(1..=MULTI_ASSET_MAX_VAULTS).contains(&batches.len())
        || batches
            .iter()
            .any(|raw| raw.len() != CONDITIONAL_BATCH_DESCRIPTOR_LEN)
    {
        return Err(ScriptError::ConditionalDescriptorEncoding);
    }
    let mut raw = vec![
        0;
        MULTI_ASSET_CONDITIONAL_PREFIX_LEN
            + batches.len() * CONDITIONAL_BATCH_DESCRIPTOR_LEN
    ];
    write_u16(&mut raw, 0, MULTI_ASSET_CONDITIONAL_VERSION);
    raw[2] = batches.len() as u8;
    raw[3] = hash_type;
    raw[4..36].copy_from_slice(code_hash);
    for (index, batch) in batches.iter().enumerate() {
        let offset = MULTI_ASSET_CONDITIONAL_PREFIX_LEN + index * CONDITIONAL_BATCH_DESCRIPTOR_LEN;
        raw[offset..offset + CONDITIONAL_BATCH_DESCRIPTOR_LEN].copy_from_slice(batch);
    }
    MultiAssetConditional::parse(&raw)?;
    Ok(raw)
}
