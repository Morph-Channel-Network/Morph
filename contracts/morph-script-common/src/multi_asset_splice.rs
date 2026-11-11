//! Canonical multi-asset re-anchor authorizations and independent value lanes.
use crate::multi_asset::{
    MULTI_ASSET_MAX_VAULTS, MultiAssetAllocation, MultiAssetId, MultiAssetStateHeader,
    MultiAssetVaultManifest, verify_multi_asset_signatures,
};
use crate::{
    BilateralSignatureWitness, PHASE_ACTIVE, Result, ScriptError, blake2b256, read_u16, write_u16,
};

pub const MULTI_ASSET_SPLICE_DOMAIN: &[u8] = b"CKB_MORPH_MULTI_ASSET_SPLICE_V1";
pub const MULTI_ASSET_SPLICE_FLOW_DOMAIN: &[u8] = b"CKB_MORPH_MULTI_ASSET_SPLICE_FLOW_V1";
pub const MULTI_ASSET_SPLICE_FORMAT: u16 = 1;
pub const MULTI_ASSET_SPLICE_HEADER_LEN: usize = 200;
pub const MULTI_ASSET_SPLICE_FLOW_LEN: usize = 97;
pub const MULTI_ASSET_SPLICE_MAX_FLOWS: usize = 2 * MULTI_ASSET_MAX_VAULTS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiAssetSpliceFlow {
    pub asset: MultiAssetId,
    pub deposit: MultiAssetAllocation,
    pub withdrawal: MultiAssetAllocation,
}

impl MultiAssetSpliceFlow {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() != MULTI_ASSET_SPLICE_FLOW_LEN {
            return Err(ScriptError::MultiAssetSpliceEncoding);
        }
        let flow = Self {
            asset: MultiAssetId::parse(&raw[..33])?,
            deposit: MultiAssetAllocation::parse(&raw[33..65])?,
            withdrawal: MultiAssetAllocation::parse(&raw[65..97])?,
        };
        if flow.asset.kind == 0 && flow.deposit.amount != 0 {
            return Err(ScriptError::MultiAssetSpliceEncoding);
        }
        flow.withdrawal.validate_for(flow.asset, false)?;
        Ok(flow)
    }
    pub fn encode(&self, raw: &mut [u8]) -> Result<()> {
        if raw.len() != MULTI_ASSET_SPLICE_FLOW_LEN {
            return Err(ScriptError::MultiAssetSpliceEncoding);
        }
        self.asset.encode(&mut raw[..33])?;
        self.deposit.encode(&mut raw[33..65])?;
        self.withdrawal.encode(&mut raw[65..97])?;
        Self::parse(raw).map(|_| ())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MultiAssetSpliceFlows<'a> {
    raw: &'a [u8],
}
impl<'a> MultiAssetSpliceFlows<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() < 4 || read_u16(raw, 2) != 0 {
            return Err(ScriptError::MultiAssetSpliceEncoding);
        }
        let count = read_u16(raw, 0) as usize;
        if !(1..=MULTI_ASSET_SPLICE_MAX_FLOWS).contains(&count)
            || raw.len() != 4 + count * MULTI_ASSET_SPLICE_FLOW_LEN
        {
            return Err(ScriptError::MultiAssetSpliceEncoding);
        }
        let flows = Self { raw };
        let mut previous = None;
        for index in 0..count {
            let flow = flows.entry(index)?;
            if previous.is_some_and(|asset| asset >= flow.asset) {
                return Err(ScriptError::MultiAssetSpliceEncoding);
            }
            previous = Some(flow.asset);
        }
        Ok(flows)
    }
    pub fn count(&self) -> usize {
        read_u16(self.raw, 0) as usize
    }
    pub fn entry(&self, index: usize) -> Result<MultiAssetSpliceFlow> {
        if index >= self.count() {
            return Err(ScriptError::IndexOutOfBounds);
        }
        let offset = 4 + index * MULTI_ASSET_SPLICE_FLOW_LEN;
        MultiAssetSpliceFlow::parse(&self.raw[offset..offset + MULTI_ASSET_SPLICE_FLOW_LEN])
    }
    pub fn commitment(&self) -> [u8; 32] {
        blake2b256(&[MULTI_ASSET_SPLICE_FLOW_DOMAIN, self.raw])
    }
    pub fn has_withdrawals(&self) -> Result<bool> {
        for index in 0..self.count() {
            if self.entry(index)?.withdrawal != MultiAssetAllocation::default() {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub fn validate_conservation(
        &self,
        old: &MultiAssetVaultManifest,
        new: &MultiAssetVaultManifest,
    ) -> Result<()> {
        let (mut before, mut after) = (0, 0);
        let (mut input_capacity, mut output_capacity) = (0u64, 0u64);
        for index in 0..self.count() {
            let left = if before < old.count() {
                Some(old.entry(before)?)
            } else {
                None
            };
            let right = if after < new.count() {
                Some(new.entry(after)?)
            } else {
                None
            };
            let expected = match (left, right) {
                (Some(a), Some(b)) => a.asset.min(b.asset),
                (Some(a), None) => a.asset,
                (None, Some(b)) => b.asset,
                (None, None) => return Err(ScriptError::MultiAssetSpliceMismatch),
            };
            let flow = self.entry(index)?;
            if flow.asset != expected {
                return Err(ScriptError::MultiAssetSpliceMismatch);
            }
            let a = if let Some(entry) = left.filter(|entry| entry.asset == expected) {
                before += 1;
                entry.allocation
            } else {
                MultiAssetAllocation::default()
            };
            let b = if let Some(entry) = right.filter(|entry| entry.asset == expected) {
                after += 1;
                entry.allocation
            } else {
                MultiAssetAllocation::default()
            };
            input_capacity = input_capacity
                .checked_add(a.capacity()?)
                .and_then(|total| total.checked_add(flow.deposit.capacity().ok()?))
                .ok_or(ScriptError::MultiAssetCapacityMismatch)?;
            output_capacity = output_capacity
                .checked_add(b.capacity()?)
                .and_then(|total| total.checked_add(flow.withdrawal.capacity().ok()?))
                .ok_or(ScriptError::MultiAssetCapacityMismatch)?;
            if a.reserve
                .checked_add(flow.deposit.reserve)
                .is_none_or(|total| b.reserve.checked_add(flow.withdrawal.reserve) != Some(total))
                || a.business_ckb
                    .checked_add(flow.deposit.business_ckb)
                    .is_none_or(|total| {
                        b.business_ckb.checked_add(flow.withdrawal.business_ckb) != Some(total)
                    })
                || a.amount
                    .checked_add(flow.deposit.amount)
                    .is_none_or(|total| b.amount.checked_add(flow.withdrawal.amount) != Some(total))
            {
                return Err(ScriptError::MultiAssetConservationMismatch);
            }
        }
        if before != old.count() || after != new.count() || input_capacity != output_capacity {
            return Err(ScriptError::MultiAssetSpliceMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MultiAssetSpliceHeader<'a> {
    raw: &'a [u8],
}
impl<'a> MultiAssetSpliceHeader<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != MULTI_ASSET_SPLICE_HEADER_LEN
            || read_u16(raw, 0) != MULTI_ASSET_SPLICE_FORMAT
            || read_u16(raw, 2) != 0
            || [
                &raw[4..36],
                &raw[36..68],
                &raw[72..104],
                &raw[104..136],
                &raw[168..200],
            ]
            .iter()
            .any(|field| field.iter().all(|byte| *byte == 0))
        {
            return Err(ScriptError::MultiAssetSpliceEncoding);
        }
        Ok(Self { raw })
    }
    pub fn old_context(&self) -> &'a [u8] {
        &self.raw[4..36]
    }
    pub fn old_state_outpoint(&self) -> &'a [u8] {
        &self.raw[36..72]
    }
    pub fn new_state_digest(&self) -> &'a [u8] {
        &self.raw[72..104]
    }
    pub fn flow_commitment(&self) -> &'a [u8] {
        &self.raw[104..136]
    }
    pub fn withdrawal_lock_hash(&self) -> &'a [u8] {
        &self.raw[136..168]
    }
    pub fn transaction_hash(&self) -> &'a [u8] {
        &self.raw[168..200]
    }
    pub fn signing_digest(&self) -> [u8; 32] {
        blake2b256(&[MULTI_ASSET_SPLICE_DOMAIN, self.raw])
    }
    pub fn verify_signatures(
        &self,
        participants: &[u8],
        witness: &BilateralSignatureWitness,
    ) -> Result<()> {
        verify_multi_asset_signatures(participants, &self.signing_digest(), witness)
    }
    pub fn new_funding_anchor(&self) -> [u8; 32] {
        // Canonical State input zero with since zero; new State is output zero.
        blake2b256(&[&[0; 8], self.old_state_outpoint(), &[0; 8]])
    }
    pub fn validate_transition(
        &self,
        old: &MultiAssetStateHeader,
        new: &MultiAssetStateHeader,
        before: &MultiAssetVaultManifest,
        after: &MultiAssetVaultManifest,
        flows: &MultiAssetSpliceFlows,
    ) -> Result<()> {
        if !old.vaults_are_bound()
            || new.vaults_are_bound()
            || new.phase() != PHASE_ACTIVE
            || new.state_number() != 0
            || old.chain_id() != new.chain_id()
            || old.channel_id() != new.channel_id()
            || old.funding_epoch().checked_add(1) != Some(new.funding_epoch())
            || old.participants_commitment() != new.participants_commitment()
            || old.challenge_policy_commitment() != new.challenge_policy_commitment()
            || old.funding_context_id()? != self.old_context()
            || self.new_funding_anchor() != new.funding_anchor()
            || new.signing_digest() != self.new_state_digest()
            || flows.commitment() != self.flow_commitment()
            || before.commitment() != old.content_root()
            || after.commitment() != new.content_root()
            || before.count() != old.vault_count()
            || after.count() != new.vault_count()
            || before.asset_registry_commitment()? != old.asset_registry_commitment()
            || after.asset_registry_commitment()? != new.asset_registry_commitment()
            || flows.has_withdrawals()? == self.withdrawal_lock_hash().iter().all(|byte| *byte == 0)
        {
            return Err(ScriptError::MultiAssetSpliceMismatch);
        }
        flows.validate_conservation(before, after)
    }
}

pub fn encode_multi_asset_splice_header(
    old_context: &[u8; 32],
    old_state: &[u8; 36],
    new_digest: &[u8; 32],
    flow_root: &[u8; 32],
    withdrawal_lock: &[u8; 32],
    transaction_hash: &[u8; 32],
) -> Result<[u8; MULTI_ASSET_SPLICE_HEADER_LEN]> {
    let mut raw = [0; MULTI_ASSET_SPLICE_HEADER_LEN];
    write_u16(&mut raw, 0, MULTI_ASSET_SPLICE_FORMAT);
    raw[4..36].copy_from_slice(old_context);
    raw[36..72].copy_from_slice(old_state);
    raw[72..104].copy_from_slice(new_digest);
    raw[104..136].copy_from_slice(flow_root);
    raw[136..168].copy_from_slice(withdrawal_lock);
    raw[168..200].copy_from_slice(transaction_hash);
    MultiAssetSpliceHeader::parse(&raw)?;
    Ok(raw)
}

pub const MULTI_ASSET_SPLICE_MAGIC: &[u8; 8] = b"MORPHMS!";
pub const MULTI_ASSET_SPLICE_PREFIX_LEN: usize = 32;
pub const MULTI_ASSET_SPLICE_MAX_WITNESS_LEN: usize = MULTI_ASSET_SPLICE_PREFIX_LEN
    + MULTI_ASSET_SPLICE_HEADER_LEN
    + crate::multi_asset::MULTI_ASSET_STATE_HEADER_LEN
    + crate::BILATERAL_SIGNATURE_WITNESS_LEN
    + 4
    + MULTI_ASSET_MAX_VAULTS * 97
    + MULTI_ASSET_MAX_VAULTS * 36
    + crate::multi_asset::MULTI_ASSET_MAX_WITNESS_LEN
    + crate::multi_asset::MULTI_ASSET_MAX_SCRIPT_LEN
    + 4
    + MULTI_ASSET_SPLICE_MAX_FLOWS * 97;

/// One current shape, with independently committed old provenance, new
/// creation evidence and flows. New-State signatures occupy input_type.
#[derive(Debug, Clone, Copy)]
pub struct MultiAssetSpliceWitness<'a> {
    header: MultiAssetSpliceHeader<'a>,
    new_header: MultiAssetStateHeader<'a>,
    signatures: BilateralSignatureWitness<'a>,
    old_manifest: MultiAssetVaultManifest<'a>,
    old_outpoints: &'a [u8],
    new_evidence: crate::multi_asset::MultiAssetWitness<'a>,
    withdrawal_script: &'a [u8],
    flows: MultiAssetSpliceFlows<'a>,
}
impl<'a> MultiAssetSpliceWitness<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        use crate::multi_asset::{
            MULTI_ASSET_MAX_SCRIPT_LEN, MULTI_ASSET_STATE_HEADER_LEN, MultiAssetWitness,
        };
        if raw.len() < MULTI_ASSET_SPLICE_PREFIX_LEN
            || raw.len() > MULTI_ASSET_SPLICE_MAX_WITNESS_LEN
            || &raw[..8] != MULTI_ASSET_SPLICE_MAGIC
            || read_u16(raw, 8) != MULTI_ASSET_SPLICE_FORMAT
            || read_u16(raw, 10) != 0
            || read_u16(raw, 18) != 0
        {
            return Err(ScriptError::MultiAssetSpliceEncoding);
        }
        let old_len = crate::read_u32(raw, 12) as usize;
        let count = read_u16(raw, 16) as usize;
        let new_len = crate::read_u32(raw, 20) as usize;
        let withdrawal_len = crate::read_u32(raw, 24) as usize;
        let flows_len = crate::read_u32(raw, 28) as usize;
        if !(1..=MULTI_ASSET_MAX_VAULTS).contains(&count)
            || withdrawal_len > MULTI_ASSET_MAX_SCRIPT_LEN
        {
            return Err(ScriptError::MultiAssetSpliceEncoding);
        }
        let mut offset = MULTI_ASSET_SPLICE_PREFIX_LEN;
        fn take<'b>(raw: &'b [u8], offset: &mut usize, len: usize) -> Result<&'b [u8]> {
            let end = offset
                .checked_add(len)
                .ok_or(ScriptError::MultiAssetSpliceEncoding)?;
            let data = raw
                .get(*offset..end)
                .ok_or(ScriptError::MultiAssetSpliceEncoding)?;
            *offset = end;
            Ok(data)
        }
        let header =
            MultiAssetSpliceHeader::parse(take(raw, &mut offset, MULTI_ASSET_SPLICE_HEADER_LEN)?)?;
        let new_header =
            MultiAssetStateHeader::parse(take(raw, &mut offset, MULTI_ASSET_STATE_HEADER_LEN)?)?;
        let signatures = BilateralSignatureWitness::parse(take(
            raw,
            &mut offset,
            crate::BILATERAL_SIGNATURE_WITNESS_LEN,
        )?)?;
        let old_manifest = MultiAssetVaultManifest::parse(take(raw, &mut offset, old_len)?)?;
        let old_outpoints = take(raw, &mut offset, count * 36)?;
        let new_evidence = MultiAssetWitness::parse(take(raw, &mut offset, new_len)?)?;
        let withdrawal_script = take(raw, &mut offset, withdrawal_len)?;
        let flows = MultiAssetSpliceFlows::parse(take(raw, &mut offset, flows_len)?)?;
        if offset != raw.len()
            || old_manifest.count() != count
            || new_header.vaults_are_bound()
            || header.new_state_digest() != new_header.signing_digest()
            || header.flow_commitment() != flows.commitment()
        {
            return Err(ScriptError::MultiAssetSpliceMismatch);
        }
        new_evidence.validate_header(&new_header)?;
        if withdrawal_script.is_empty() {
            if flows.has_withdrawals()?
                || header.withdrawal_lock_hash().iter().any(|byte| *byte != 0)
            {
                return Err(ScriptError::MultiAssetSpliceMismatch);
            }
        } else {
            crate::multi_asset::multi_asset_script_occupied_bytes(withdrawal_script)?;
            if !flows.has_withdrawals()?
                || blake2b256(&[withdrawal_script]) != header.withdrawal_lock_hash()
            {
                return Err(ScriptError::MultiAssetSpliceMismatch);
            }
        }
        Ok(Self {
            header,
            new_header,
            signatures,
            old_manifest,
            old_outpoints,
            new_evidence,
            withdrawal_script,
            flows,
        })
    }
    pub fn header(&self) -> &MultiAssetSpliceHeader<'a> {
        &self.header
    }
    pub fn new_header(&self) -> &MultiAssetStateHeader<'a> {
        &self.new_header
    }
    pub fn signatures(&self) -> &BilateralSignatureWitness<'a> {
        &self.signatures
    }
    pub fn old_manifest(&self) -> &MultiAssetVaultManifest<'a> {
        &self.old_manifest
    }
    pub fn old_outpoints(&self) -> &'a [u8] {
        self.old_outpoints
    }
    pub fn new_evidence(&self) -> &crate::multi_asset::MultiAssetWitness<'a> {
        &self.new_evidence
    }
    pub fn withdrawal_script(&self) -> &'a [u8] {
        self.withdrawal_script
    }
    pub fn flows(&self) -> &MultiAssetSpliceFlows<'a> {
        &self.flows
    }
    pub fn validate_old_header(&self, old: &MultiAssetStateHeader) -> Result<()> {
        self.validate_old_context(old)?;
        self.header
            .verify_signatures(old.participants_commitment(), &self.signatures)
    }
    pub fn validate_old_context(&self, old: &MultiAssetStateHeader) -> Result<()> {
        self.header.validate_transition(
            old,
            &self.new_header,
            &self.old_manifest,
            self.new_evidence.manifest(),
            &self.flows,
        )?;
        if crate::multi_asset::multi_asset_outpoint_set_commitment(
            old.content_root(),
            self.old_manifest.count(),
            self.old_outpoints,
        )? != old.outpoint_root()
        {
            return Err(ScriptError::VaultOutPointMismatch);
        }
        Ok(())
    }
}
