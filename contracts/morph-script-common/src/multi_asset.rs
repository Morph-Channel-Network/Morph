//! Versioned, bounded multi-Vault channel encodings. Legacy headers and
//! descriptors intentionally do not accept these encodings.

use crate::{
    BilateralSignatureWitness, MORPH_PROTOCOL_VERSION, PHASE_ACTIVE, PHASE_SETTLING, Result,
    SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B, STATE_HEADER_LEN, STATE_MODE_BILATERAL_PLAINTEXT,
    ScriptError, StateHeader, StateHeaderInput, blake2b256, encode_state_header, read_u16,
    read_u32, read_u64, read_u128, write_u16, write_u64,
};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};

pub const MULTI_ASSET_STATE_DOMAIN: &[u8] = b"CKB_MORPH_MULTI_ASSET_STATE_V1";
pub const MULTI_ASSET_VAULT_SET_DOMAIN: &[u8] = b"CKB_MORPH_MULTI_ASSET_VAULT_SET_V1";
pub const MULTI_ASSET_OUTPOINT_SET_DOMAIN: &[u8] = b"CKB_MORPH_MULTI_ASSET_OUTPOINT_SET_V1";
pub const MULTI_ASSET_DESCRIPTOR_DOMAIN: &[u8] = b"CKB_MORPH_MULTI_ASSET_DESCRIPTOR_V1";
pub const MULTI_ASSET_FUNDING_CONTEXT_DOMAIN: &[u8] = b"CKB_MORPH_MULTI_ASSET_FUNDING_CONTEXT_V1";
pub const MULTI_ASSET_STATE_LAYOUT_VERSION: u16 = 2;
pub const MULTI_ASSET_DESCRIPTOR_VERSION: u16 = 4;
pub const MULTI_ASSET_ENCODING_VERSION: u16 = 1;
/// Candidate resource bounds; release requires worst-case CKB-VM budget evidence.
pub const MULTI_ASSET_MAX_VAULTS: usize = 8;
pub const MULTI_ASSET_MAX_OUTPUTS: usize = 2 * MULTI_ASSET_MAX_VAULTS + 1;
pub const MULTI_ASSET_STATE_HEADER_LEN: usize = STATE_HEADER_LEN + 32 + 32 + 2 + 2;
pub const MULTI_ASSET_ID_LEN: usize = 33;
pub const MULTI_ASSET_ALLOCATION_LEN: usize = 32;
pub const MULTI_ASSET_VAULT_ENTRY_LEN: usize = 97;
pub const MULTI_ASSET_PAYOUT_ENTRY_LEN: usize = 97;
pub const MULTI_ASSET_DESCRIPTOR_PREFIX_LEN: usize = 100;
pub const MULTI_ASSET_OUTPOINT_LEN: usize = 36;
pub const MULTI_ASSET_WITNESS_PREFIX_LEN: usize = 28;
pub const MULTI_ASSET_MAX_SCRIPT_LEN: usize = 512;
pub const MULTI_ASSET_WITNESS_MAGIC: &[u8; 8] = b"MORPHMA!";
pub const MULTI_ASSET_VAULT_ARGS_MAGIC: &[u8; 8] = b"MORPHMV!";
pub const MULTI_ASSET_VAULT_ARGS_LEN: usize = 116;
pub const MULTI_ASSET_MAX_WITNESS_LEN: usize = MULTI_ASSET_WITNESS_PREFIX_LEN
    + 4
    + MULTI_ASSET_MAX_VAULTS * MULTI_ASSET_VAULT_ENTRY_LEN
    + MULTI_ASSET_DESCRIPTOR_PREFIX_LEN
    + MULTI_ASSET_MAX_VAULTS * MULTI_ASSET_PAYOUT_ENTRY_LEN
    + MULTI_ASSET_MAX_VAULTS * MULTI_ASSET_OUTPOINT_LEN
    + (6 + MULTI_ASSET_MAX_VAULTS) * (4 + MULTI_ASSET_MAX_SCRIPT_LEN);

fn zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn hash32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(bytes);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiAssetVaultArgs<'a> {
    raw: &'a [u8],
}

impl<'a> MultiAssetVaultArgs<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != MULTI_ASSET_VAULT_ARGS_LEN
            || &raw[..8] != MULTI_ASSET_VAULT_ARGS_MAGIC
            || read_u16(raw, 8) != MULTI_ASSET_ENCODING_VERSION
            || read_u16(raw, 10) != 0
            || zero(&raw[12..44])
            || zero(&raw[52..84])
            || zero(&raw[84..116])
        {
            return Err(ScriptError::MultiAssetEncoding);
        }
        let args = Self { raw };
        crate::validate_relative_block_since(args.finalise_since(), args.finalise_since())?;
        Ok(args)
    }
    pub fn funding_anchor(&self) -> &'a [u8] {
        &self.raw[12..44]
    }
    pub fn finalise_since(&self) -> u64 {
        read_u64(self.raw, 44)
    }
    pub fn state_type_hash(&self) -> &'a [u8] {
        &self.raw[52..84]
    }
    pub fn state_lock_hash(&self) -> &'a [u8] {
        &self.raw[84..116]
    }
}

pub fn encode_multi_asset_vault_args(
    anchor: &[u8; 32],
    since: u64,
    state_type: &[u8; 32],
    state_lock: &[u8; 32],
) -> Result<[u8; MULTI_ASSET_VAULT_ARGS_LEN]> {
    let mut raw = [0; MULTI_ASSET_VAULT_ARGS_LEN];
    raw[..8].copy_from_slice(MULTI_ASSET_VAULT_ARGS_MAGIC);
    write_u16(&mut raw, 8, MULTI_ASSET_ENCODING_VERSION);
    raw[12..44].copy_from_slice(anchor);
    write_u64(&mut raw, 44, since);
    raw[52..84].copy_from_slice(state_type);
    raw[84..116].copy_from_slice(state_lock);
    MultiAssetVaultArgs::parse(&raw)?;
    Ok(raw)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MultiAssetId {
    pub kind: u8,
    pub type_hash: [u8; 32],
}

impl MultiAssetId {
    pub const CKB: Self = Self {
        kind: 0,
        type_hash: [0; 32],
    };

    pub const fn xudt(type_hash: [u8; 32]) -> Self {
        Self { kind: 1, type_hash }
    }

    pub fn validate(&self) -> Result<()> {
        match self.kind {
            0 if zero(&self.type_hash) => Ok(()),
            1 if !zero(&self.type_hash) => Ok(()),
            _ => Err(ScriptError::MultiAssetEncoding),
        }
    }

    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() != MULTI_ASSET_ID_LEN {
            return Err(ScriptError::MultiAssetEncoding);
        }
        let asset = Self {
            kind: raw[0],
            type_hash: hash32(&raw[1..]),
        };
        asset.validate()?;
        Ok(asset)
    }

    pub fn encode(&self, raw: &mut [u8]) -> Result<()> {
        self.validate()?;
        if raw.len() != MULTI_ASSET_ID_LEN {
            return Err(ScriptError::MultiAssetEncoding);
        }
        raw[0] = self.kind;
        raw[1..].copy_from_slice(&self.type_hash);
        Ok(())
    }
}

/// CKB reserve and business value remain distinct from token quantity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MultiAssetAllocation {
    pub reserve: u64,
    pub business_ckb: u64,
    pub amount: u128,
}

impl MultiAssetAllocation {
    pub fn capacity(&self) -> Result<u64> {
        self.reserve
            .checked_add(self.business_ckb)
            .ok_or(ScriptError::MultiAssetCapacityMismatch)
    }

    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() != MULTI_ASSET_ALLOCATION_LEN {
            return Err(ScriptError::MultiAssetEncoding);
        }
        let value = Self {
            reserve: read_u64(raw, 0),
            business_ckb: read_u64(raw, 8),
            amount: read_u128(raw, 16),
        };
        value.capacity()?;
        Ok(value)
    }

    pub fn encode(&self, raw: &mut [u8]) -> Result<()> {
        self.capacity()?;
        if raw.len() != MULTI_ASSET_ALLOCATION_LEN {
            return Err(ScriptError::MultiAssetEncoding);
        }
        write_u64(raw, 0, self.reserve);
        write_u64(raw, 8, self.business_ckb);
        raw[16..].copy_from_slice(&self.amount.to_le_bytes());
        Ok(())
    }

    fn validate_for(&self, asset: MultiAssetId, vault: bool) -> Result<()> {
        let capacity = self.capacity()?;
        if ((asset.kind == 0 || capacity == 0) && self.amount != 0)
            || (capacity != 0 && self.reserve == 0)
            || (vault && (capacity == 0 || (asset.kind == 1 && self.amount == 0)))
        {
            return Err(ScriptError::MultiAssetCapacityMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiAssetVaultEntry {
    pub asset: MultiAssetId,
    pub lock_hash: [u8; 32],
    pub allocation: MultiAssetAllocation,
}

impl MultiAssetVaultEntry {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() != MULTI_ASSET_VAULT_ENTRY_LEN {
            return Err(ScriptError::MultiAssetEncoding);
        }
        let entry = Self {
            asset: MultiAssetId::parse(&raw[..33])?,
            lock_hash: hash32(&raw[33..65]),
            allocation: MultiAssetAllocation::parse(&raw[65..])?,
        };
        if zero(&entry.lock_hash) {
            return Err(ScriptError::MultiAssetEncoding);
        }
        entry.allocation.validate_for(entry.asset, true)?;
        Ok(entry)
    }

    pub fn encode(&self, raw: &mut [u8]) -> Result<()> {
        if raw.len() != MULTI_ASSET_VAULT_ENTRY_LEN {
            return Err(ScriptError::MultiAssetEncoding);
        }
        self.asset.encode(&mut raw[..33])?;
        raw[33..65].copy_from_slice(&self.lock_hash);
        self.allocation.encode(&mut raw[65..])?;
        Self::parse(raw).map(|_| ())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiAssetVaultManifest<'a> {
    raw: &'a [u8],
}

fn parse_counted(raw: &[u8], prefix: usize, entry: usize, version: u16) -> Result<usize> {
    if raw.len() < prefix || read_u16(raw, 0) != version || raw[3] != 0 {
        return Err(ScriptError::MultiAssetEncoding);
    }
    let count = raw[2] as usize;
    if !(1..=MULTI_ASSET_MAX_VAULTS).contains(&count) || raw.len() != prefix + count * entry {
        return Err(ScriptError::MultiAssetEncoding);
    }
    Ok(count)
}

impl<'a> MultiAssetVaultManifest<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        let count = parse_counted(
            raw,
            4,
            MULTI_ASSET_VAULT_ENTRY_LEN,
            MULTI_ASSET_ENCODING_VERSION,
        )?;
        let manifest = Self { raw };
        let mut previous = None;
        let mut total_capacity = 0u64;
        for i in 0..count {
            let entry = manifest.entry(i)?;
            if previous.is_some_and(|asset| asset >= entry.asset) {
                return Err(ScriptError::MultiAssetEncoding);
            }
            if entry.lock_hash != manifest.entry(0)?.lock_hash {
                return Err(ScriptError::MultiAssetEncoding);
            }
            total_capacity = total_capacity
                .checked_add(entry.allocation.capacity()?)
                .ok_or(ScriptError::MultiAssetCapacityMismatch)?;
            previous = Some(entry.asset);
        }
        Ok(manifest)
    }

    pub fn count(&self) -> usize {
        self.raw[2] as usize
    }
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }
    pub fn entry(&self, index: usize) -> Result<MultiAssetVaultEntry> {
        if index >= self.count() {
            return Err(ScriptError::IndexOutOfBounds);
        }
        let offset = 4 + index * MULTI_ASSET_VAULT_ENTRY_LEN;
        MultiAssetVaultEntry::parse(&self.raw[offset..offset + MULTI_ASSET_VAULT_ENTRY_LEN])
    }
    pub fn commitment(&self) -> [u8; 32] {
        blake2b256(&[MULTI_ASSET_VAULT_SET_DOMAIN, self.raw])
    }

    pub fn asset_registry_commitment(&self) -> Result<[u8; 32]> {
        let mut hashes = [[0u8; 32]; MULTI_ASSET_MAX_VAULTS];
        let mut count = 0;
        for i in 0..self.count() {
            let asset = self.entry(i)?.asset;
            if asset.kind == 1 {
                hashes[count] = asset.type_hash;
                count += 1;
            }
        }
        let refs: [&[u8]; MULTI_ASSET_MAX_VAULTS] = core::array::from_fn(|i| hashes[i].as_slice());
        crate::asset_registry_commitment(&refs[..count])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiAssetPayoutEntry {
    pub asset: MultiAssetId,
    pub allocations: [MultiAssetAllocation; 2],
}

impl MultiAssetPayoutEntry {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() != MULTI_ASSET_PAYOUT_ENTRY_LEN {
            return Err(ScriptError::MultiAssetEncoding);
        }
        let asset = MultiAssetId::parse(&raw[..33])?;
        let allocations = [
            MultiAssetAllocation::parse(&raw[33..65])?,
            MultiAssetAllocation::parse(&raw[65..97])?,
        ];
        for allocation in &allocations {
            allocation.validate_for(asset, false)?;
        }
        Ok(Self { asset, allocations })
    }
    pub fn encode(&self, raw: &mut [u8]) -> Result<()> {
        if raw.len() != MULTI_ASSET_PAYOUT_ENTRY_LEN {
            return Err(ScriptError::MultiAssetEncoding);
        }
        self.asset.encode(&mut raw[..33])?;
        self.allocations[0].encode(&mut raw[33..65])?;
        self.allocations[1].encode(&mut raw[65..97])?;
        Self::parse(raw).map(|_| ())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiAssetSettlementDescriptor<'a> {
    raw: &'a [u8],
}

impl<'a> MultiAssetSettlementDescriptor<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        let count = parse_counted(
            raw,
            MULTI_ASSET_DESCRIPTOR_PREFIX_LEN,
            MULTI_ASSET_PAYOUT_ENTRY_LEN,
            MULTI_ASSET_DESCRIPTOR_VERSION,
        )?;
        let descriptor = Self { raw };
        if zero(descriptor.lock_hash(0)?)
            || descriptor.lock_hash(0)? >= descriptor.lock_hash(1)?
            || zero(descriptor.carrier_refund_lock())
        {
            return Err(ScriptError::MultiAssetEncoding);
        }
        let mut previous = None;
        let mut total_capacity = 0u64;
        for i in 0..count {
            let entry = descriptor.entry(i)?;
            if previous.is_some_and(|asset| asset >= entry.asset) {
                return Err(ScriptError::MultiAssetEncoding);
            }
            for allocation in &entry.allocations {
                total_capacity = total_capacity
                    .checked_add(allocation.capacity()?)
                    .ok_or(ScriptError::MultiAssetCapacityMismatch)?;
            }
            previous = Some(entry.asset);
        }
        Ok(descriptor)
    }
    pub fn count(&self) -> usize {
        self.raw[2] as usize
    }
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }
    pub fn lock_hash(&self, participant: usize) -> Result<&'a [u8]> {
        if participant >= 2 {
            return Err(ScriptError::IndexOutOfBounds);
        }
        Ok(&self.raw[4 + participant * 32..36 + participant * 32])
    }
    pub fn carrier_refund_lock(&self) -> &'a [u8] {
        &self.raw[68..100]
    }
    pub fn entry(&self, index: usize) -> Result<MultiAssetPayoutEntry> {
        if index >= self.count() {
            return Err(ScriptError::IndexOutOfBounds);
        }
        let offset = MULTI_ASSET_DESCRIPTOR_PREFIX_LEN + index * MULTI_ASSET_PAYOUT_ENTRY_LEN;
        MultiAssetPayoutEntry::parse(&self.raw[offset..offset + MULTI_ASSET_PAYOUT_ENTRY_LEN])
    }
    pub fn commitment(&self) -> [u8; 32] {
        blake2b256(&[MULTI_ASSET_DESCRIPTOR_DOMAIN, self.raw])
    }
}

pub fn validate_multi_asset_conservation(
    manifest: &MultiAssetVaultManifest,
    descriptor: &MultiAssetSettlementDescriptor,
) -> Result<()> {
    if manifest.count() != descriptor.count() {
        return Err(ScriptError::MultiAssetConservationMismatch);
    }
    for i in 0..manifest.count() {
        let vault = manifest.entry(i)?;
        let payouts = descriptor.entry(i)?;
        let [a, b] = payouts.allocations;
        if vault.asset != payouts.asset
            || a.reserve.checked_add(b.reserve) != Some(vault.allocation.reserve)
            || a.business_ckb.checked_add(b.business_ckb) != Some(vault.allocation.business_ckb)
            || a.amount.checked_add(b.amount) != Some(vault.allocation.amount)
        {
            return Err(ScriptError::MultiAssetConservationMismatch);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiAssetStateHeader<'a> {
    raw: &'a [u8],
}

pub fn encode_multi_asset_state_header(
    base: &StateHeaderInput,
    content_root: &[u8; 32],
    outpoint_root: &[u8; 32],
    count: u16,
) -> Result<[u8; MULTI_ASSET_STATE_HEADER_LEN]> {
    let mut raw = [0; MULTI_ASSET_STATE_HEADER_LEN];
    raw[..STATE_HEADER_LEN].copy_from_slice(&encode_state_header(base));
    raw[346..378].copy_from_slice(content_root);
    raw[378..410].copy_from_slice(outpoint_root);
    write_u16(&mut raw, 410, count);
    MultiAssetStateHeader::parse(&raw)?;
    Ok(raw)
}

impl<'a> MultiAssetStateHeader<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() != MULTI_ASSET_STATE_HEADER_LEN {
            return Err(ScriptError::MultiAssetEncoding);
        }
        let header = Self { raw };
        let base = header.base()?;
        if base.protocol_version() != MORPH_PROTOCOL_VERSION
            || base.signature_scheme_id() != SIGNATURE_SCHEME_SECP256K1_ECDSA_BLAKE2B
            || base.state_layout_version() != MULTI_ASSET_STATE_LAYOUT_VERSION
            || base.descriptor_version() != MULTI_ASSET_DESCRIPTOR_VERSION
            || base.mode() != STATE_MODE_BILATERAL_PLAINTEXT
            || !matches!(base.phase(), PHASE_ACTIVE | PHASE_SETTLING)
            || !zero(base.vault_materialisation_root())
            || !zero(base.vault_outpoint_commitment())
            || base.vault_set_commitment() != header.content_root()
            || zero(header.content_root())
            || read_u16(raw, 412) != 0
            || !(1..=MULTI_ASSET_MAX_VAULTS).contains(&header.vault_count())
            || (base.phase() == PHASE_SETTLING && !header.vaults_are_bound())
        {
            return Err(ScriptError::UnsupportedProtocolProfile);
        }
        Ok(header)
    }
    pub fn base(&self) -> Result<StateHeader<'a>> {
        StateHeader::parse(&self.raw[..STATE_HEADER_LEN])
    }
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }
    pub fn content_root(&self) -> &'a [u8] {
        &self.raw[346..378]
    }
    pub fn outpoint_root(&self) -> &'a [u8] {
        &self.raw[378..410]
    }
    pub fn vault_count(&self) -> usize {
        read_u16(self.raw, 410) as usize
    }
    pub fn vaults_are_bound(&self) -> bool {
        !zero(self.outpoint_root())
    }
    pub fn signing_digest(&self) -> [u8; 32] {
        blake2b256(&[MULTI_ASSET_STATE_DOMAIN, self.raw])
    }
    pub fn funding_context_id(&self) -> Result<[u8; 32]> {
        let base = self.base()?;
        Ok(blake2b256(&[
            MULTI_ASSET_FUNDING_CONTEXT_DOMAIN,
            base.chain_id(),
            base.channel_id(),
            base.funding_anchor(),
            self.content_root(),
            self.outpoint_root(),
        ]))
    }
    pub fn is_activation_to(&self, next: &Self) -> bool {
        !self.vaults_are_bound()
            && next.vaults_are_bound()
            && self.raw[..378] == next.raw[..378]
            && self.raw[410..] == next.raw[410..]
    }
    pub fn same_context_except_progress(&self, next: &Self) -> Result<bool> {
        Ok(self.base()?.same_context_except_progress(&next.base()?)
            && self.raw[346..] == next.raw[346..])
    }
    pub fn verify_signatures(&self, witness: &BilateralSignatureWitness) -> Result<()> {
        if self.base()?.participants_commitment() != witness.participants_commitment() {
            return Err(ScriptError::ParticipantCommitmentMismatch);
        }
        let digest = self.signing_digest();
        for i in 0..2 {
            let key = VerifyingKey::from_sec1_bytes(witness.pubkey(i))
                .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
            let signature = Signature::try_from(witness.signature(i))
                .map_err(|_| ScriptError::ParticipantWitnessEncoding)?;
            key.verify_prehash(&digest, &signature)
                .map_err(|_| ScriptError::InvalidParticipantSignature)?;
        }
        Ok(())
    }
}

/// OutPoints follow canonical manifest asset order, not input/output order.
pub fn multi_asset_outpoint_set_commitment(
    content_root: &[u8],
    count: usize,
    raw: &[u8],
) -> Result<[u8; 32]> {
    if content_root.len() != 32
        || zero(content_root)
        || !(1..=MULTI_ASSET_MAX_VAULTS).contains(&count)
        || raw.len() != count * MULTI_ASSET_OUTPOINT_LEN
    {
        return Err(ScriptError::MultiAssetEncoding);
    }
    for i in 0..count {
        let point = &raw[i * 36..(i + 1) * 36];
        if zero(&point[..32]) {
            return Err(ScriptError::MultiAssetEncoding);
        }
        for j in 0..i {
            if point == &raw[j * 36..(j + 1) * 36] {
                return Err(ScriptError::MultiAssetEncoding);
            }
        }
    }
    Ok(blake2b256(&[
        MULTI_ASSET_OUTPOINT_SET_DOMAIN,
        content_root,
        &(count as u16).to_le_bytes(),
        raw,
    ]))
}

/// Canonical Molecule Script encoding: code_hash, hash_type, and Bytes args.
/// Occupied capacity excludes Molecule framing, as required by CKB.
pub fn multi_asset_script_occupied_bytes(raw: &[u8]) -> Result<u64> {
    if raw.len() < 53
        || raw.len() > MULTI_ASSET_MAX_SCRIPT_LEN
        || read_u32(raw, 0) as usize != raw.len()
        || read_u32(raw, 4) != 16
        || read_u32(raw, 8) != 48
        || read_u32(raw, 12) != 49
        || read_u32(raw, 49) as usize != raw.len() - 53
        || !matches!(raw[48], 0 | 1 | 2 | 4)
    {
        return Err(ScriptError::MultiAssetEncoding);
    }
    Ok(33 + (raw.len() - 53) as u64)
}

pub fn multi_asset_occupied_capacity(
    lock: &[u8],
    type_script: Option<&[u8]>,
    data_len: u64,
) -> Result<u64> {
    let lock_bytes = multi_asset_script_occupied_bytes(lock)?;
    let type_bytes = type_script
        .map(multi_asset_script_occupied_bytes)
        .transpose()?
        .unwrap_or(0);
    (8 + lock_bytes + type_bytes)
        .checked_add(data_len)
        .and_then(|bytes| bytes.checked_mul(100_000_000))
        .ok_or(ScriptError::MultiAssetCapacityMismatch)
}

/// Scripts are ordered: participant 0, participant 1, carrier refund, Vault,
/// State Type, State Lock, then each xUDT Type Script in manifest asset order.
/// Each has a u32 length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiAssetScripts<'a> {
    raw: &'a [u8],
    count: usize,
}

impl<'a> MultiAssetScripts<'a> {
    pub fn parse(
        raw: &'a [u8],
        manifest: &MultiAssetVaultManifest,
        descriptor: &MultiAssetSettlementDescriptor,
    ) -> Result<Self> {
        let mut typed = 0;
        for i in 0..manifest.count() {
            typed += usize::from(manifest.entry(i)?.asset.kind == 1);
        }
        let scripts = Self {
            raw,
            count: 6 + typed,
        };
        let mut offset = 0usize;
        for _ in 0..scripts.count {
            if raw.len().saturating_sub(offset) < 4 {
                return Err(ScriptError::MultiAssetEncoding);
            }
            let len = read_u32(raw, offset) as usize;
            if !(53..=MULTI_ASSET_MAX_SCRIPT_LEN).contains(&len) || raw.len() - offset - 4 < len {
                return Err(ScriptError::MultiAssetEncoding);
            }
            multi_asset_script_occupied_bytes(&raw[offset + 4..offset + 4 + len])?;
            offset += 4 + len;
        }
        if offset != raw.len() {
            return Err(ScriptError::MultiAssetEncoding);
        }
        for i in 0..2 {
            if blake2b256(&[scripts.script(i)?]) != descriptor.lock_hash(i)? {
                return Err(ScriptError::MultiAssetCommitmentMismatch);
            }
        }
        if blake2b256(&[scripts.script(2)?]) != descriptor.carrier_refund_lock() {
            return Err(ScriptError::MultiAssetCommitmentMismatch);
        }
        let vault_script = scripts.script(3)?;
        let args = MultiAssetVaultArgs::parse(&vault_script[53..])?;
        let state_type = scripts.script(4)?;
        let state_lock = scripts.script(5)?;
        let state_type_hash = blake2b256(&[state_type]);
        let state_lock_hash = blake2b256(&[state_lock]);
        if args.state_type_hash() != state_type_hash
            || args.state_lock_hash() != state_lock_hash
            || state_type[53..].len() != 40
            || &state_type[53..85] != args.funding_anchor()
            || read_u64(state_type, 85) != args.finalise_since()
            || state_lock[53..] != state_type_hash
        {
            return Err(ScriptError::MultiAssetCommitmentMismatch);
        }
        let vault_lock_hash = blake2b256(&[vault_script]);
        for i in 0..3 {
            let hash = blake2b256(&[scripts.script(i)?]);
            if hash == vault_lock_hash || hash == state_lock_hash {
                return Err(ScriptError::MultiAssetCommitmentMismatch);
            }
        }
        let mut type_index = 6;
        for i in 0..manifest.count() {
            let vault = manifest.entry(i)?;
            let payout = descriptor.entry(i)?;
            if blake2b256(&[scripts.script(3)?]) != vault.lock_hash {
                return Err(ScriptError::MultiAssetCommitmentMismatch);
            }
            let type_script = if vault.asset.kind == 1 {
                let script = scripts.script(type_index)?;
                type_index += 1;
                if blake2b256(&[script]) != vault.asset.type_hash {
                    return Err(ScriptError::MultiAssetCommitmentMismatch);
                }
                Some(script)
            } else {
                None
            };
            if multi_asset_occupied_capacity(
                scripts.script(3)?,
                type_script,
                if type_script.is_some() { 16 } else { 0 },
            )? > vault.allocation.reserve
            {
                return Err(ScriptError::MultiAssetCapacityMismatch);
            }
            for participant in 0..2 {
                let allocation = payout.allocations[participant];
                if allocation.capacity()? == 0 {
                    continue;
                }
                let payout_type = if allocation.amount != 0 {
                    type_script
                } else {
                    None
                };
                if multi_asset_occupied_capacity(
                    scripts.script(participant)?,
                    payout_type,
                    if payout_type.is_some() { 16 } else { 0 },
                )? > allocation.reserve
                {
                    return Err(ScriptError::MultiAssetCapacityMismatch);
                }
            }
        }
        Ok(scripts)
    }
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }
    pub fn script(&self, index: usize) -> Result<&'a [u8]> {
        if index >= self.count {
            return Err(ScriptError::IndexOutOfBounds);
        }
        let mut offset = 0;
        for i in 0..=index {
            let len = read_u32(self.raw, offset) as usize;
            if i == index {
                return Ok(&self.raw[offset + 4..offset + 4 + len]);
            }
            offset += 4 + len;
        }
        Err(ScriptError::IndexOutOfBounds)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiAssetWitness<'a> {
    raw: &'a [u8],
    manifest: MultiAssetVaultManifest<'a>,
    descriptor: MultiAssetSettlementDescriptor<'a>,
    outpoints: &'a [u8],
    scripts: MultiAssetScripts<'a>,
}

impl<'a> MultiAssetWitness<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() < MULTI_ASSET_WITNESS_PREFIX_LEN
            || raw.len() > MULTI_ASSET_MAX_WITNESS_LEN
            || &raw[..8] != MULTI_ASSET_WITNESS_MAGIC
            || read_u16(raw, 8) != MULTI_ASSET_ENCODING_VERSION
            || read_u16(raw, 10) != 0
            || read_u16(raw, 22) != 0
        {
            return Err(ScriptError::MultiAssetEncoding);
        }
        let manifest_end = MULTI_ASSET_WITNESS_PREFIX_LEN
            .checked_add(read_u32(raw, 12) as usize)
            .ok_or(ScriptError::MultiAssetEncoding)?;
        let descriptor_end = manifest_end
            .checked_add(read_u32(raw, 16) as usize)
            .ok_or(ScriptError::MultiAssetEncoding)?;
        let count = read_u16(raw, 20) as usize;
        let scripts_len = read_u32(raw, 24) as usize;
        if descriptor_end > raw.len()
            || count > MULTI_ASSET_MAX_VAULTS
            || raw.len() - descriptor_end != count * 36 + scripts_len
        {
            return Err(ScriptError::MultiAssetEncoding);
        }
        let manifest =
            MultiAssetVaultManifest::parse(&raw[MULTI_ASSET_WITNESS_PREFIX_LEN..manifest_end])?;
        let descriptor = MultiAssetSettlementDescriptor::parse(&raw[manifest_end..descriptor_end])?;
        validate_multi_asset_conservation(&manifest, &descriptor)?;
        let outpoints = &raw[descriptor_end..descriptor_end + count * 36];
        if count != 0 {
            if count != manifest.count() {
                return Err(ScriptError::MultiAssetVaultSetIncomplete);
            }
            multi_asset_outpoint_set_commitment(&manifest.commitment(), count, outpoints)?;
        }
        let scripts =
            MultiAssetScripts::parse(&raw[descriptor_end + count * 36..], &manifest, &descriptor)?;
        Ok(Self {
            raw,
            manifest,
            descriptor,
            outpoints,
            scripts,
        })
    }
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }
    pub fn manifest(&self) -> &MultiAssetVaultManifest<'a> {
        &self.manifest
    }
    pub fn descriptor(&self) -> &MultiAssetSettlementDescriptor<'a> {
        &self.descriptor
    }
    pub fn outpoints(&self) -> &'a [u8] {
        self.outpoints
    }
    pub fn scripts(&self) -> &MultiAssetScripts<'a> {
        &self.scripts
    }
    pub fn outpoint(&self, index: usize) -> Result<&'a [u8]> {
        if index >= self.outpoints.len() / 36 {
            return Err(ScriptError::IndexOutOfBounds);
        }
        Ok(&self.outpoints[index * 36..(index + 1) * 36])
    }
    pub fn validate_header(&self, header: &MultiAssetStateHeader) -> Result<()> {
        let base = header.base()?;
        if self.manifest.count() != header.vault_count()
            || self.manifest.commitment() != header.content_root()
            || self.manifest.asset_registry_commitment()? != base.asset_registry_commitment()
            || self.descriptor.commitment() != base.settlement_descriptor_commitment()
        {
            return Err(ScriptError::MultiAssetCommitmentMismatch);
        }
        if MultiAssetVaultArgs::parse(&self.scripts.script(3)?[53..])?.funding_anchor()
            != base.funding_anchor()
        {
            return Err(ScriptError::FundingAnchorMismatch);
        }
        if header.vaults_are_bound() {
            if multi_asset_outpoint_set_commitment(
                header.content_root(),
                header.vault_count(),
                self.outpoints,
            )? != header.outpoint_root()
            {
                return Err(ScriptError::VaultOutPointMismatch);
            }
        } else if !self.outpoints.is_empty() {
            return Err(ScriptError::VaultActivationInvalid);
        }
        Ok(())
    }
}
