//! Multi-asset funding, settlement, and complete unilateral recovery evidence.

use std::collections::BTreeMap;

use morph_script_common::multi_asset as wire;
use morph_script_common::{
    BILATERAL_SIGNATURE_WITNESS_LEN, BilateralSignatureWitness, ScriptError, write_u16,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hash::{
    MULTI_ASSET_DESCRIPTOR_DOMAIN, MULTI_ASSET_FUNDING_CONTEXT_DOMAIN,
    MULTI_ASSET_OUTPOINT_SET_DOMAIN, MULTI_ASSET_ROOT_FUNDING_DOMAIN, MULTI_ASSET_STATE_DOMAIN,
    MULTI_ASSET_VAULT_SET_DOMAIN,
};
use crate::{AssetRegistry, Bytes32, Mode, Phase, StateAuthorization, VaultAsset, blake2b256};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MultiAssetError {
    #[error("invalid multi-asset wire evidence: {0:?}")]
    Wire(ScriptError),
    #[error("incomplete or noncanonical multi-asset recovery evidence")]
    IncompleteEvidence,
    #[error("root creation requires transaction-bound funding authorization")]
    RootFundingContextRequired,
    #[error("settling recovery requires a positive state number")]
    InvalidSettlingStateNumber,
    #[error("script identity or canonical Script encoding mismatch")]
    ScriptIdentity,
    #[error("signed reserve cannot fund the required occupied capacity")]
    InsufficientReserve,
    #[error(transparent)]
    Conditional(#[from] crate::ConditionalError),
}

impl From<ScriptError> for MultiAssetError {
    fn from(error: ScriptError) -> Self {
        Self::Wire(error)
    }
}

pub type MultiAssetResult<T> = Result<T, MultiAssetError>;

pub(crate) fn wire_asset(asset: &VaultAsset) -> wire::MultiAssetId {
    match asset {
        VaultAsset::Ckb => wire::MultiAssetId::CKB,
        VaultAsset::Xudt(hash) => wire::MultiAssetId::xudt(*hash),
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiAssetValue {
    pub reserve: u64,
    pub business_ckb: u64,
    pub amount: u128,
}

impl MultiAssetValue {
    pub(crate) fn wire(self) -> wire::MultiAssetAllocation {
        wire::MultiAssetAllocation {
            reserve: self.reserve,
            business_ckb: self.business_ckb,
            amount: self.amount,
        }
    }
    pub fn capacity(self) -> MultiAssetResult<u64> {
        Ok(self.wire().capacity()?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiAssetVault {
    pub asset: VaultAsset,
    pub lock_hash: Bytes32,
    pub value: MultiAssetValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiAssetManifest {
    pub vaults: Vec<MultiAssetVault>,
}

fn check_count(count: usize) -> MultiAssetResult<()> {
    if !(1..=wire::MULTI_ASSET_MAX_VAULTS).contains(&count) {
        return Err(MultiAssetError::Wire(ScriptError::MultiAssetEncoding));
    }
    Ok(())
}

pub(crate) fn host_commitment(domain: &[u8], encoded: &[u8]) -> Bytes32 {
    let mut data = Vec::with_capacity(domain.len() + encoded.len());
    data.extend_from_slice(domain);
    data.extend_from_slice(encoded);
    blake2b256(&data)
}

impl MultiAssetManifest {
    pub fn decode(raw: &[u8]) -> MultiAssetResult<Self> {
        let manifest = wire::MultiAssetVaultManifest::parse(raw)?;
        let vaults = (0..manifest.count())
            .map(|index| {
                let entry = manifest.entry(index)?;
                Ok(MultiAssetVault {
                    asset: if entry.asset.kind == 0 {
                        VaultAsset::Ckb
                    } else {
                        VaultAsset::Xudt(entry.asset.type_hash)
                    },
                    lock_hash: entry.lock_hash,
                    value: MultiAssetValue {
                        reserve: entry.allocation.reserve,
                        business_ckb: entry.allocation.business_ckb,
                        amount: entry.allocation.amount,
                    },
                })
            })
            .collect::<MultiAssetResult<Vec<_>>>()?;
        Ok(Self { vaults })
    }
    pub fn encode(&self) -> MultiAssetResult<Vec<u8>> {
        check_count(self.vaults.len())?;
        let mut raw = vec![0; 4 + self.vaults.len() * wire::MULTI_ASSET_VAULT_ENTRY_LEN];
        write_u16(&mut raw, 0, wire::MULTI_ASSET_ENCODING_VERSION);
        raw[2] = self.vaults.len() as u8;
        for (i, vault) in self.vaults.iter().enumerate() {
            let offset = 4 + i * wire::MULTI_ASSET_VAULT_ENTRY_LEN;
            wire::MultiAssetVaultEntry {
                asset: wire_asset(&vault.asset),
                lock_hash: vault.lock_hash,
                allocation: vault.value.wire(),
            }
            .encode(&mut raw[offset..offset + wire::MULTI_ASSET_VAULT_ENTRY_LEN])?;
        }
        wire::MultiAssetVaultManifest::parse(&raw)?;
        Ok(raw)
    }
    pub fn commitment(&self) -> MultiAssetResult<Bytes32> {
        Ok(host_commitment(
            MULTI_ASSET_VAULT_SET_DOMAIN,
            &self.encode()?,
        ))
    }
    pub fn registry(&self) -> MultiAssetResult<AssetRegistry> {
        self.encode()?;
        Ok(AssetRegistry {
            xudt_types: self
                .vaults
                .iter()
                .filter_map(|vault| match vault.asset {
                    VaultAsset::Ckb => None,
                    VaultAsset::Xudt(hash) => Some(hash),
                })
                .collect(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiAssetPayout {
    pub asset: VaultAsset,
    pub values: [MultiAssetValue; 2],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiAssetSettlement {
    pub capability: MultiAssetSettlementCapability,
    pub participant_lock_hashes: [Bytes32; 2],
    pub carrier_refund_lock_hash: Bytes32,
    pub payouts: Vec<MultiAssetPayout>,
}

/// A current settlement has one explicit interpretation. Conditions use the
/// same Vault-set custody and signing engine as ordinary allocations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MultiAssetSettlementCapability {
    Ordinary,
    CkbConditional {
        batch_code_hash: Bytes32,
        batch_hash_type: u8,
        batch: Box<crate::ConditionalBatch>,
    },
}

impl MultiAssetSettlement {
    pub fn encode(&self) -> MultiAssetResult<Vec<u8>> {
        check_count(self.payouts.len())?;
        let mut raw = vec![
            0;
            wire::MULTI_ASSET_DESCRIPTOR_PREFIX_LEN
                + self.payouts.len() * wire::MULTI_ASSET_PAYOUT_ENTRY_LEN
        ];
        write_u16(&mut raw, 0, wire::MULTI_ASSET_DESCRIPTOR_VERSION);
        raw[2] = self.payouts.len() as u8;
        raw[4..36].copy_from_slice(&self.participant_lock_hashes[0]);
        raw[36..68].copy_from_slice(&self.participant_lock_hashes[1]);
        raw[68..100].copy_from_slice(&self.carrier_refund_lock_hash);
        for (i, payout) in self.payouts.iter().enumerate() {
            let offset =
                wire::MULTI_ASSET_DESCRIPTOR_PREFIX_LEN + i * wire::MULTI_ASSET_PAYOUT_ENTRY_LEN;
            wire::MultiAssetPayoutEntry {
                asset: wire_asset(&payout.asset),
                allocations: payout.values.map(MultiAssetValue::wire),
            }
            .encode(&mut raw[offset..offset + wire::MULTI_ASSET_PAYOUT_ENTRY_LEN])?;
        }
        if let MultiAssetSettlementCapability::CkbConditional {
            batch_code_hash,
            batch_hash_type,
            batch,
        } = &self.capability
        {
            use morph_script_common::multi_asset_conditional::{
                MULTI_ASSET_SETTLEMENT_CKB_CONDITIONAL, encode_multi_asset_conditional,
            };
            raw[3] = MULTI_ASSET_SETTLEMENT_CKB_CONDITIONAL;
            raw.extend_from_slice(&encode_multi_asset_conditional(
                batch_code_hash,
                *batch_hash_type,
                &batch.encode_descriptor()?,
            )?);
        }
        wire::MultiAssetSettlementDescriptor::parse(&raw)?;
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> MultiAssetResult<Self> {
        let descriptor = wire::MultiAssetSettlementDescriptor::parse(raw)?;
        let array32 = |bytes: &[u8]| {
            bytes
                .try_into()
                .map_err(|_| MultiAssetError::IncompleteEvidence)
        };
        let payouts = (0..descriptor.count())
            .map(|index| {
                let entry = descriptor.entry(index)?;
                Ok(MultiAssetPayout {
                    asset: if entry.asset.kind == 0 {
                        VaultAsset::Ckb
                    } else {
                        VaultAsset::Xudt(entry.asset.type_hash)
                    },
                    values: entry.allocations.map(|value| MultiAssetValue {
                        reserve: value.reserve,
                        business_ckb: value.business_ckb,
                        amount: value.amount,
                    }),
                })
            })
            .collect::<MultiAssetResult<Vec<_>>>()?;
        Ok(Self {
            capability: match descriptor.conditional()? {
                None => MultiAssetSettlementCapability::Ordinary,
                Some(conditional) => MultiAssetSettlementCapability::CkbConditional {
                    batch_code_hash: array32(&conditional.as_bytes()[4..36])?,
                    batch_hash_type: conditional.as_bytes()[3],
                    batch: Box::new(crate::ConditionalBatch::decode_descriptor(
                        &conditional.as_bytes()[morph_script_common::multi_asset_conditional::MULTI_ASSET_CONDITIONAL_PREFIX_LEN..],
                    )?),
                },
            },
            participant_lock_hashes: [
                array32(descriptor.lock_hash(0)?)?,
                array32(descriptor.lock_hash(1)?)?,
            ],
            carrier_refund_lock_hash: array32(descriptor.carrier_refund_lock())?,
            payouts,
        })
    }

    pub fn commitment(&self) -> MultiAssetResult<Bytes32> {
        Ok(host_commitment(
            MULTI_ASSET_DESCRIPTOR_DOMAIN,
            &self.encode()?,
        ))
    }
    pub fn validate_against(&self, manifest: &MultiAssetManifest) -> MultiAssetResult<()> {
        let encoded_manifest = manifest.encode()?;
        let encoded_descriptor = self.encode()?;
        Ok(wire::validate_multi_asset_conservation(
            &wire::MultiAssetVaultManifest::parse(&encoded_manifest)?,
            &wire::MultiAssetSettlementDescriptor::parse(&encoded_descriptor)?,
        )?)
    }

    /// The sole funding interpretation of a current descriptor. A conditional
    /// CKB transfer is funded business value awaiting resolution; it never
    /// consumes payout reserve, State carrier, another asset, or external fees.
    pub fn custody_manifest(
        &self,
        vault_lock_hash: Bytes32,
    ) -> MultiAssetResult<MultiAssetManifest> {
        let encoded = self.encode()?;
        let descriptor = wire::MultiAssetSettlementDescriptor::parse(&encoded)?;
        let pending = descriptor
            .conditional()?
            .map(|conditional| conditional.pending_capacity())
            .transpose()?
            .unwrap_or(0);
        let vaults = self
            .payouts
            .iter()
            .map(|payout| {
                let [a, b] = payout.values;
                let value = MultiAssetValue {
                    reserve: a
                        .reserve
                        .checked_add(b.reserve)
                        .ok_or(ScriptError::MultiAssetCapacityMismatch)?,
                    business_ckb: a
                        .business_ckb
                        .checked_add(b.business_ckb)
                        .and_then(|sum| {
                            sum.checked_add(if payout.asset == VaultAsset::Ckb {
                                pending
                            } else {
                                0
                            })
                        })
                        .ok_or(ScriptError::MultiAssetCapacityMismatch)?,
                    amount: a
                        .amount
                        .checked_add(b.amount)
                        .ok_or(ScriptError::MultiAssetConservationMismatch)?,
                };
                Ok(MultiAssetVault {
                    asset: payout.asset.clone(),
                    lock_hash: vault_lock_hash,
                    value,
                })
            })
            .collect::<MultiAssetResult<Vec<_>>>()?;
        let manifest = MultiAssetManifest { vaults };
        self.validate_against(&manifest)?;
        Ok(manifest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiAssetOutPoint {
    pub tx_hash: Bytes32,
    pub index: u32,
}

pub fn encode_multi_asset_outpoints(points: &[MultiAssetOutPoint]) -> MultiAssetResult<Vec<u8>> {
    if points.len() > wire::MULTI_ASSET_MAX_VAULTS {
        return Err(MultiAssetError::IncompleteEvidence);
    }
    let mut raw = Vec::with_capacity(points.len() * wire::MULTI_ASSET_OUTPOINT_LEN);
    for point in points {
        raw.extend_from_slice(&point.tx_hash);
        raw.extend_from_slice(&point.index.to_le_bytes());
    }
    Ok(raw)
}

pub fn multi_asset_outpoint_commitment(
    manifest: &MultiAssetManifest,
    points: &[MultiAssetOutPoint],
) -> MultiAssetResult<Bytes32> {
    if manifest.vaults.len() != points.len() {
        return Err(MultiAssetError::IncompleteEvidence);
    }
    let content = manifest.commitment()?;
    let raw = encode_multi_asset_outpoints(points)?;
    wire::multi_asset_outpoint_set_commitment(&content, points.len(), &raw)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&content);
    bytes.extend_from_slice(&(points.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&raw);
    Ok(host_commitment(MULTI_ASSET_OUTPOINT_SET_DOMAIN, &bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiAssetHeader {
    pub protocol_version: u16,
    pub chain_id: Bytes32,
    pub signature_scheme_id: u16,
    pub channel_id: Bytes32,
    pub funding_epoch: u64,
    pub funding_anchor: Bytes32,
    pub state_number: u64,
    pub mode: Mode,
    pub phase: Phase,
    pub participants_commitment: Bytes32,
    pub asset_registry_commitment: Bytes32,
    pub settlement_descriptor_commitment: Bytes32,
    pub descriptor_version: u16,
    pub challenge_policy_commitment: Bytes32,
    pub state_layout_version: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiAssetState {
    pub header: MultiAssetHeader,
    pub vault_content_set_root: Bytes32,
    pub vault_outpoint_set_root: Bytes32,
    pub vault_count: u16,
}

impl MultiAssetState {
    pub fn encode(&self) -> MultiAssetResult<[u8; wire::MULTI_ASSET_STATE_HEADER_LEN]> {
        let base = &self.header;
        let phase = match base.phase {
            Phase::Active => morph_script_common::PHASE_ACTIVE,
            Phase::Settling => morph_script_common::PHASE_SETTLING,
            _ => return Err(MultiAssetError::IncompleteEvidence),
        };
        Ok(wire::encode_multi_asset_state_header(
            &wire::MultiAssetStateHeaderInput {
                protocol_version: base.protocol_version,
                chain_id: base.chain_id,
                signature_scheme_id: base.signature_scheme_id,
                channel_id: base.channel_id,
                funding_epoch: base.funding_epoch,
                funding_anchor: base.funding_anchor,
                state_number: base.state_number,
                mode: match base.mode {
                    Mode::BilateralPlain => 1,
                },
                phase,
                participants_commitment: base.participants_commitment,
                asset_registry_commitment: base.asset_registry_commitment,
                settlement_descriptor_commitment: base.settlement_descriptor_commitment,
                descriptor_version: base.descriptor_version,
                challenge_policy_commitment: base.challenge_policy_commitment,
                state_layout_version: base.state_layout_version,
            },
            &self.vault_content_set_root,
            &self.vault_outpoint_set_root,
            self.vault_count,
        )?)
    }
    pub fn signing_digest(&self) -> MultiAssetResult<Bytes32> {
        Ok(host_commitment(MULTI_ASSET_STATE_DOMAIN, &self.encode()?))
    }
    pub fn root_funding_signing_digest(
        &self,
        transaction_hash: &Bytes32,
    ) -> MultiAssetResult<Bytes32> {
        if self.header.funding_epoch != 0
            || self.header.phase != Phase::Active
            || self.header.state_number != 0
            || self.vault_outpoint_set_root != [0; 32]
            || *transaction_hash == [0; 32]
        {
            return Err(MultiAssetError::Wire(ScriptError::VaultActivationInvalid));
        }
        let mut bytes = self.signing_digest()?.to_vec();
        bytes.extend_from_slice(transaction_hash);
        Ok(host_commitment(MULTI_ASSET_ROOT_FUNDING_DOMAIN, &bytes))
    }
    pub fn funding_context_id(&self) -> MultiAssetResult<Bytes32> {
        self.encode()?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.header.chain_id);
        bytes.extend_from_slice(&self.header.channel_id);
        bytes.extend_from_slice(&self.header.funding_anchor);
        bytes.extend_from_slice(&self.vault_content_set_root);
        bytes.extend_from_slice(&self.vault_outpoint_set_root);
        Ok(host_commitment(MULTI_ASSET_FUNDING_CONTEXT_DOMAIN, &bytes))
    }
    pub fn verify_authorization(&self, authorization: &StateAuthorization) -> MultiAssetResult<()> {
        let raw = self.encode()?;
        let signatures = encode_multi_asset_signatures(authorization)?;
        Ok(wire::MultiAssetStateHeader::parse(&raw)?
            .verify_signatures(&BilateralSignatureWitness::parse(&signatures)?)?)
    }
}

pub fn encode_multi_asset_signatures(
    authorization: &StateAuthorization,
) -> MultiAssetResult<[u8; BILATERAL_SIGNATURE_WITNESS_LEN]> {
    if authorization.threshold != 2 || authorization.signatures.len() != 2 {
        return Err(MultiAssetError::IncompleteEvidence);
    }
    let mut raw = [0; BILATERAL_SIGNATURE_WITNESS_LEN];
    write_u16(
        &mut raw,
        0,
        morph_script_common::BILATERAL_SIGNATURE_WITNESS_VERSION,
    );
    raw[2] = 2;
    raw[3] = 2;
    for (i, signature) in authorization.signatures.iter().enumerate() {
        if signature.pubkey_sec1.len() != 33 || signature.signature.len() != 64 {
            return Err(MultiAssetError::IncompleteEvidence);
        }
        let start = 4 + i * 97;
        raw[start..start + 33].copy_from_slice(&signature.pubkey_sec1);
        raw[start + 33..start + 97].copy_from_slice(&signature.signature);
    }
    BilateralSignatureWitness::parse(&raw)?;
    Ok(raw)
}

pub fn encode_multi_asset_witness(
    manifest: &MultiAssetManifest,
    settlement: &MultiAssetSettlement,
    points: &[MultiAssetOutPoint],
    scripts: &MultiAssetRecoveryScripts,
) -> MultiAssetResult<Vec<u8>> {
    let scripts = scripts.encode(manifest)?;
    let manifest = manifest.encode()?;
    let descriptor = settlement.encode()?;
    let outpoints = encode_multi_asset_outpoints(points)?;
    let mut raw = vec![0; wire::MULTI_ASSET_WITNESS_PREFIX_LEN];
    raw[..8].copy_from_slice(wire::MULTI_ASSET_WITNESS_MAGIC);
    write_u16(&mut raw, 8, wire::MULTI_ASSET_ENCODING_VERSION);
    raw[12..16].copy_from_slice(&(manifest.len() as u32).to_le_bytes());
    raw[16..20].copy_from_slice(&(descriptor.len() as u32).to_le_bytes());
    write_u16(&mut raw, 20, points.len() as u16);
    raw[24..28].copy_from_slice(&(scripts.len() as u32).to_le_bytes());
    raw.extend_from_slice(&manifest);
    raw.extend_from_slice(&descriptor);
    raw.extend_from_slice(&outpoints);
    raw.extend_from_slice(&scripts);
    wire::MultiAssetWitness::parse(&raw)?;
    Ok(raw)
}

/// Complete scripts are required before signing, so reserve checks use the
/// actual occupied bytes rather than a typical wallet's script size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiAssetRecoveryScripts {
    pub vault_lock: Vec<u8>,
    pub participant_locks: [Vec<u8>; 2],
    pub carrier_refund_lock: Vec<u8>,
    pub state_type: Vec<u8>,
    pub state_lock: Vec<u8>,
    pub type_scripts: Vec<MultiAssetTypeScript>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiAssetTypeScript {
    pub type_hash: Bytes32,
    pub script: Vec<u8>,
}

fn canonical_script_occupied_bytes(raw: &[u8]) -> MultiAssetResult<u64> {
    if raw.len() < 53 || raw.len() > wire::MULTI_ASSET_MAX_SCRIPT_LEN {
        return Err(MultiAssetError::ScriptIdentity);
    }
    let read = |offset| morph_script_common::read_u32(raw, offset) as usize;
    if read(0) != raw.len()
        || read(4) != 16
        || read(8) != 48
        || read(12) != 49
        || read(49) != raw.len() - 53
        || !matches!(raw[48], 0 | 1 | 2 | 4)
    {
        return Err(MultiAssetError::ScriptIdentity);
    }
    Ok(33 + (raw.len() - 53) as u64)
}

fn occupied_capacity(
    lock: &[u8],
    type_script: Option<&[u8]>,
    data_len: u64,
) -> MultiAssetResult<u64> {
    let lock_bytes = canonical_script_occupied_bytes(lock)?;
    let type_bytes = type_script
        .map(canonical_script_occupied_bytes)
        .transpose()?
        .unwrap_or(0);
    (8 + lock_bytes + type_bytes + data_len)
        .checked_mul(100_000_000)
        .ok_or(MultiAssetError::InsufficientReserve)
}

impl MultiAssetRecoveryScripts {
    pub fn encode(&self, manifest: &MultiAssetManifest) -> MultiAssetResult<Vec<u8>> {
        let registry = manifest.registry()?;
        if self.type_scripts.len() != registry.xudt_types.len()
            || !self
                .type_scripts
                .iter()
                .map(|entry| &entry.type_hash)
                .eq(registry.xudt_types.iter())
        {
            return Err(MultiAssetError::ScriptIdentity);
        }
        let mut raw = Vec::new();
        for script in self
            .participant_locks
            .iter()
            .map(Vec::as_slice)
            .chain([
                self.carrier_refund_lock.as_slice(),
                self.vault_lock.as_slice(),
                self.state_type.as_slice(),
                self.state_lock.as_slice(),
            ])
            .chain(
                self.type_scripts
                    .iter()
                    .map(|entry| entry.script.as_slice()),
            )
        {
            canonical_script_occupied_bytes(script)?;
            raw.extend_from_slice(&(script.len() as u32).to_le_bytes());
            raw.extend_from_slice(script);
        }
        Ok(raw)
    }
    pub fn validate(
        &self,
        manifest: &MultiAssetManifest,
        settlement: &MultiAssetSettlement,
        carrier_capacity: u64,
    ) -> MultiAssetResult<()> {
        settlement.validate_against(manifest)?;
        let registry = manifest.registry()?;
        self.encode(manifest)?;
        let type_scripts: BTreeMap<_, _> = self
            .type_scripts
            .iter()
            .map(|entry| (entry.type_hash, &entry.script))
            .collect();
        if type_scripts.len() != registry.xudt_types.len() {
            return Err(MultiAssetError::ScriptIdentity);
        }
        for participant in 0..2 {
            if blake2b256(&self.participant_locks[participant])
                != settlement.participant_lock_hashes[participant]
            {
                return Err(MultiAssetError::ScriptIdentity);
            }
            canonical_script_occupied_bytes(&self.participant_locks[participant])?;
        }
        if blake2b256(&self.carrier_refund_lock) != settlement.carrier_refund_lock_hash {
            return Err(MultiAssetError::ScriptIdentity);
        }
        if occupied_capacity(&self.carrier_refund_lock, None, 0)? > carrier_capacity {
            return Err(MultiAssetError::InsufficientReserve);
        }
        if occupied_capacity(
            &self.state_lock,
            Some(&self.state_type),
            wire::MULTI_ASSET_STATE_HEADER_LEN as u64,
        )? > carrier_capacity
        {
            return Err(MultiAssetError::InsufficientReserve);
        }
        for (vault, payout) in manifest.vaults.iter().zip(&settlement.payouts) {
            if blake2b256(&self.vault_lock) != vault.lock_hash {
                return Err(MultiAssetError::ScriptIdentity);
            }
            let type_script = match vault.asset {
                VaultAsset::Ckb => None,
                VaultAsset::Xudt(hash) => {
                    let script = type_scripts
                        .get(&hash)
                        .ok_or(MultiAssetError::ScriptIdentity)?;
                    if blake2b256(script) != hash {
                        return Err(MultiAssetError::ScriptIdentity);
                    }
                    Some(script.as_slice())
                }
            };
            let data_len = if type_script.is_some() { 16 } else { 0 };
            if occupied_capacity(&self.vault_lock, type_script, data_len)? > vault.value.reserve {
                return Err(MultiAssetError::InsufficientReserve);
            }
            for participant in 0..2 {
                let value = payout.values[participant];
                if value.capacity()? == 0 {
                    continue;
                }
                let payout_type = if value.amount > 0 { type_script } else { None };
                if occupied_capacity(
                    &self.participant_locks[participant],
                    payout_type,
                    if payout_type.is_some() { 16 } else { 0 },
                )? > value.reserve
                {
                    return Err(MultiAssetError::InsufficientReserve);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiAssetRecoveryPackage {
    pub state: MultiAssetState,
    pub authorization: StateAuthorization,
    pub manifest: MultiAssetManifest,
    pub settlement: MultiAssetSettlement,
    pub outpoints: Vec<MultiAssetOutPoint>,
    pub scripts: MultiAssetRecoveryScripts,
    pub state_carrier_capacity: u64,
}

impl MultiAssetRecoveryPackage {
    /// Decode the current wire profile into validated host objects. No older
    /// layouts or unsigned recovery packages are accepted.
    pub fn decode(
        header: &[u8],
        witness: &[u8],
        signatures: &[u8],
        carrier: u64,
    ) -> MultiAssetResult<Self> {
        let mut package = Self::decode_contents(header, witness, carrier)?;
        let signatures = BilateralSignatureWitness::parse(signatures)?;
        package.authorization.signatures = (0..2)
            .map(|index| crate::ParticipantSignature {
                pubkey_sec1: signatures.pubkey(index).to_vec(),
                signature: signatures.signature(index).to_vec(),
            })
            .collect();
        package.validate()?;
        Ok(package)
    }

    /// Decode unsigned proposal evidence only. Never use this as authenticated
    /// recovery evidence; `decode` and `validate` require complete signatures.
    pub fn decode_contents(header: &[u8], witness: &[u8], carrier: u64) -> MultiAssetResult<Self> {
        fn bytes32(bytes: &[u8]) -> MultiAssetResult<Bytes32> {
            bytes
                .try_into()
                .map_err(|_| MultiAssetError::IncompleteEvidence)
        }
        let state = wire::MultiAssetStateHeader::parse(header)?;
        let base = state;
        let evidence = wire::MultiAssetWitness::parse(witness)?;
        evidence.validate_header(&state)?;
        let vaults = MultiAssetManifest::decode(evidence.manifest().as_bytes())?.vaults;
        let mut type_index = 6;
        let type_scripts = vaults
            .iter()
            .filter_map(|vault| match vault.asset {
                VaultAsset::Ckb => None,
                VaultAsset::Xudt(type_hash) => {
                    let result = evidence
                        .scripts()
                        .script(type_index)
                        .map(|script| MultiAssetTypeScript {
                            type_hash,
                            script: script.to_vec(),
                        })
                        .map_err(MultiAssetError::from);
                    type_index += 1;
                    Some(result)
                }
            })
            .collect::<MultiAssetResult<Vec<_>>>()?;
        let outpoints = evidence
            .outpoints()
            .chunks_exact(36)
            .map(|raw| {
                Ok(MultiAssetOutPoint {
                    tx_hash: bytes32(&raw[..32])?,
                    index: u32::from_le_bytes(
                        raw[32..]
                            .try_into()
                            .map_err(|_| MultiAssetError::IncompleteEvidence)?,
                    ),
                })
            })
            .collect::<MultiAssetResult<Vec<_>>>()?;
        let package = Self {
            state: MultiAssetState {
                header: MultiAssetHeader {
                    protocol_version: base.protocol_version(),
                    chain_id: bytes32(base.chain_id())?,
                    signature_scheme_id: base.signature_scheme_id(),
                    channel_id: bytes32(base.channel_id())?,
                    funding_epoch: base.funding_epoch(),
                    funding_anchor: bytes32(base.funding_anchor())?,
                    state_number: base.state_number(),
                    mode: Mode::BilateralPlain,
                    phase: if base.phase() == morph_script_common::PHASE_ACTIVE {
                        Phase::Active
                    } else {
                        Phase::Settling
                    },
                    participants_commitment: bytes32(base.participants_commitment())?,
                    asset_registry_commitment: bytes32(base.asset_registry_commitment())?,
                    settlement_descriptor_commitment: bytes32(
                        base.settlement_descriptor_commitment(),
                    )?,
                    descriptor_version: base.descriptor_version(),
                    challenge_policy_commitment: bytes32(base.challenge_policy_commitment())?,
                    state_layout_version: base.state_layout_version(),
                },
                vault_content_set_root: bytes32(state.content_root())?,
                vault_outpoint_set_root: bytes32(state.outpoint_root())?,
                vault_count: state.vault_count() as u16,
            },
            authorization: StateAuthorization {
                threshold: 2,
                signatures: vec![],
            },
            manifest: MultiAssetManifest { vaults },
            settlement: MultiAssetSettlement::decode(evidence.descriptor().as_bytes())?,
            outpoints,
            scripts: MultiAssetRecoveryScripts {
                participant_locks: [
                    evidence.scripts().script(0)?.to_vec(),
                    evidence.scripts().script(1)?.to_vec(),
                ],
                carrier_refund_lock: evidence.scripts().script(2)?.to_vec(),
                vault_lock: evidence.scripts().script(3)?.to_vec(),
                state_type: evidence.scripts().script(4)?.to_vec(),
                state_lock: evidence.scripts().script(5)?.to_vec(),
                type_scripts,
            },
            state_carrier_capacity: carrier,
        };
        package.validate_contents()?;
        Ok(package)
    }

    pub fn validate(&self) -> MultiAssetResult<()> {
        self.validate_contents()?;
        if self.state.header.funding_epoch == 0 && self.outpoints.is_empty() {
            return Err(MultiAssetError::RootFundingContextRequired);
        }
        self.state.verify_authorization(&self.authorization)
    }

    /// Verify all evidence except participant signatures. Used before a signer
    /// authorises a proposed state; never sufficient for a recovery package.
    pub fn validate_contents(&self) -> MultiAssetResult<()> {
        if self.state.header.phase == Phase::Settling && self.state.header.state_number == 0 {
            return Err(MultiAssetError::InvalidSettlingStateNumber);
        }
        let raw = self.state.encode()?;
        let header = wire::MultiAssetStateHeader::parse(&raw)?;
        let evidence = encode_multi_asset_witness(
            &self.manifest,
            &self.settlement,
            &self.outpoints,
            &self.scripts,
        )?;
        wire::MultiAssetWitness::parse(&evidence)?.validate_header(&header)?;
        self.scripts.validate(
            &self.manifest,
            &self.settlement,
            self.state_carrier_capacity,
        )
    }
}
