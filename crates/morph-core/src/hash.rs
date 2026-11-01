use blake2b_rs::Blake2bBuilder;

use crate::types::{
    AssetRegistry, Bytes32, FactorySpliceHeader, FactorySpliceKind, FactoryVaultDelta,
    FactoryVaultDescriptor, Mode, Phase, SpliceAssetDelta, SpliceHeader, SpliceKind, StateHeader,
    VaultAsset, VaultDescriptor,
};

pub const STATE_DOMAIN: &[u8] = b"CKB_MORPH_CHANNEL_STATE";
pub const FUNDING_CONTEXT_DOMAIN: &[u8] = b"CKB_MORPH_FUNDING_CONTEXT";
pub const PARTICIPANTS_DOMAIN: &[u8] = b"CKB_MORPH_PARTICIPANTS";
pub const SPLICE_HEADER_DOMAIN: &[u8] = b"CKB_MORPH_SPLICE_HEADER";
pub const SPLICE_DELTA_DOMAIN: &[u8] = b"CKB_MORPH_SPLICE_DELTA";
pub const VAULT_DESCRIPTOR_DOMAIN: &[u8] = b"CKB_MORPH_VAULT_DESCRIPTOR";
pub const FACTORY_SPLICE_HEADER_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_SPLICE_HEADER";
pub const FACTORY_VAULT_DESCRIPTOR_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_VAULT_DESCRIPTOR";
pub const FACTORY_VAULT_DELTA_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_VAULT_DELTA";
pub const VAULT_OUTPOINT_COMMITMENT_DOMAIN: &[u8] = b"CKB_MORPH_VAULT_OUTPOINT_V1";
pub const MULTI_ASSET_STATE_DOMAIN: &[u8] = b"CKB_MORPH_MULTI_ASSET_STATE_V1";
pub const MULTI_ASSET_VAULT_SET_DOMAIN: &[u8] = b"CKB_MORPH_MULTI_ASSET_VAULT_SET_V1";
pub const MULTI_ASSET_OUTPOINT_SET_DOMAIN: &[u8] = b"CKB_MORPH_MULTI_ASSET_OUTPOINT_SET_V1";
pub const MULTI_ASSET_DESCRIPTOR_DOMAIN: &[u8] = b"CKB_MORPH_MULTI_ASSET_DESCRIPTOR_V1";
pub const MULTI_ASSET_FUNDING_CONTEXT_DOMAIN: &[u8] = b"CKB_MORPH_MULTI_ASSET_FUNDING_CONTEXT_V1";

pub trait SigningBytes {
    fn encode_signing_bytes(&self, out: &mut Vec<u8>);
}

pub fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut hasher = Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build();
    hasher.update(data);
    hasher.finalize(&mut out);
    out
}

pub fn participants_commitment(threshold: u8, pubkeys: &[&[u8]]) -> Bytes32 {
    let mut out = [0u8; 32];
    let mut hasher = Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build();
    hasher.update(PARTICIPANTS_DOMAIN);
    hasher.update(&[threshold]);
    hasher.update(&[pubkeys.len() as u8]);
    for pubkey in pubkeys {
        hasher.update(pubkey);
    }
    hasher.finalize(&mut out);
    out
}

/// Commits to the complete, canonically ordered xUDT allow-list.
///
/// `AssetRegistry` uses a `BTreeSet`, so equal registries have one encoding
/// regardless of insertion order.
pub fn asset_registry_commitment(registry: &AssetRegistry) -> Bytes32 {
    let mut bytes = Vec::with_capacity(
        morph_script_common::ASSET_REGISTRY_DOMAIN.len() + 8 + registry.xudt_types.len() * 32,
    );
    bytes.extend_from_slice(morph_script_common::ASSET_REGISTRY_DOMAIN);
    bytes.extend_from_slice(&(registry.xudt_types.len() as u64).to_le_bytes());
    for type_hash in &registry.xudt_types {
        bytes.extend_from_slice(type_hash);
    }
    blake2b256(&bytes)
}

pub fn funding_context_id(
    chain_id: &Bytes32,
    channel_id: &Bytes32,
    funding_anchor: &Bytes32,
    vault_set_commitment: &Bytes32,
    vault_outpoint_commitment: &Bytes32,
) -> Bytes32 {
    let mut bytes = Vec::with_capacity(FUNDING_CONTEXT_DOMAIN.len() + 32 * 5);
    bytes.extend_from_slice(FUNDING_CONTEXT_DOMAIN);
    bytes.extend_from_slice(chain_id);
    bytes.extend_from_slice(channel_id);
    bytes.extend_from_slice(funding_anchor);
    bytes.extend_from_slice(vault_set_commitment);
    bytes.extend_from_slice(vault_outpoint_commitment);
    blake2b256(&bytes)
}

pub fn vault_outpoint_commitment(tx_hash: &Bytes32, index: u32) -> Bytes32 {
    let mut bytes = Vec::with_capacity(VAULT_OUTPOINT_COMMITMENT_DOMAIN.len() + 36);
    bytes.extend_from_slice(VAULT_OUTPOINT_COMMITMENT_DOMAIN);
    bytes.extend_from_slice(tx_hash);
    bytes.extend_from_slice(&index.to_le_bytes());
    blake2b256(&bytes)
}

impl SigningBytes for StateHeader {
    fn encode_signing_bytes(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(STATE_DOMAIN);
        out.extend_from_slice(&self.protocol_version.to_le_bytes());
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.signature_scheme_id.to_le_bytes());
        out.extend_from_slice(&self.channel_id);
        out.extend_from_slice(&self.funding_epoch.to_le_bytes());
        out.extend_from_slice(&self.funding_anchor);
        out.extend_from_slice(&self.vault_set_commitment);
        out.extend_from_slice(&self.state_number.to_le_bytes());
        out.push(self.mode.as_u8());
        out.push(self.phase.as_u8());
        out.extend_from_slice(&self.participants_commitment);
        out.extend_from_slice(&self.asset_registry_commitment);
        out.extend_from_slice(&self.settlement_descriptor_commitment);
        out.extend_from_slice(&self.descriptor_version.to_le_bytes());
        out.extend_from_slice(&self.vault_materialisation_root);
        out.extend_from_slice(&self.challenge_policy_commitment);
        out.extend_from_slice(&self.state_layout_version.to_le_bytes());
        out.extend_from_slice(&self.vault_outpoint_commitment);
    }
}

impl StateHeader {
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(384);
        self.encode_signing_bytes(&mut bytes);
        blake2b256(&bytes)
    }

    pub fn funding_context_id(&self) -> [u8; 32] {
        funding_context_id(
            &self.chain_id,
            &self.channel_id,
            &self.funding_anchor,
            &self.vault_set_commitment,
            &self.vault_outpoint_commitment,
        )
    }
}

impl SigningBytes for SpliceHeader {
    fn encode_signing_bytes(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(SPLICE_HEADER_DOMAIN);
        out.extend_from_slice(&self.protocol_version.to_le_bytes());
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.signature_scheme_id.to_le_bytes());
        out.extend_from_slice(&self.channel_id);
        out.extend_from_slice(&self.old_funding_anchor);
        out.extend_from_slice(&self.new_funding_anchor);
        out.extend_from_slice(&self.old_funding_epoch.to_le_bytes());
        out.extend_from_slice(&self.new_funding_epoch.to_le_bytes());
        out.extend_from_slice(&self.base_state_number.to_le_bytes());
        out.extend_from_slice(&self.splice_number.to_le_bytes());
        out.push(self.kind.as_u8());
        out.extend_from_slice(&self.old_vault_commitment);
        out.extend_from_slice(&self.new_vault_commitment);
        out.extend_from_slice(&self.asset_delta_commitment);
        out.extend_from_slice(&self.participants_commitment);
        out.extend_from_slice(&self.vault_materialisation_root);
        out.extend_from_slice(&self.new_vault_materialisation_root);
        out.extend_from_slice(&self.challenge_policy_commitment);
        out.extend_from_slice(&self.old_vault_outpoint_commitment);
        out.extend_from_slice(&self.new_vault_outpoint_commitment);
        out.extend_from_slice(&self.withdrawal_lock_hash);
    }
}

impl SpliceHeader {
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(384);
        self.encode_signing_bytes(&mut bytes);
        blake2b256(&bytes)
    }
}

impl SigningBytes for FactorySpliceHeader {
    fn encode_signing_bytes(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(FACTORY_SPLICE_HEADER_DOMAIN);
        out.extend_from_slice(&self.protocol_version.to_le_bytes());
        out.extend_from_slice(&self.chain_id);
        out.extend_from_slice(&self.signature_scheme_id.to_le_bytes());
        out.extend_from_slice(&self.factory_id);
        out.extend_from_slice(&self.old_update_number.to_le_bytes());
        out.extend_from_slice(&self.new_update_number.to_le_bytes());
        out.extend_from_slice(&self.old_state_root);
        out.extend_from_slice(&self.new_state_root);
        out.extend_from_slice(&self.old_access_manifest_root);
        out.extend_from_slice(&self.new_access_manifest_root);
        out.push(self.kind.as_u8());
        out.extend_from_slice(&self.vault_delta_commitment);
        out.extend_from_slice(&self.non_interference_digest);
        out.extend_from_slice(&self.participants_commitment);
        out.extend_from_slice(&self.old_vault_materialisation_root);
        out.extend_from_slice(&self.new_vault_materialisation_root);
        out.extend_from_slice(&self.old_vault_outpoint_commitment);
        out.extend_from_slice(&self.new_vault_outpoint_commitment);
        out.extend_from_slice(&self.withdrawal_lock_hash);
    }
}

impl FactorySpliceHeader {
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(384);
        self.encode_signing_bytes(&mut bytes);
        blake2b256(&bytes)
    }
}

pub fn vault_descriptor_commitment(descriptor: &VaultDescriptor) -> Bytes32 {
    let mut bytes = Vec::with_capacity(64 + descriptor.assets.len() * 49);
    bytes.extend_from_slice(VAULT_DESCRIPTOR_DOMAIN);
    bytes.extend_from_slice(&descriptor.funding_anchor);
    bytes.extend_from_slice(&(descriptor.assets.len() as u16).to_le_bytes());
    for amount in &descriptor.assets {
        encode_vault_asset(&amount.asset, &mut bytes);
        bytes.extend_from_slice(&amount.amount.to_le_bytes());
    }
    blake2b256(&bytes)
}

pub fn factory_vault_descriptor_commitment(descriptor: &FactoryVaultDescriptor) -> Bytes32 {
    let mut bytes = Vec::with_capacity(64 + descriptor.assets.len() * 49);
    bytes.extend_from_slice(FACTORY_VAULT_DESCRIPTOR_DOMAIN);
    bytes.extend_from_slice(&descriptor.factory_id);
    bytes.extend_from_slice(&(descriptor.assets.len() as u16).to_le_bytes());
    for amount in &descriptor.assets {
        encode_vault_asset(&amount.asset, &mut bytes);
        bytes.extend_from_slice(&amount.amount.to_le_bytes());
    }
    blake2b256(&bytes)
}

pub fn splice_asset_delta_commitment(deltas: &[SpliceAssetDelta]) -> Bytes32 {
    let mut bytes = Vec::with_capacity(64 + deltas.len() * 113);
    bytes.extend_from_slice(SPLICE_DELTA_DOMAIN);
    bytes.extend_from_slice(&(deltas.len() as u16).to_le_bytes());
    for delta in deltas {
        encode_vault_asset(&delta.asset, &mut bytes);
        bytes.extend_from_slice(&delta.old_amount.to_le_bytes());
        bytes.extend_from_slice(&delta.new_amount.to_le_bytes());
        bytes.extend_from_slice(&delta.external_input.to_le_bytes());
        bytes.extend_from_slice(&delta.withdrawal.to_le_bytes());
        bytes.extend_from_slice(&delta.signed_fee.to_le_bytes());
    }
    blake2b256(&bytes)
}

pub fn factory_vault_delta_commitment(deltas: &[FactoryVaultDelta]) -> Bytes32 {
    let mut bytes = Vec::with_capacity(64 + deltas.len() * 97);
    bytes.extend_from_slice(FACTORY_VAULT_DELTA_DOMAIN);
    bytes.extend_from_slice(&(deltas.len() as u16).to_le_bytes());
    for delta in deltas {
        encode_vault_asset(&delta.asset, &mut bytes);
        bytes.extend_from_slice(&delta.old_amount.to_le_bytes());
        bytes.extend_from_slice(&delta.new_amount.to_le_bytes());
        bytes.extend_from_slice(&delta.external_input.to_le_bytes());
        bytes.extend_from_slice(&delta.withdrawal.to_le_bytes());
    }
    blake2b256(&bytes)
}

impl Mode {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::BilateralPlain => 1,
            Self::FactoryProof => 2,
        }
    }
}

impl Phase {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Funding => 0,
            Self::Active => 1,
            Self::Settling => 2,
            Self::Closed => 3,
        }
    }
}

impl SpliceKind {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::In => 0,
            Self::Out => 1,
        }
    }
}

impl FactorySpliceKind {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::In => 0,
            Self::Out => 1,
        }
    }
}

fn encode_vault_asset(asset: &VaultAsset, out: &mut Vec<u8>) {
    match asset {
        VaultAsset::Ckb => {
            out.push(0);
            out.extend_from_slice(&[0u8; 32]);
        }
        VaultAsset::Xudt(type_hash) => {
            out.push(1);
            out.extend_from_slice(type_hash);
        }
    }
}
