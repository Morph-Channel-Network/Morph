//! Factory materialisation planning. A validated plan is public evidence for
//! all-participant approval, not proof that a Factory State or Vault is live.
//! Factory execution must still bind its authenticated State and actual CKB
//! inputs/outputs to this exact plan. Existing single-Vault scripts do not
//! accept this profile.
use std::collections::BTreeSet;

use crate::{
    Bytes32, FactoryParticipantSignature, MultiAssetError, MultiAssetManifest, MultiAssetOutPoint,
    MultiAssetRecoveryPackage, MultiAssetResult, MultiAssetTypeScript, Phase, StateAuthorization,
    blake2b256, encode_multi_asset_outpoints, encode_multi_asset_signatures,
    encode_multi_asset_witness, multi_asset_outpoint_commitment,
};
use morph_script_common::{BilateralSignatureWitness, FactorySignatureWitness, ScriptError};
use morph_script_common::{factory_multi_asset as wire, multi_asset as asset};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactoryMultiAssetChild {
    pub state_output_index: u32,
    pub recovery: MultiAssetRecoveryPackage,
    pub creation_authorization: StateAuthorization,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactoryMultiAssetMaterialisation {
    pub chain_id: Bytes32,
    pub factory_id: Bytes32,
    pub participants_commitment: Bytes32,
    /// The source Factory State is input zero, with since = 0.
    pub old_state: MultiAssetOutPoint,
    pub transaction_hash: Bytes32,
    pub source: MultiAssetManifest,
    pub factory_vault_lock: Vec<u8>,
    pub type_scripts: Vec<MultiAssetTypeScript>,
    pub source_outpoints: Vec<MultiAssetOutPoint>,
    /// Retained State is output zero, followed by its Vaults in manifest order.
    pub retained: Option<MultiAssetManifest>,
    pub factory_carrier_capacity: u64,
    /// Exactly the new child State carriers; Factory Vault value never funds them.
    pub external_carrier_contribution: u64,
    /// Empty with retained custody. Otherwise output zero refunds the full
    /// Factory State carrier to this exact Script.
    pub carrier_refund_lock: Vec<u8>,
    pub children: Vec<FactoryMultiAssetChild>,
}

fn mismatch<T>() -> MultiAssetResult<T> {
    Err(ScriptError::FactoryMultiAssetPartitionMismatch.into())
}

impl FactoryMultiAssetMaterialisation {
    pub fn validate_contents(&self) -> MultiAssetResult<()> {
        if self.chain_id == [0; 32]
            || self.factory_id == [0; 32]
            || self.participants_commitment == [0; 32]
            || self.old_state.tx_hash == [0; 32]
            || self.transaction_hash == [0; 32]
            || self.old_state.tx_hash == self.transaction_hash
            || self
                .source_outpoints
                .iter()
                .any(|point| point.tx_hash == self.transaction_hash)
            || self.factory_carrier_capacity == 0
            || !(1..=wire::FACTORY_MULTI_ASSET_MAX_CHILDREN).contains(&self.children.len())
            || self.source_outpoints.contains(&self.old_state)
        {
            return mismatch();
        }
        multi_asset_outpoint_commitment(&self.source, &self.source_outpoints)?;
        let source_raw = self.source.encode()?;
        let retained_raw = self
            .retained
            .as_ref()
            .map(MultiAssetManifest::encode)
            .transpose()?;
        let child_raw = self
            .children
            .iter()
            .map(|child| child.recovery.manifest.encode())
            .collect::<MultiAssetResult<Vec<_>>>()?;
        let source = asset::MultiAssetVaultManifest::parse(&source_raw)?;
        let source_lock = source.entry(0)?.lock_hash;
        let registry = self.source.registry()?;
        asset::multi_asset_script_occupied_bytes(&self.factory_vault_lock)?;
        if self.factory_vault_lock.len() != 117
            || self.factory_vault_lock[53..85] != self.factory_id
            || self.factory_vault_lock[85..] == [0; 32]
            || blake2b256(&self.factory_vault_lock) != source_lock
            || self.type_scripts.len() != registry.xudt_types.len()
        {
            return mismatch();
        }
        let mut previous_type = None;
        for entry in &self.type_scripts {
            asset::multi_asset_script_occupied_bytes(&entry.script)?;
            if blake2b256(&entry.script) != entry.type_hash
                || !registry.contains(&entry.type_hash)
                || previous_type.is_some_and(|previous| previous >= entry.type_hash)
            {
                return mismatch();
            }
            previous_type = Some(entry.type_hash);
        }
        for manifest in std::iter::once(&self.source).chain(self.retained.iter()) {
            for vault in &manifest.vaults {
                let ty = match &vault.asset {
                    crate::VaultAsset::Ckb => None,
                    crate::VaultAsset::Xudt(hash) => Some(
                        self.type_scripts
                            .iter()
                            .find(|entry| entry.type_hash == *hash)
                            .ok_or(MultiAssetError::IncompleteEvidence)?
                            .script
                            .as_slice(),
                    ),
                };
                if vault.value.reserve
                    < asset::multi_asset_occupied_capacity(
                        &self.factory_vault_lock,
                        ty,
                        if ty.is_some() { 16 } else { 0 },
                    )?
                {
                    return mismatch();
                }
            }
        }
        let retained = retained_raw
            .as_deref()
            .map(asset::MultiAssetVaultManifest::parse)
            .transpose()?;
        let children = child_raw
            .iter()
            .map(|raw| asset::MultiAssetVaultManifest::parse(raw))
            .collect::<Result<Vec<_>, _>>()?;
        wire::validate_materialisation_partition(&source, retained.as_ref(), &children)?;
        if self.retained.is_some() {
            if !self.carrier_refund_lock.is_empty() {
                return mismatch();
            }
        } else if self.carrier_refund_lock.is_empty()
            || blake2b256(&self.carrier_refund_lock) == source_lock
            || asset::multi_asset_occupied_capacity(&self.carrier_refund_lock, None, 0)?
                > self.factory_carrier_capacity
        {
            return mismatch();
        }
        let mut occupied = BTreeSet::from([0u32]);
        if let Some(retained) = &self.retained {
            for index in 1..=retained.vaults.len() {
                occupied.insert(index as u32);
            }
        }
        let mut channel_ids = BTreeSet::new();
        let mut state_types = BTreeSet::new();
        let mut state_locks = BTreeSet::new();
        let mut carriers = 0u64;
        let mut custody_locks = BTreeSet::from([source_lock]);
        for child in &self.children {
            custody_locks.insert(blake2b256(&child.recovery.scripts.vault_lock));
            custody_locks.insert(blake2b256(&child.recovery.scripts.state_lock));
        }
        if !self.carrier_refund_lock.is_empty()
            && custody_locks.contains(&blake2b256(&self.carrier_refund_lock))
        {
            return mismatch();
        }
        let mut first_input = vec![0u8; 8];
        first_input.extend_from_slice(&self.old_state.tx_hash);
        first_input.extend_from_slice(&self.old_state.index.to_le_bytes());
        for child in &self.children {
            let exit = &child.recovery;
            exit.validate()?;
            for lock in exit
                .scripts
                .participant_locks
                .iter()
                .chain(std::iter::once(&exit.scripts.carrier_refund_lock))
            {
                if custody_locks.contains(&blake2b256(lock)) {
                    return mismatch();
                }
            }
            let header = &exit.state.header;
            if header.chain_id != self.chain_id
                || header.funding_epoch != 0
                || header.phase != Phase::Settling
                || header.state_number != 1
                || !channel_ids.insert(header.channel_id)
                || !state_types.insert(blake2b256(&exit.scripts.state_type))
                || !state_locks.insert(blake2b256(&exit.scripts.state_lock))
                || child.state_output_index >= wire::FACTORY_MULTI_ASSET_MAX_OUTPUTS as u32
                || !occupied.insert(child.state_output_index)
            {
                return mismatch();
            }
            let mut anchor = first_input.clone();
            anchor.extend_from_slice(&(child.state_output_index as u64).to_le_bytes());
            if blake2b256(&anchor) != header.funding_anchor {
                return mismatch();
            }
            for point in &exit.outpoints {
                if point.tx_hash != self.transaction_hash
                    || point.index >= wire::FACTORY_MULTI_ASSET_MAX_OUTPUTS as u32
                    || !occupied.insert(point.index)
                {
                    return mismatch();
                }
            }
            let mut creation = exit.clone();
            creation.state.header.phase = Phase::Active;
            creation.state.header.state_number = 0;
            creation.state.vault_outpoint_set_root = [0; 32];
            creation.outpoints.clear();
            creation.authorization = child.creation_authorization.clone();
            creation.validate_contents()?;
            let encoded = creation.state.encode()?;
            let signatures = encode_multi_asset_signatures(&child.creation_authorization)?;
            asset::MultiAssetStateHeader::parse(&encoded)?.verify_root_funding_signatures(
                &self.transaction_hash,
                &BilateralSignatureWitness::parse(&signatures)?,
            )?;
            carriers = carriers
                .checked_add(exit.state_carrier_capacity)
                .ok_or(ScriptError::MultiAssetCapacityMismatch)?;
        }
        if carriers != self.external_carrier_contribution {
            return mismatch();
        }
        let source_capacity = (0..source.count()).try_fold(0u64, |sum, i| {
            sum.checked_add(source.entry(i)?.allocation.capacity()?)
                .ok_or(ScriptError::MultiAssetCapacityMismatch)
        })?;
        source_capacity
            .checked_add(self.factory_carrier_capacity)
            .and_then(|value| value.checked_add(carriers))
            .ok_or(ScriptError::MultiAssetCapacityMismatch)?;
        Ok(())
    }

    /// Canonical public intent; signatures are verified prerequisites but are
    /// not themselves committed, allowing equivalent valid signature delivery.
    pub fn encode_intent(&self) -> MultiAssetResult<Vec<u8>> {
        self.validate_contents()?;
        let source = self.source.encode()?;
        let retained = self
            .retained
            .as_ref()
            .map(MultiAssetManifest::encode)
            .transpose()?
            .unwrap_or_default();
        let mut raw = Vec::new();
        raw.extend_from_slice(&1u16.to_le_bytes());
        raw.extend_from_slice(&(self.children.len() as u16).to_le_bytes());
        raw.extend_from_slice(&self.chain_id);
        raw.extend_from_slice(&self.factory_id);
        raw.extend_from_slice(&self.participants_commitment);
        raw.extend_from_slice(&self.old_state.tx_hash);
        raw.extend_from_slice(&self.old_state.index.to_le_bytes());
        raw.extend_from_slice(&self.transaction_hash);
        raw.extend_from_slice(&(source.len() as u32).to_le_bytes());
        raw.extend_from_slice(&(retained.len() as u32).to_le_bytes());
        raw.extend_from_slice(&self.factory_carrier_capacity.to_le_bytes());
        raw.extend_from_slice(&self.external_carrier_contribution.to_le_bytes());
        raw.extend_from_slice(&(self.carrier_refund_lock.len() as u32).to_le_bytes());
        raw.extend_from_slice(&(self.factory_vault_lock.len() as u32).to_le_bytes());
        raw.extend_from_slice(&(self.type_scripts.len() as u16).to_le_bytes());
        raw.extend_from_slice(&0u16.to_le_bytes());
        raw.extend_from_slice(&source);
        raw.extend_from_slice(&encode_multi_asset_outpoints(&self.source_outpoints)?);
        raw.extend_from_slice(&retained);
        raw.extend_from_slice(&self.carrier_refund_lock);
        raw.extend_from_slice(&self.factory_vault_lock);
        for entry in &self.type_scripts {
            raw.extend_from_slice(&(entry.script.len() as u32).to_le_bytes());
            raw.extend_from_slice(&entry.script);
        }
        for child in &self.children {
            let recovery = &child.recovery;
            let witness = encode_multi_asset_witness(
                &recovery.manifest,
                &recovery.settlement,
                &recovery.outpoints,
                &recovery.scripts,
            )?;
            raw.extend_from_slice(&child.state_output_index.to_le_bytes());
            raw.extend_from_slice(&recovery.state_carrier_capacity.to_le_bytes());
            raw.extend_from_slice(&recovery.state.encode()?);
            raw.extend_from_slice(&(witness.len() as u32).to_le_bytes());
            raw.extend_from_slice(&witness);
        }
        Ok(raw)
    }
    pub fn signing_digest(&self) -> MultiAssetResult<Bytes32> {
        Ok(crate::multi_asset::host_commitment(
            crate::hash::FACTORY_MULTI_ASSET_MATERIALISATION_DOMAIN,
            &self.encode_intent()?,
        ))
    }
    pub fn verify_authorization(
        &self,
        expected_participants: &Bytes32,
        authorization: &[FactoryParticipantSignature],
    ) -> MultiAssetResult<()> {
        if self.participants_commitment != *expected_participants
            || !(2..=16).contains(&authorization.len())
        {
            return mismatch();
        }
        let mut raw = vec![1, 0, authorization.len() as u8, authorization.len() as u8];
        for signature in authorization {
            if signature.pubkey_sec1.len() != 33 || signature.signature.len() != 64 {
                return Err(MultiAssetError::IncompleteEvidence);
            }
            raw.extend_from_slice(&signature.participant);
            raw.extend_from_slice(&signature.pubkey_sec1);
            raw.extend_from_slice(&signature.signature);
        }
        wire::verify_materialisation_authorisation(
            &self.encode_intent()?,
            expected_participants,
            &FactorySignatureWitness::parse(&raw)?,
        )?;
        for child in &self.children {
            if child
                .recovery
                .authorization
                .signatures
                .iter()
                .any(|signature| {
                    !authorization
                        .iter()
                        .any(|member| member.pubkey_sec1 == signature.pubkey_sec1)
                })
            {
                return mismatch();
            }
        }
        Ok(())
    }
}
