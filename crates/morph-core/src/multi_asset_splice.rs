//! Multi-asset splice intents. A completed bridge must retire the exact old
//! State input, preserve its carrier and fund the complete new Vault set.
use crate::{
    Bytes32, MultiAssetError, MultiAssetManifest, MultiAssetOutPoint, MultiAssetRecoveryPackage,
    MultiAssetRecoveryScripts, MultiAssetResult, MultiAssetSettlement, MultiAssetState,
    MultiAssetValue, StateAuthorization, VaultAsset, blake2b256, encode_multi_asset_signatures,
};
use morph_script_common::{
    BilateralSignatureWitness, ScriptError, multi_asset as wire, multi_asset_splice as splice,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiAssetSpliceFlow {
    pub asset: VaultAsset,
    pub deposit: MultiAssetValue,
    pub withdrawal: MultiAssetValue,
}

pub fn encode_multi_asset_splice_flows(
    flows: &[MultiAssetSpliceFlow],
) -> MultiAssetResult<Vec<u8>> {
    if !(1..=splice::MULTI_ASSET_SPLICE_MAX_FLOWS).contains(&flows.len()) {
        return Err(ScriptError::MultiAssetSpliceEncoding.into());
    }
    let mut raw = vec![0; 4 + flows.len() * splice::MULTI_ASSET_SPLICE_FLOW_LEN];
    raw[..2].copy_from_slice(&(flows.len() as u16).to_le_bytes());
    for (index, flow) in flows.iter().enumerate() {
        let offset = 4 + index * splice::MULTI_ASSET_SPLICE_FLOW_LEN;
        splice::MultiAssetSpliceFlow {
            asset: crate::multi_asset::wire_asset(&flow.asset),
            deposit: flow.deposit.wire(),
            withdrawal: flow.withdrawal.wire(),
        }
        .encode(&mut raw[offset..offset + splice::MULTI_ASSET_SPLICE_FLOW_LEN])?;
    }
    splice::MultiAssetSpliceFlows::parse(&raw)?;
    Ok(raw)
}

pub fn multi_asset_splice_flow_commitment(
    flows: &[MultiAssetSpliceFlow],
) -> MultiAssetResult<Bytes32> {
    Ok(crate::multi_asset::host_commitment(
        crate::hash::MULTI_ASSET_SPLICE_FLOW_DOMAIN,
        &encode_multi_asset_splice_flows(flows)?,
    ))
}

pub fn multi_asset_splice_funding_anchor(old_state: &MultiAssetOutPoint) -> Bytes32 {
    let mut raw = vec![0; 8]; // old State input since = 0
    raw.extend_from_slice(&old_state.tx_hash);
    raw.extend_from_slice(&old_state.index.to_le_bytes());
    raw.extend_from_slice(&0u64.to_le_bytes()); // new State output index = 0
    blake2b256(&raw)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiAssetSpliceProposal {
    pub base_state_digest: Bytes32,
    pub old_state_outpoint: MultiAssetOutPoint,
    pub transaction_hash: Bytes32,
    pub new_state_authorization: StateAuthorization,
    pub initial_recovery_authorization: StateAuthorization,
    pub new_state: MultiAssetState,
    pub new_manifest: MultiAssetManifest,
    pub new_settlement: MultiAssetSettlement,
    pub new_scripts: MultiAssetRecoveryScripts,
    pub flows: Vec<MultiAssetSpliceFlow>,
    /// Empty only when every withdrawal allocation is empty.
    pub withdrawal_lock: Vec<u8>,
}

impl MultiAssetSpliceProposal {
    fn header(
        &self,
        current: &MultiAssetRecoveryPackage,
    ) -> MultiAssetResult<[u8; splice::MULTI_ASSET_SPLICE_HEADER_LEN]> {
        let mut point = [0; 36];
        point[..32].copy_from_slice(&self.old_state_outpoint.tx_hash);
        point[32..].copy_from_slice(&self.old_state_outpoint.index.to_le_bytes());
        Ok(splice::encode_multi_asset_splice_header(
            &current.state.funding_context_id()?,
            &point,
            &self.new_state.signing_digest()?,
            &multi_asset_splice_flow_commitment(&self.flows)?,
            &if self.withdrawal_lock.is_empty() {
                [0; 32]
            } else {
                blake2b256(&self.withdrawal_lock)
            },
            &self.transaction_hash,
        )?)
    }
    pub fn validate(&self, current: &MultiAssetRecoveryPackage) -> MultiAssetResult<()> {
        self.validate_contents(current)?;
        self.new_state
            .verify_authorization(&self.new_state_authorization)?;
        self.initial_recovery(current)?;
        Ok(())
    }
    /// Validate unsigned funding terms without authorising a bridge spend.
    pub fn validate_contents(&self, current: &MultiAssetRecoveryPackage) -> MultiAssetResult<()> {
        current.validate()?;
        if self.base_state_digest != current.state.signing_digest()?
            || current.outpoints.contains(&self.old_state_outpoint)
        {
            return Err(ScriptError::MultiAssetSpliceMismatch.into());
        }
        let next = MultiAssetRecoveryPackage {
            state: self.new_state.clone(),
            authorization: self.new_state_authorization.clone(),
            manifest: self.new_manifest.clone(),
            settlement: self.new_settlement.clone(),
            scripts: self.new_scripts.clone(),
            outpoints: vec![],
            state_carrier_capacity: current.state_carrier_capacity,
        };
        next.validate_contents()?;
        self.initial_recovery_contents(current)?;
        let old_header = current.state.encode()?;
        let new_header = self.new_state.encode()?;
        let before = current.manifest.encode()?;
        let after = self.new_manifest.encode()?;
        let flows = encode_multi_asset_splice_flows(&self.flows)?;
        let header = self.header(current)?;
        splice::MultiAssetSpliceHeader::parse(&header)?.validate_transition(
            &wire::MultiAssetStateHeader::parse(&old_header)?,
            &wire::MultiAssetStateHeader::parse(&new_header)?,
            &wire::MultiAssetVaultManifest::parse(&before)?,
            &wire::MultiAssetVaultManifest::parse(&after)?,
            &splice::MultiAssetSpliceFlows::parse(&flows)?,
        )?;
        let old = &current.scripts;
        let new = &self.new_scripts;
        // The splice changes funding, not authority code, participants or the
        // relative-block challenge policy. Script framing was validated above.
        let old_args = wire::MultiAssetVaultArgs::parse(&old.vault_lock[53..])?;
        let new_args = wire::MultiAssetVaultArgs::parse(&new.vault_lock[53..])?;
        if old.participant_locks != new.participant_locks
            || old.carrier_refund_lock != new.carrier_refund_lock
            || old.vault_lock[..49] != new.vault_lock[..49]
            || old.state_type[..49] != new.state_type[..49]
            || old.state_lock[..49] != new.state_lock[..49]
            || old_args.finalise_since() != new_args.finalise_since()
            || !matches!(old.state_type.len(), 93 | 125)
            || old.state_type.len() != new.state_type.len()
            || old.state_type[85..] != new.state_type[85..]
        {
            return Err(MultiAssetError::ScriptIdentity);
        }
        if !self.withdrawal_lock.is_empty() {
            wire::multi_asset_script_occupied_bytes(&self.withdrawal_lock)?;
            for flow in &self.flows {
                if flow.withdrawal == MultiAssetValue::default() {
                    continue;
                }
                let type_script = if flow.withdrawal.amount == 0 {
                    None
                } else {
                    let VaultAsset::Xudt(hash) = flow.asset else {
                        return Err(ScriptError::MultiAssetSpliceMismatch.into());
                    };
                    Some(
                        old.type_scripts
                            .iter()
                            .chain(&new.type_scripts)
                            .find(|script| script.type_hash == hash)
                            .ok_or(MultiAssetError::IncompleteEvidence)?
                            .script
                            .as_slice(),
                    )
                };
                let occupied = wire::multi_asset_occupied_capacity(
                    &self.withdrawal_lock,
                    type_script,
                    if type_script.is_some() { 16 } else { 0 },
                )?;
                if flow.withdrawal.reserve < occupied {
                    return Err(MultiAssetError::InsufficientReserve);
                }
            }
        }
        Ok(())
    }
    /// The complete unilateral state for the exact future transaction body
    /// must be retained before releasing either old-context bridge signature.
    pub fn initial_recovery(
        &self,
        current: &MultiAssetRecoveryPackage,
    ) -> MultiAssetResult<MultiAssetRecoveryPackage> {
        let recovery = self.initial_recovery_contents(current)?;
        recovery.validate()?;
        Ok(recovery)
    }
    /// Predict the exact future exit for review before all receipts exist.
    /// Call `initial_recovery` to require its complete participant authority.
    pub fn initial_recovery_contents(
        &self,
        current: &MultiAssetRecoveryPackage,
    ) -> MultiAssetResult<MultiAssetRecoveryPackage> {
        if !(1..=wire::MULTI_ASSET_MAX_VAULTS).contains(&self.new_manifest.vaults.len()) {
            return Err(ScriptError::MultiAssetSpliceEncoding.into());
        }
        let points = (0..self.new_manifest.vaults.len())
            .map(|index| MultiAssetOutPoint {
                tx_hash: self.transaction_hash,
                index: index as u32 + 1,
            })
            .collect::<Vec<_>>();
        let mut state = self.new_state.clone();
        state.header.phase = crate::Phase::Settling;
        state.header.state_number = 1;
        state.vault_outpoint_set_root =
            crate::multi_asset_outpoint_commitment(&self.new_manifest, &points)?;
        let recovery = MultiAssetRecoveryPackage {
            state,
            authorization: self.initial_recovery_authorization.clone(),
            manifest: self.new_manifest.clone(),
            settlement: self.new_settlement.clone(),
            outpoints: points,
            scripts: self.new_scripts.clone(),
            state_carrier_capacity: current.state_carrier_capacity,
        };
        recovery.validate_contents()?;
        Ok(recovery)
    }
    pub(crate) fn intent_digest(
        &self,
        current: &MultiAssetRecoveryPackage,
    ) -> MultiAssetResult<Bytes32> {
        self.validate_contents(current)?;
        Ok(crate::multi_asset::host_commitment(
            crate::hash::MULTI_ASSET_SPLICE_DOMAIN,
            &self.header(current)?,
        ))
    }
    pub fn encode_header(
        &self,
        current: &MultiAssetRecoveryPackage,
    ) -> MultiAssetResult<[u8; splice::MULTI_ASSET_SPLICE_HEADER_LEN]> {
        self.validate(current)?;
        self.header(current)
    }
    pub fn signing_digest(&self, current: &MultiAssetRecoveryPackage) -> MultiAssetResult<Bytes32> {
        self.validate(current)?;
        let header = self.header(current)?;
        Ok(crate::multi_asset::host_commitment(
            crate::hash::MULTI_ASSET_SPLICE_DOMAIN,
            &header,
        ))
    }
    pub fn encode_witness(
        &self,
        current: &MultiAssetRecoveryPackage,
        authorization: &StateAuthorization,
    ) -> MultiAssetResult<Vec<u8>> {
        self.verify_authorization(current, authorization)?;
        let old_manifest = current.manifest.encode()?;
        let old_points = crate::encode_multi_asset_outpoints(&current.outpoints)?;
        let new_evidence = crate::encode_multi_asset_witness(
            &self.new_manifest,
            &self.new_settlement,
            &[],
            &self.new_scripts,
        )?;
        let flows = encode_multi_asset_splice_flows(&self.flows)?;
        let mut raw = vec![0; splice::MULTI_ASSET_SPLICE_PREFIX_LEN];
        raw[..8].copy_from_slice(splice::MULTI_ASSET_SPLICE_MAGIC);
        raw[8..10].copy_from_slice(&splice::MULTI_ASSET_SPLICE_FORMAT.to_le_bytes());
        raw[12..16].copy_from_slice(&(old_manifest.len() as u32).to_le_bytes());
        raw[16..18].copy_from_slice(&(current.outpoints.len() as u16).to_le_bytes());
        raw[20..24].copy_from_slice(&(new_evidence.len() as u32).to_le_bytes());
        raw[24..28].copy_from_slice(&(self.withdrawal_lock.len() as u32).to_le_bytes());
        raw[28..32].copy_from_slice(&(flows.len() as u32).to_le_bytes());
        raw.extend_from_slice(&self.header(current)?);
        raw.extend_from_slice(&self.new_state.encode()?);
        raw.extend_from_slice(&encode_multi_asset_signatures(authorization)?);
        raw.extend_from_slice(&old_manifest);
        raw.extend_from_slice(&old_points);
        raw.extend_from_slice(&new_evidence);
        raw.extend_from_slice(&self.withdrawal_lock);
        raw.extend_from_slice(&flows);
        splice::MultiAssetSpliceWitness::parse(&raw)?;
        Ok(raw)
    }
    pub fn verify_authorization(
        &self,
        current: &MultiAssetRecoveryPackage,
        authorization: &StateAuthorization,
    ) -> MultiAssetResult<()> {
        self.validate(current)?;
        let header = self.header(current)?;
        let signatures = encode_multi_asset_signatures(authorization)?;
        Ok(
            splice::MultiAssetSpliceHeader::parse(&header)?.verify_signatures(
                &current.state.header.participants_commitment,
                &BilateralSignatureWitness::parse(&signatures)?,
            )?,
        )
    }
}
