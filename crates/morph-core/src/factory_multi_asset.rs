//! Complete Factory materialisation plans and private child recovery checks.
//! Consensus separately authenticates the Factory State and the exact physical
//! input/output set against the canonical intent encoded here.
use crate::{
    Bytes32, FactoryParticipantSignature, MultiAssetError, MultiAssetManifest, MultiAssetOutPoint,
    MultiAssetRecoveryPackage, MultiAssetResult, MultiAssetTypeScript, blake2b256,
    encode_multi_asset_outpoints, encode_multi_asset_signatures, encode_multi_asset_witness,
};
use morph_script_common::factory_multi_asset as wire;
use morph_script_common::{BilateralSignatureWitness, ScriptError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactoryMultiAssetChild {
    pub state_output_index: u32,
    pub recovery: MultiAssetRecoveryPackage,
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
        self.encode_intent().map(|_| ())
    }

    /// Canonical public intent; signatures are verified prerequisites but are
    /// not themselves committed, allowing equivalent valid signature delivery.
    fn encode_intent_unchecked(&self) -> MultiAssetResult<Vec<u8>> {
        if !(1..=wire::FACTORY_MULTI_ASSET_MAX_CHILDREN).contains(&self.children.len())
            || self.source_outpoints.len() != self.source.vaults.len()
            || self.type_scripts.len() > 8
            || self.factory_vault_lock.len() > 512
            || self.carrier_refund_lock.len() > 512
            || self.type_scripts.iter().any(|entry| {
                entry.script.len() > 512 || entry.type_hash != blake2b256(&entry.script)
            })
        {
            return mismatch();
        }
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
    pub fn encode_intent(&self) -> MultiAssetResult<Vec<u8>> {
        let raw = self.encode_intent_unchecked()?;
        let intent = wire::FactoryMaterialisationIntent::parse(&raw)?;
        for (i, child) in self.children.iter().enumerate() {
            let recovery = encode_multi_asset_signatures(&child.recovery.authorization)?;
            intent
                .child(i)?
                .verify_recovery_authorisation(&BilateralSignatureWitness::parse(&recovery)?)?;
        }
        Ok(raw)
    }
    pub fn signing_digest(&self) -> MultiAssetResult<Bytes32> {
        Ok(crate::multi_asset::host_commitment(
            crate::hash::FACTORY_MULTI_ASSET_MATERIALISATION_DOMAIN,
            &self.encode_intent()?,
        ))
    }
    pub fn encode_witness(
        &self,
        expected_participants: &Bytes32,
        authorization: &[FactoryParticipantSignature],
    ) -> MultiAssetResult<Vec<u8>> {
        if self.participants_commitment != *expected_participants
            || !(2..=16).contains(&authorization.len())
        {
            return mismatch();
        }
        let intent = self.encode_intent()?;
        let signatures = encode_factory_all_participant_signatures(authorization)?;
        let mut raw = wire::FACTORY_MATERIALISATION_MAGIC.to_vec();
        raw.extend_from_slice(&1u16.to_le_bytes());
        raw.extend_from_slice(&0u16.to_le_bytes());
        raw.extend_from_slice(&(intent.len() as u32).to_le_bytes());
        raw.extend_from_slice(&(signatures.len() as u32).to_le_bytes());
        raw.extend_from_slice(&(self.children.len() as u16).to_le_bytes());
        raw.extend_from_slice(&0u16.to_le_bytes());
        raw.extend_from_slice(&intent);
        raw.extend_from_slice(&signatures);
        for child in &self.children {
            let signatures = encode_multi_asset_signatures(&child.recovery.authorization)?;
            let signatures = BilateralSignatureWitness::parse(&signatures)?;
            raw.extend_from_slice(signatures.pubkey(0));
            raw.extend_from_slice(signatures.pubkey(1));
        }
        wire::FactoryMaterialisationWitness::parse(&raw)?.verify()?;
        Ok(raw)
    }
    pub fn verify_authorization(
        &self,
        expected_participants: &Bytes32,
        authorization: &[FactoryParticipantSignature],
    ) -> MultiAssetResult<()> {
        self.encode_witness(expected_participants, authorization)
            .map(|_| ())
    }
}

pub fn encode_factory_all_participant_signatures(
    authorization: &[FactoryParticipantSignature],
) -> MultiAssetResult<Vec<u8>> {
    if !(2..=16).contains(&authorization.len()) {
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
    morph_script_common::FactorySignatureWitness::parse(&raw)?;
    Ok(raw)
}
pub fn encode_factory_multi_asset_state_witness(
    kind: u16,
    manifest: &MultiAssetManifest,
    points: &[MultiAssetOutPoint],
    authorization: &[FactoryParticipantSignature],
) -> MultiAssetResult<Vec<u8>> {
    if points.len() > 8 {
        return mismatch();
    }
    let manifest = manifest.encode()?;
    let signatures = if kind == wire::FACTORY_STATE_WITNESS_ACTIVATE && authorization.is_empty() {
        vec![]
    } else {
        encode_factory_all_participant_signatures(authorization)?
    };
    let mut raw = wire::FACTORY_MULTI_ASSET_STATE_WITNESS_MAGIC.to_vec();
    raw.extend_from_slice(&1u16.to_le_bytes());
    raw.extend_from_slice(&0u16.to_le_bytes());
    raw.extend_from_slice(&kind.to_le_bytes());
    raw.extend_from_slice(&(points.len() as u16).to_le_bytes());
    raw.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
    raw.extend_from_slice(&(signatures.len() as u32).to_le_bytes());
    raw.extend_from_slice(&manifest);
    raw.extend_from_slice(&encode_multi_asset_outpoints(points)?);
    raw.extend_from_slice(&signatures);
    wire::FactoryMultiAssetStateWitness::parse(&raw)?;
    Ok(raw)
}
