//! Current Factory reduced release construction. Rights are shared protocol
//! objects; no retired State/header or retired spending witness is accepted.
//! Initial all-member allocation must establish valid reserve entitlements;
//! a localised decrement proof does not establish that initial allocation.
//! A reduced spend retains a nonempty successor and its occupied CKB floor;
//! the Factory State carrier is preserved. It cannot retire the final dust or
//! collectively owned carrier with one key. This matches the prior reduced
//! capability; canonical all-member materialisation can retire the parent.
use crate::{
    Bytes32, FactoryCompactRightProof, FactoryParticipantKey, FactoryRight, FactoryRightKind,
    MultiAssetManifest, MultiAssetOutPoint, MultiAssetResult, MultiAssetTypeScript,
    MultiAssetValue, VaultAsset, encode_multi_asset_outpoints,
};
use morph_script_common::ScriptError;
pub use morph_script_common::factory_multi_asset::FactoryTransitionOperation;
use morph_script_common::factory_multi_asset::{self as wire, FactoryMultiAssetHeaderFields};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactoryReducedReleasePayout {
    pub asset: VaultAsset,
    pub value: MultiAssetValue,
    pub lock_script: Vec<u8>,
    pub output_index: u16,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactoryReducedReleaseRight {
    pub before: FactoryCompactRightProof,
    pub after: FactoryCompactRightProof,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactoryMultiAssetReducedRelease {
    pub operation: FactoryTransitionOperation,
    pub before: FactoryMultiAssetHeaderFields,
    pub after: FactoryMultiAssetHeaderFields,
    pub members: Vec<FactoryParticipantKey>,
    pub signer_index: u16,
    pub old_state: MultiAssetOutPoint,
    pub transaction_hash: Bytes32,
    pub carrier_capacity: u64,
    pub source: MultiAssetManifest,
    pub source_outpoints: Vec<MultiAssetOutPoint>,
    pub retained: MultiAssetManifest,
    pub factory_lock_script: Vec<u8>,
    pub type_scripts: Vec<MultiAssetTypeScript>,
    pub payouts: Vec<FactoryReducedReleasePayout>,
    pub rights: Vec<FactoryReducedReleaseRight>,
    pub materialisation: Option<crate::FactoryMultiAssetMaterialisation>,
}
fn invalid<T>() -> MultiAssetResult<T> {
    Err(ScriptError::FactoryReducedProofEncoding.into())
}
fn encode_right(raw: &mut Vec<u8>, right: &FactoryRight) {
    raw.extend_from_slice(&right.id.participant);
    raw.extend_from_slice(&right.id.subchannel);
    raw.push(match right.id.kind {
        FactoryRightKind::Balance => 0,
        FactoryRightKind::ReserveClaim => 1,
        FactoryRightKind::Membership => 2,
        FactoryRightKind::ExitPath => 3,
        FactoryRightKind::SponsorBudgetClaim => 4,
    });
    raw.push(u8::from(right.id.asset_type.is_some()));
    raw.extend_from_slice(&right.id.asset_type.unwrap_or([0; 32]));
    raw.extend_from_slice(&right.quantity.to_le_bytes());
}
fn encode_proof(raw: &mut Vec<u8>, proof: &FactoryCompactRightProof) -> MultiAssetResult<()> {
    if proof.siblings.len() > 64 {
        return invalid();
    }
    raw.extend_from_slice(&(proof.siblings.len() as u16).to_le_bytes());
    for sibling in &proof.siblings {
        raw.extend_from_slice(&sibling.depth.to_le_bytes());
        raw.extend_from_slice(&sibling.hash);
    }
    Ok(())
}
impl FactoryMultiAssetReducedRelease {
    pub fn signature_count(&self) -> usize {
        if self.operation.is_full() {
            self.members.len()
        } else {
            1
        }
    }
    fn encode_base_frame(&self, signatures: &[[u8; 64]]) -> MultiAssetResult<Vec<u8>> {
        if (self.operation == FactoryTransitionOperation::ReducedChild)
            != self.materialisation.is_some()
            || signatures.len() != self.signature_count()
            || !(2..=16).contains(&self.members.len())
            || usize::from(self.signer_index) >= self.members.len()
            || self.rights.len() > wire::FACTORY_TRANSITION_MAX_RIGHTS
            || self.payouts.len() > 8
            || self.type_scripts.len() > 16
            || self.source_outpoints.len() != self.source.vaults.len()
            || self.factory_lock_script.len() != 117
            || self.members.iter().any(|m| m.pubkey_sec1.len() != 33)
            || self
                .type_scripts
                .iter()
                .any(|s| s.script.len() > 512 || crate::blake2b256(&s.script) != s.type_hash)
            || self.payouts.iter().any(|p| p.lock_script.len() > 512)
        {
            return invalid();
        }
        let own_types = self.operation != FactoryTransitionOperation::ReducedChild;
        let mut scripts = vec![self.factory_lock_script.as_slice()];
        if own_types {
            scripts.extend(self.type_scripts.iter().map(|s| s.script.as_slice()));
        }
        scripts.extend(self.payouts.iter().map(|p| p.lock_script.as_slice()));
        let table_bytes = morph_script_common::script_table::encode(&scripts)?;
        let table = morph_script_common::script_table::ScriptTable::parse(&table_bytes)?;
        let source = self.source.encode()?;
        let retained = self.retained.encode()?;
        let mut raw = Vec::with_capacity(wire::FACTORY_REDUCED_RELEASE_PREFIX_LEN);
        raw.extend_from_slice(wire::FACTORY_REDUCED_RELEASE_MAGIC);
        raw.extend_from_slice(&2u16.to_le_bytes());
        raw.extend_from_slice(&(self.operation as u16).to_le_bytes());
        raw.extend_from_slice(&(self.members.len() as u16).to_le_bytes());
        raw.extend_from_slice(&self.signer_index.to_le_bytes());
        raw.extend_from_slice(&(self.rights.len() as u16).to_le_bytes());
        raw.extend_from_slice(&(self.payouts.len() as u16).to_le_bytes());
        raw.extend_from_slice(&(source.len() as u32).to_le_bytes());
        raw.extend_from_slice(&(retained.len() as u32).to_le_bytes());
        raw.extend_from_slice(&(table_bytes.len() as u32).to_le_bytes());
        raw.extend_from_slice(
            &(if own_types {
                self.type_scripts.len() as u16
            } else {
                0
            })
            .to_le_bytes(),
        );
        raw.extend_from_slice(&(table.index_of(&self.factory_lock_script)? as u16).to_le_bytes());
        raw.extend_from_slice(&self.old_state.tx_hash);
        raw.extend_from_slice(&self.old_state.index.to_le_bytes());
        raw.extend_from_slice(&self.transaction_hash);
        raw.extend_from_slice(&self.carrier_capacity.to_le_bytes());
        raw.extend_from_slice(&self.before.encode()?);
        raw.extend_from_slice(&self.after.encode()?);
        for signature in signatures {
            raw.extend_from_slice(signature);
        }
        for member in &self.members {
            raw.extend_from_slice(&member.participant);
            raw.extend_from_slice(&member.pubkey_sec1);
        }
        raw.extend_from_slice(&source);
        raw.extend_from_slice(&encode_multi_asset_outpoints(&self.source_outpoints)?);
        raw.extend_from_slice(&retained);
        raw.extend_from_slice(&table_bytes);
        if own_types {
            for script in &self.type_scripts {
                raw.push(table.index_of(&script.script)? as u8);
            }
        }
        for payout in &self.payouts {
            let mut asset = [0; 33];
            crate::multi_asset::wire_asset(&payout.asset).encode(&mut asset)?;
            raw.extend_from_slice(&asset);
            let mut allocation = [0; 32];
            payout.value.wire().encode(&mut allocation)?;
            raw.extend_from_slice(&allocation);
            raw.extend_from_slice(&(table.index_of(&payout.lock_script)? as u16).to_le_bytes());
            raw.extend_from_slice(&payout.output_index.to_le_bytes());
        }
        for right in &self.rights {
            if right.before.right.id != right.after.right.id {
                return invalid();
            }
            encode_right(&mut raw, &right.before.right);
            raw.extend_from_slice(&right.after.right.quantity.to_le_bytes());
            encode_proof(&mut raw, &right.before)?;
            encode_proof(&mut raw, &right.after)?;
        }
        Ok(raw)
    }
    fn encode_frame(
        &self,
        signatures: &[[u8; 64]],
        require_private_exits: bool,
    ) -> MultiAssetResult<Vec<u8>> {
        let mut raw = self.encode_base_frame(signatures)?;
        if let Some(materialisation) = &self.materialisation {
            // This call checks both child recovery signatures before a Factory
            // signing digest can be returned. Exit signatures remain private.
            let intent = if require_private_exits {
                materialisation.encode_intent()?
            } else {
                materialisation.encode_public_intent()?
            };
            raw.extend_from_slice(&(intent.len() as u32).to_le_bytes());
            raw.extend_from_slice(&intent);
            for child in &materialisation.children {
                for participant in &child.recovery.authorization.signatures {
                    raw.extend_from_slice(&participant.pubkey_sec1);
                }
            }
        }
        Ok(raw)
    }
    /// Explicitly fills the successor's non-interference digest. Call before
    /// constructing the exact transaction that contains the successor header.
    /// This digest excludes the raw transaction hash and itself, avoiding a
    /// transaction/header fixed point. The final signature binds the exact
    /// transaction hash independently after construction.
    pub fn set_locality_digest(&mut self) -> MultiAssetResult<()> {
        let raw = self.encode_base_frame(&vec![[0; 64]; self.signature_count()])?;
        let signature_end = 788
            + if self.operation.is_full() {
                (self.members.len() - 1) * 64
            } else {
                0
            };
        self.after.non_interference_digest =
            wire::factory_transition_locality_digest(&raw, signature_end)?;
        Ok(())
    }
    pub fn encode_unsigned(&self) -> MultiAssetResult<Vec<u8>> {
        let raw = self.encode_frame(&vec![[0; 64]; self.signature_count()], true)?;
        wire::FactoryReducedReleaseWitness::parse(&raw)?.validate_transition()?;
        Ok(raw)
    }
    /// Public review before private child exits exist. This creates no parent
    /// authorization; the signer journal requires both possession attestations.
    pub fn encode_public_unsigned(&self) -> MultiAssetResult<Vec<u8>> {
        let raw = self.encode_frame(&vec![[0; 64]; self.signature_count()], false)?;
        wire::FactoryReducedReleaseWitness::parse(&raw)?.validate_transition()?;
        Ok(raw)
    }
    pub fn signing_digest(&self) -> MultiAssetResult<Bytes32> {
        let raw = self.encode_unsigned()?;
        Ok(wire::FactoryReducedReleaseWitness::parse(&raw)?.signing_digest())
    }
    pub fn encode_witness(&self, signature: &[u8; 64]) -> MultiAssetResult<Vec<u8>> {
        self.encode_authorized(&[*signature])
    }
    /// Exact role-ordered N-of-N signatures for full metadata/custody changes.
    pub fn encode_authorized(&self, signatures: &[[u8; 64]]) -> MultiAssetResult<Vec<u8>> {
        let raw = self.encode_frame(signatures, true)?;
        wire::FactoryReducedReleaseWitness::parse(&raw)?.verify()?;
        Ok(raw)
    }
}

/// Add role-ordered authorizations through the sole current wire codec.
pub fn authorize_factory_transition(
    raw: &[u8],
    signatures: &[[u8; 64]],
) -> MultiAssetResult<Vec<u8>> {
    let proof = wire::FactoryReducedReleaseWitness::parse(raw)?;
    let mut authorized = raw.to_vec();
    proof.write_signatures(signatures, &mut authorized)?;
    Ok(authorized)
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum FactoryRightsRefreshError {
    #[error("the retained Factory rights data does not match its committed root")]
    InvalidSnapshot,
    #[error("invalid current Factory transition: {0:?}")]
    InvalidTransition(ScriptError),
    #[error("full-consent root replacement requires delivery of its complete new rights data")]
    FullSnapshotRequired,
}
/// Full root data is recovery evidence, never an independent signing journal.
/// Keep it with each member's package backup. Reduced transactions publicly
/// reveal their localized changed leaves, so an uninvolved member can update
/// this data and regenerate their current proof without contacting a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactoryRightsSnapshot {
    pub chain_id: Bytes32,
    pub factory_id: Bytes32,
    pub update_number: u64,
    pub state_root: Bytes32,
    pub rights: Vec<FactoryRight>,
}
impl FactoryRightsSnapshot {
    pub fn validate(&self) -> Result<(), FactoryRightsRefreshError> {
        if self.rights.windows(2).any(|pair| pair[0].id >= pair[1].id)
            || crate::factory_right_sparse_root(&self.rights)
                .map_err(|_| FactoryRightsRefreshError::InvalidSnapshot)?
                != self.state_root
        {
            return Err(FactoryRightsRefreshError::InvalidSnapshot);
        }
        Ok(())
    }
    /// Apply only after the exact transaction has been canonically confirmed
    /// by the journal's chain guard. This pure root-data transformation does
    /// not assert transaction inclusion, finality or signer freshness.
    pub fn apply_transition(&self, frame: &[u8]) -> Result<Self, FactoryRightsRefreshError> {
        self.validate()?;
        let proof = wire::FactoryReducedReleaseWitness::parse(frame)
            .map_err(FactoryRightsRefreshError::InvalidTransition)?;
        proof
            .verify()
            .map_err(FactoryRightsRefreshError::InvalidTransition)?;
        if proof.before().chain_id() != self.chain_id
            || proof.before().factory_id() != self.factory_id
            || proof.before().update_number() != self.update_number
            || proof.before().state_root() != self.state_root
        {
            return Err(FactoryRightsRefreshError::InvalidSnapshot);
        }
        let mut next = self.clone();
        for i in 0..proof.right_count() {
            let change = proof
                .right(i)
                .map_err(FactoryRightsRefreshError::InvalidTransition)?;
            let id = decode_right_id(&change.before)?;
            let index = next
                .rights
                .binary_search_by(|right| right.id.cmp(&id))
                .map_err(|_| FactoryRightsRefreshError::InvalidSnapshot)?;
            if next.rights[index].quantity != change.before.quantity() {
                return Err(FactoryRightsRefreshError::InvalidSnapshot);
            }
            next.rights[index].quantity = change.after.quantity();
        }
        let mut root = [0; 32];
        root.copy_from_slice(proof.after().state_root());
        next.update_number = proof.after().update_number();
        next.state_root = root;
        if next.validate().is_err() {
            return Err(if proof.operation().is_full() {
                FactoryRightsRefreshError::FullSnapshotRequired
            } else {
                FactoryRightsRefreshError::InvalidSnapshot
            });
        }
        Ok(next)
    }
    /// A new full-consent allocation is explicitly delivered; never infer its
    /// leaves from a root hash, retain an old proof, or contact a missing peer.
    /// The caller must verify the exact full-consent authorization and chain
    /// inclusion independently before accepting this read-only data snapshot.
    pub fn accept_full_snapshot(
        &self,
        after: &FactoryMultiAssetHeaderFields,
        rights: Vec<FactoryRight>,
    ) -> Result<Self, FactoryRightsRefreshError> {
        self.validate()?;
        if after.chain_id != self.chain_id
            || after.factory_id != self.factory_id
            || after.update_number
                != self
                    .update_number
                    .checked_add(1)
                    .ok_or(FactoryRightsRefreshError::InvalidSnapshot)?
        {
            return Err(FactoryRightsRefreshError::InvalidSnapshot);
        }
        let next = Self {
            chain_id: self.chain_id,
            factory_id: self.factory_id,
            update_number: after.update_number,
            state_root: after.state_root,
            rights,
        };
        next.validate()?;
        Ok(next)
    }
    pub fn proof(
        &self,
        id: &crate::FactoryRightId,
    ) -> Result<FactoryCompactRightProof, FactoryRightsRefreshError> {
        self.validate()?;
        crate::factory_right_sparse_proof_compact(&self.rights, id)
            .map_err(|_| FactoryRightsRefreshError::InvalidSnapshot)
    }
}
fn decode_right_id(
    right: &morph_script_common::FactoryRight<'_>,
) -> Result<crate::FactoryRightId, FactoryRightsRefreshError> {
    let mut participant = [0; 32];
    participant.copy_from_slice(right.participant());
    let mut subchannel = [0; 32];
    subchannel.copy_from_slice(right.subchannel());
    let kind = match right.kind() {
        0 => FactoryRightKind::Balance,
        1 => FactoryRightKind::ReserveClaim,
        2 => FactoryRightKind::Membership,
        3 => FactoryRightKind::ExitPath,
        4 => FactoryRightKind::SponsorBudgetClaim,
        _ => return Err(FactoryRightsRefreshError::InvalidSnapshot),
    };
    let asset_type = if right.asset_present() == 1 {
        let mut hash = [0; 32];
        hash.copy_from_slice(right.asset_type());
        Some(hash)
    } else {
        None
    };
    Ok(crate::FactoryRightId {
        participant,
        subchannel,
        kind,
        asset_type,
    })
}

/// Strip only current Factory authorizations to create a reviewed proposal.
pub fn unsigned_factory_transition(raw: &[u8]) -> MultiAssetResult<Vec<u8>> {
    let proof = wire::FactoryReducedReleaseWitness::parse(raw)?;
    let mut unsigned = raw.to_vec();
    proof.write_unsigned(&mut unsigned)?;
    Ok(unsigned)
}
