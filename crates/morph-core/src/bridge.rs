//! Sovereign Factory-right -> materialised Channel -> provider-edge lifecycle.
//!
//! A routing provider mirrors `ProviderEdgeDescriptor`; it is never the source
//! of truth for Factory rights, Morph script identity, or channel settlement.

use std::collections::{BTreeMap, BTreeSet};

use k256::ecdsa::VerifyingKey;
use morph_script_common::multi_asset::{
    MultiAssetStateHeader, multi_asset_occupied_capacity, multi_asset_script_occupied_bytes,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::agent::AgentAsset;
use crate::backend::{ChannelParticipant, validate_participant_identities};
use crate::rgbpp::CkbOutPoint;
use crate::{
    Amount, Bytes32, FactoryRightId, FactoryRightKind, FactoryRightMerkleProof, Mode,
    MultiAssetError, MultiAssetRecoveryPackage, Phase, StateAuthorization, VaultAsset, blake2b256,
    factory_right_leaf_hash, verify_factory_right_merkle_proof,
};

const DEPLOYMENT_ID_DOMAIN: &[u8] = b"CKB_MORPH_DEPLOYMENT_ID_V1";
const FACTORY_RESERVATION_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_RESERVATION_V1";
const FACTORY_RIGHT_PROOF_DOMAIN: &[u8] = b"CKB_MORPH_FACTORY_RIGHT_PROOF_V1";
const EDGE_DESCRIPTOR_DOMAIN: &[u8] = b"CKB_MORPH_PROVIDER_EDGE_V1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedScriptIdentity {
    pub code_hash: Bytes32,
    pub hash_type: u8,
}
impl TrustedScriptIdentity {
    fn validate(&self) -> BridgeResult<()> {
        if is_zero(&self.code_hash) || !matches!(self.hash_type, 0 | 1 | 2 | 4) {
            return Err(BridgeError::InvalidDeployment);
        }
        Ok(())
    }
    fn matches(&self, script: &[u8]) -> BridgeResult<()> {
        multi_asset_script_occupied_bytes(script).map_err(|_| BridgeError::UntrustedDeployment)?;
        if script[16..48] != self.code_hash || script[48] != self.hash_type {
            return Err(BridgeError::UntrustedDeployment);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedMorphDeployment {
    pub ckb_genesis_hash: Bytes32,
    pub state_type: TrustedScriptIdentity,
    pub state_lock: TrustedScriptIdentity,
    pub vault_lock: TrustedScriptIdentity,
    pub factory_type: TrustedScriptIdentity,
    pub factory_vault_lock: TrustedScriptIdentity,
}
impl TrustedMorphDeployment {
    pub fn validate(&self) -> BridgeResult<()> {
        if is_zero(&self.ckb_genesis_hash) {
            return Err(BridgeError::InvalidDeployment);
        }
        for identity in [
            &self.state_type,
            &self.state_lock,
            &self.vault_lock,
            &self.factory_type,
            &self.factory_vault_lock,
        ] {
            identity.validate()?;
        }
        Ok(())
    }
    pub fn deployment_id(&self) -> BridgeResult<Bytes32> {
        self.validate()?;
        let mut raw = DEPLOYMENT_ID_DOMAIN.to_vec();
        raw.extend_from_slice(&self.ckb_genesis_hash);
        for identity in [
            &self.state_type,
            &self.state_lock,
            &self.vault_lock,
            &self.factory_type,
            &self.factory_vault_lock,
        ] {
            raw.extend_from_slice(&identity.code_hash);
            raw.push(identity.hash_type);
        }
        Ok(blake2b256(&raw))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryRightReservation {
    pub reservation_id: Bytes32,
    pub factory_id: Bytes32,
    pub factory_update_number: u64,
    pub right: FactoryRightId,
    pub quantity: Amount,
    pub factory_state_root: Bytes32,
    pub access_manifest_root: Bytes32,
    pub right_proof: FactoryRightMerkleProof,
    pub proof_commitment: Bytes32,
    pub idempotency_key: Bytes32,
    pub reserved_at_unix: u64,
    pub expires_at_unix: u64,
}

impl FactoryRightReservation {
    pub fn derive_id(&self) -> BridgeResult<Bytes32> {
        self.validate_fields(false)?;
        let mut raw = Vec::with_capacity(FACTORY_RESERVATION_DOMAIN.len() + 320);
        raw.extend_from_slice(FACTORY_RESERVATION_DOMAIN);
        raw.extend_from_slice(&self.factory_id);
        raw.extend_from_slice(&self.factory_update_number.to_le_bytes());
        encode_right_id(&self.right, &mut raw);
        raw.extend_from_slice(&self.quantity.to_le_bytes());
        raw.extend_from_slice(&self.factory_state_root);
        raw.extend_from_slice(&self.access_manifest_root);
        raw.extend_from_slice(&self.proof_commitment);
        raw.extend_from_slice(&self.idempotency_key);
        raw.extend_from_slice(&self.reserved_at_unix.to_le_bytes());
        raw.extend_from_slice(&self.expires_at_unix.to_le_bytes());
        Ok(blake2b256(&raw))
    }

    pub fn validate(&self, now_unix: u64) -> BridgeResult<()> {
        self.validate_fields(true)?;
        if self.reservation_id != self.derive_id()? {
            return Err(BridgeError::ReservationIdMismatch);
        }
        if now_unix < self.reserved_at_unix {
            return Err(BridgeError::ReservationNotYetValid);
        }
        if now_unix >= self.expires_at_unix {
            return Err(BridgeError::ReservationExpired);
        }
        Ok(())
    }

    fn validate_fields(&self, check_id: bool) -> BridgeResult<()> {
        if check_id && is_zero(&self.reservation_id) {
            return Err(BridgeError::InvalidReservation);
        }
        if is_zero(&self.factory_id)
            || is_zero(&self.right.participant)
            || is_zero(&self.right.subchannel)
            || self.right.asset_type.is_some_and(|asset| is_zero(&asset))
            || self.quantity == 0
            || is_zero(&self.factory_state_root)
            || is_zero(&self.access_manifest_root)
            || is_zero(&self.proof_commitment)
            || is_zero(&self.idempotency_key)
            || self.expires_at_unix <= self.reserved_at_unix
        {
            return Err(BridgeError::InvalidReservation);
        }
        if !matches!(
            self.right.kind,
            FactoryRightKind::Balance | FactoryRightKind::ReserveClaim
        ) {
            return Err(BridgeError::UnsupportedFactoryRight);
        }
        if self.right_proof.right.id != self.right
            || self.right_proof.right.quantity < self.quantity
            || self.proof_commitment != factory_right_proof_commitment(&self.right_proof)
        {
            return Err(BridgeError::InvalidFactoryProof);
        }
        verify_factory_right_merkle_proof(self.factory_state_root, &self.right_proof)
            .map_err(|_| BridgeError::InvalidFactoryProof)?;
        Ok(())
    }
}

pub fn factory_right_proof_commitment(proof: &FactoryRightMerkleProof) -> Bytes32 {
    let mut raw =
        Vec::with_capacity(FACTORY_RIGHT_PROOF_DOMAIN.len() + 64 + proof.siblings.len() * 33);
    raw.extend_from_slice(FACTORY_RIGHT_PROOF_DOMAIN);
    raw.extend_from_slice(&factory_right_leaf_hash(&proof.right));
    raw.extend_from_slice(&(proof.siblings.len() as u16).to_le_bytes());
    for sibling in &proof.siblings {
        raw.push(match sibling.side {
            crate::FactoryMerkleSiblingSide::Left => 0,
            crate::FactoryMerkleSiblingSide::Right => 1,
        });
        raw.extend_from_slice(&sibling.hash);
    }
    blake2b256(&raw)
}

/// Actual full Cell returned by the canonical-chain observer. Hash-only claims
/// cannot establish either script identity or occupied capacity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializedCellEvidence {
    pub out_point: CkbOutPoint,
    pub lock: Vec<u8>,
    #[serde(deserialize_with = "required_option")]
    pub type_script: Option<Vec<u8>>,
    pub capacity: u64,
    pub data: Vec<u8>,
}
impl MaterializedCellEvidence {
    fn validate(&self) -> BridgeResult<()> {
        let occupied = multi_asset_occupied_capacity(
            &self.lock,
            self.type_script.as_deref(),
            self.data.len() as u64,
        )
        .map_err(|_| BridgeError::InvalidMaterialisation)?;
        if is_zero(&self.out_point.tx_hash) || self.capacity < occupied {
            return Err(BridgeError::InvalidMaterialisation);
        }
        Ok(())
    }
}

/// Child Type args commit the full Factory Type hash. The canonical-chain
/// observer also establishes the reserve script's association with that
/// materialisation history; its bytes and arguments are checked here. No live
/// parent or fresh parent signature is required to use the independent child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryOriginEvidence {
    /// Historical canonical source, retained after the parent is spent.
    pub source: crate::FactoryCustody,
    pub members: Vec<crate::FactoryParticipantKey>,
}

/// Complete current custody plus latest private co-signed recovery. The caller
/// must establish that `state` and every Vault are live in the named canonical
/// block and supply independently checked confirmations. This pure host model
/// validates content and authority; it is not a CKB RPC/chain oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializedChannelEvidence {
    pub recovery: MultiAssetRecoveryPackage,
    pub state: MaterializedCellEvidence,
    /// Exact manifest order, with no extra, missing or substituted Cell.
    pub vaults: Vec<MaterializedCellEvidence>,
    pub participants: [ChannelParticipant; 2],
    pub asset: AgentAsset,
    #[serde(deserialize_with = "required_option")]
    pub factory_reservation_id: Option<Bytes32>,
    #[serde(deserialize_with = "required_option")]
    pub factory_origin: Option<FactoryOriginEvidence>,
    pub committed_block_hash: Bytes32,
    pub committed_block_number: u64,
    pub confirmations: u64,
    #[serde(deserialize_with = "required_option")]
    pub rgbpp_proof_commitment: Option<Bytes32>,
}

fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderEdgeDescriptor {
    pub edge_id: Bytes32,
    pub channel_id: Bytes32,
    pub funding_context_id: Bytes32,
    pub funding_epoch: u64,
    pub state_number: u64,
    pub participants: [Bytes32; 2],
    /// State-signer keys corresponding positionally to `participants`.
    pub participant_pubkeys_sec1: [Vec<u8>; 2],
    pub asset: AgentAsset,
    pub directional_liquidity: [Amount; 2],
    pub deployment_id: Bytes32,
    pub factory_id: Option<Bytes32>,
    pub factory_update_number: Option<u64>,
    pub factory_reservation_id: Option<Bytes32>,
    pub evidence_block_hash: Bytes32,
    pub evidence_block_number: u64,
    pub opaque_morph_commitment: Bytes32,
}

impl ProviderEdgeDescriptor {
    pub fn derive_id(&self) -> BridgeResult<Bytes32> {
        self.asset.validate()?;
        if [
            self.channel_id,
            self.funding_context_id,
            self.participants[0],
            self.participants[1],
            self.deployment_id,
            self.evidence_block_hash,
            self.opaque_morph_commitment,
        ]
        .iter()
        .any(is_zero)
            || self.participants[0] == self.participants[1]
            || self.directional_liquidity.iter().all(|amount| *amount == 0)
        {
            return Err(BridgeError::InvalidMaterialisation);
        }
        for (participant, public_key) in self
            .participants
            .iter()
            .zip(self.participant_pubkeys_sec1.iter())
        {
            let key = VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| BridgeError::InvalidMaterialisation)?;
            if key.to_encoded_point(true).as_bytes() != public_key
                || blake2b256(public_key) != *participant
            {
                return Err(BridgeError::InvalidMaterialisation);
            }
        }
        let mut raw = Vec::with_capacity(EDGE_DESCRIPTOR_DOMAIN.len() + 480);
        raw.extend_from_slice(EDGE_DESCRIPTOR_DOMAIN);
        raw.extend_from_slice(&self.channel_id);
        raw.extend_from_slice(&self.funding_context_id);
        raw.extend_from_slice(&self.funding_epoch.to_le_bytes());
        raw.extend_from_slice(&self.participants[0]);
        raw.extend_from_slice(&self.participants[1]);
        raw.extend_from_slice(&self.participant_pubkeys_sec1[0]);
        raw.extend_from_slice(&self.participant_pubkeys_sec1[1]);
        raw.extend_from_slice(&self.asset.commitment()?);
        raw.extend_from_slice(&self.deployment_id);
        encode_option_bytes32(self.factory_id, &mut raw);
        match self.factory_update_number {
            Some(value) => {
                raw.push(1);
                raw.extend_from_slice(&value.to_le_bytes());
            }
            None => raw.push(0),
        }
        encode_option_bytes32(self.factory_reservation_id, &mut raw);
        Ok(blake2b256(&raw))
    }
}

/// Validate a coherent batch of provider projections. Each item still needs
/// verified custody as its source; this structural check prevents adapters from
/// combining two states of one channel or counting the same physical Type twice.
pub fn validate_provider_edge_set(edges: &[ProviderEdgeDescriptor]) -> BridgeResult<()> {
    let mut assets = BTreeSet::new();
    let mut channels: BTreeMap<Bytes32, &ProviderEdgeDescriptor> = BTreeMap::new();
    for edge in edges {
        if edge.edge_id != edge.derive_id()? {
            return Err(BridgeError::InvalidMaterialisation);
        }
        if !assets.insert((edge.channel_id, routing_asset_commitment(&edge.asset)?)) {
            return Err(BridgeError::AssetAliasConflict);
        }
        if let Some(previous) = channels.insert(edge.channel_id, edge) {
            let mut before = previous.participants;
            let mut after = edge.participants;
            before.sort();
            after.sort();
            if previous.funding_context_id != edge.funding_context_id
                || previous.funding_epoch != edge.funding_epoch
                || previous.deployment_id != edge.deployment_id
                || asset_ckb_genesis_hash(&previous.asset) != asset_ckb_genesis_hash(&edge.asset)
                || before != after
            {
                return Err(BridgeError::ActiveEdgeConflict);
            }
            if previous.state_number != edge.state_number
                || previous.opaque_morph_commitment != edge.opaque_morph_commitment
            {
                return Err(BridgeError::StaleEdgeEvidence);
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeLifecycle {
    Reserved,
    Materializing,
    Active(ProviderEdgeDescriptor),
    Draining(ProviderEdgeDescriptor),
    Disabled {
        edge: ProviderEdgeDescriptor,
        reason: String,
        disabled_at_unix: u64,
    },
    Invalidated {
        edge: ProviderEdgeDescriptor,
        reason: String,
        invalidated_at_unix: u64,
    },
}

type ChannelAssetKey = (Bytes32, Bytes32);

// Private durable maps are explicit entry arrays. Byte32/tuple JSON object
// keys are not valid serde_json maps; duplicate entries remain rejected.
mod map_entries {
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};
    use std::collections::BTreeMap;
    pub fn serialize<S: Serializer, K: Serialize, V: Serialize>(
        map: &BTreeMap<K, V>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(map.iter())
    }
    pub fn deserialize<
        'de,
        D: Deserializer<'de>,
        K: Deserialize<'de> + Ord,
        V: Deserialize<'de>,
    >(
        deserializer: D,
    ) -> Result<BTreeMap<K, V>, D::Error> {
        let entries = Vec::<(K, V)>::deserialize(deserializer)?;
        let count = entries.len();
        let map: BTreeMap<_, _> = entries.into_iter().collect();
        if map.len() != count {
            return Err(D::Error::custom("duplicate registry map key"));
        }
        Ok(map)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SovereignEdgeRegistry {
    #[serde(with = "map_entries")]
    reservations: BTreeMap<Bytes32, FactoryRightReservation>,
    #[serde(with = "map_entries")]
    reservation_idempotency: BTreeMap<Bytes32, Bytes32>,
    #[serde(with = "map_entries")]
    lifecycles: BTreeMap<Bytes32, EdgeLifecycle>,
    #[serde(with = "map_entries")]
    channel_edges: BTreeMap<ChannelAssetKey, Bytes32>,
}

impl SovereignEdgeRegistry {
    pub fn reserve(
        &mut self,
        reservation: FactoryRightReservation,
        now_unix: u64,
    ) -> BridgeResult<Bytes32> {
        reservation.validate(now_unix)?;
        if let Some(existing) = self
            .reservation_idempotency
            .get(&reservation.idempotency_key)
        {
            if existing == &reservation.reservation_id {
                return Ok(*existing);
            }
            return Err(BridgeError::IdempotencyConflict);
        }
        if self.reservations.contains_key(&reservation.reservation_id) {
            return Err(BridgeError::ReservationConflict);
        }
        self.reservation_idempotency
            .insert(reservation.idempotency_key, reservation.reservation_id);
        self.lifecycles
            .insert(reservation.reservation_id, EdgeLifecycle::Reserved);
        self.reservations
            .insert(reservation.reservation_id, reservation.clone());
        Ok(reservation.reservation_id)
    }
    pub fn begin_materialisation(&mut self, reservation_id: &Bytes32) -> BridgeResult<()> {
        match self.lifecycles.get_mut(reservation_id) {
            Some(lifecycle @ EdgeLifecycle::Reserved) => {
                *lifecycle = EdgeLifecycle::Materializing;
                Ok(())
            }
            _ => Err(BridgeError::InvalidLifecycle),
        }
    }
    pub fn activate(
        &mut self,
        evidence: MaterializedChannelEvidence,
        deployment: &TrustedMorphDeployment,
        minimum_confirmations: u64,
        now_unix: u64,
    ) -> BridgeResult<ProviderEdgeDescriptor> {
        let reservation = evidence
            .factory_reservation_id
            .map(|id| {
                self.reservations
                    .get(&id)
                    .ok_or(BridgeError::ReservationNotFound)
            })
            .transpose()?;
        if let Some(reservation) = reservation {
            reservation.validate(now_unix)?;
            if !matches!(
                self.lifecycles.get(&reservation.reservation_id),
                Some(
                    EdgeLifecycle::Materializing
                        | EdgeLifecycle::Active(_)
                        | EdgeLifecycle::Draining(_)
                )
            ) {
                return Err(BridgeError::InvalidLifecycle);
            }
        }
        let edge = derive_edge(
            &evidence,
            reservation,
            deployment,
            minimum_confirmations,
            true,
        )?;
        self.require_current_channel_view(&edge)?;
        let key = (edge.channel_id, routing_asset_commitment(&edge.asset)?);
        if let Some(existing) = self.channel_edges.get(&key)
            && let Some(EdgeLifecycle::Active(previous) | EdgeLifecycle::Draining(previous)) =
                self.lifecycles.get(existing)
        {
            return if previous == &edge {
                Ok(previous.clone())
            } else {
                Err(BridgeError::ActiveEdgeConflict)
            };
        }
        let lifecycle_key = evidence.factory_reservation_id.unwrap_or(edge.edge_id);
        self.channel_edges.insert(key, lifecycle_key);
        self.lifecycles
            .insert(lifecycle_key, EdgeLifecycle::Active(edge.clone()));
        Ok(edge)
    }
    pub fn begin_draining(&mut self, channel_id: &Bytes32, asset: &AgentAsset) -> BridgeResult<()> {
        let key = *self
            .channel_edges
            .get(&(*channel_id, routing_asset_commitment(asset)?))
            .ok_or(BridgeError::EdgeNotFound)?;
        let edge = match self.lifecycles.get(&key) {
            Some(EdgeLifecycle::Active(edge)) => edge.clone(),
            _ => return Err(BridgeError::InvalidLifecycle),
        };
        if edge.asset != *asset {
            return Err(BridgeError::AssetAliasConflict);
        }
        self.lifecycles.insert(key, EdgeLifecycle::Draining(edge));
        Ok(())
    }
    /// Liquidity refresh preserves stable identity. A splice needs explicit
    /// drain/disable/activate for this asset; another asset is a distinct edge.
    pub fn refresh(
        &mut self,
        evidence: MaterializedChannelEvidence,
        deployment: &TrustedMorphDeployment,
        minimum_confirmations: u64,
    ) -> BridgeResult<ProviderEdgeDescriptor> {
        let key = *self
            .channel_edges
            .get(&(
                evidence.recovery.state.header.channel_id,
                routing_asset_commitment(&evidence.asset)?,
            ))
            .ok_or(BridgeError::EdgeNotFound)?;
        let (previous, draining) = match self.lifecycles.get(&key) {
            Some(EdgeLifecycle::Active(edge)) => (edge.clone(), false),
            Some(EdgeLifecycle::Draining(edge)) => (edge.clone(), true),
            _ => return Err(BridgeError::InvalidLifecycle),
        };
        let reservation = evidence
            .factory_reservation_id
            .map(|id| {
                self.reservations
                    .get(&id)
                    .ok_or(BridgeError::ReservationNotFound)
            })
            .transpose()?;
        let refreshed = derive_edge(
            &evidence,
            reservation,
            deployment,
            minimum_confirmations,
            false,
        )?;
        self.require_current_channel_view(&refreshed)?;
        if refreshed.edge_id != previous.edge_id
            || refreshed.funding_context_id != previous.funding_context_id
            || refreshed.state_number <= previous.state_number
            || refreshed.evidence_block_number < previous.evidence_block_number
        {
            return Err(BridgeError::StaleEdgeEvidence);
        }
        self.lifecycles.insert(
            key,
            if draining {
                EdgeLifecycle::Draining(refreshed.clone())
            } else {
                EdgeLifecycle::Active(refreshed.clone())
            },
        );
        Ok(refreshed)
    }
    pub fn disable(
        &mut self,
        channel_id: &Bytes32,
        asset: &AgentAsset,
        reason: String,
        disabled_at_unix: u64,
    ) -> BridgeResult<()> {
        validate_reason(&reason)?;
        let key = *self
            .channel_edges
            .get(&(*channel_id, routing_asset_commitment(asset)?))
            .ok_or(BridgeError::EdgeNotFound)?;
        let edge = match self.lifecycles.get(&key) {
            Some(EdgeLifecycle::Active(edge) | EdgeLifecycle::Draining(edge)) => edge.clone(),
            _ => return Err(BridgeError::InvalidLifecycle),
        };
        if edge.asset != *asset {
            return Err(BridgeError::AssetAliasConflict);
        }
        self.lifecycles.insert(
            key,
            EdgeLifecycle::Disabled {
                edge,
                reason,
                disabled_at_unix,
            },
        );
        Ok(())
    }
    pub fn invalidate(
        &mut self,
        channel_id: &Bytes32,
        asset: &AgentAsset,
        reason: String,
        invalidated_at_unix: u64,
    ) -> BridgeResult<()> {
        validate_reason(&reason)?;
        let key = *self
            .channel_edges
            .get(&(*channel_id, routing_asset_commitment(asset)?))
            .ok_or(BridgeError::EdgeNotFound)?;
        let edge = match self.lifecycles.get(&key) {
            Some(
                EdgeLifecycle::Active(edge)
                | EdgeLifecycle::Draining(edge)
                | EdgeLifecycle::Disabled { edge, .. },
            ) => edge.clone(),
            _ => return Err(BridgeError::InvalidLifecycle),
        };
        if edge.asset != *asset {
            return Err(BridgeError::AssetAliasConflict);
        }
        self.lifecycles.insert(
            key,
            EdgeLifecycle::Invalidated {
                edge,
                reason,
                invalidated_at_unix,
            },
        );
        Ok(())
    }
    pub fn lifecycle(&self, key: &Bytes32) -> Option<&EdgeLifecycle> {
        self.lifecycles.get(key)
    }
    pub fn edge_for_channel(
        &self,
        channel_id: &Bytes32,
        asset: &AgentAsset,
    ) -> BridgeResult<Option<&ProviderEdgeDescriptor>> {
        let Some(key) = self
            .channel_edges
            .get(&(*channel_id, routing_asset_commitment(asset)?))
        else {
            return Ok(None);
        };
        let edge = match self.lifecycles.get(key) {
            Some(
                EdgeLifecycle::Active(edge)
                | EdgeLifecycle::Draining(edge)
                | EdgeLifecycle::Disabled { edge, .. }
                | EdgeLifecycle::Invalidated { edge, .. },
            ) => Some(edge),
            _ => None,
        };
        if let Some(edge) = edge {
            if edge.asset != *asset {
                return Err(BridgeError::AssetAliasConflict);
            }
            self.require_current_channel_view(edge)?;
        }
        Ok(edge)
    }
    /// Every asset shares one signed State track. A newer complete state seen
    /// through one edge makes older views of every other asset stale; callers
    /// must refresh those projections before advertising them again.
    fn require_current_channel_view(&self, proposed: &ProviderEdgeDescriptor) -> BridgeResult<()> {
        for ((channel_id, _), key) in &self.channel_edges {
            if *channel_id != proposed.channel_id {
                continue;
            }
            let (known, live) = match self.lifecycles.get(key) {
                Some(EdgeLifecycle::Active(edge) | EdgeLifecycle::Draining(edge)) => (edge, true),
                Some(
                    EdgeLifecycle::Disabled { edge, .. } | EdgeLifecycle::Invalidated { edge, .. },
                ) => (edge, false),
                _ => continue,
            };
            if known.funding_context_id != proposed.funding_context_id {
                if live {
                    return Err(BridgeError::ActiveEdgeConflict);
                }
                continue;
            }
            if known.state_number > proposed.state_number
                || (known.state_number == proposed.state_number
                    && known.opaque_morph_commitment != proposed.opaque_morph_commitment)
            {
                return Err(BridgeError::StaleEdgeEvidence);
            }
        }
        Ok(())
    }
}
fn validate_reason(reason: &str) -> BridgeResult<()> {
    if reason.trim().is_empty() || reason.len() > 256 {
        return Err(BridgeError::InvalidReason);
    }
    Ok(())
}

/// RGB++ and a native xUDT view of the same Type share one physical balance.
/// They must never each advertise that full balance as separate liquidity.
fn routing_asset_commitment(asset: &AgentAsset) -> BridgeResult<Bytes32> {
    let physical = match asset {
        AgentAsset::Rgbpp(asset) => AgentAsset::Xudt {
            ckb_genesis_hash: asset.ckb_genesis_hash,
            type_script_hash: asset.xudt_type_script_hash,
        },
        _ => asset.clone(),
    };
    Ok(physical.commitment()?)
}

fn derive_edge(
    evidence: &MaterializedChannelEvidence,
    reservation: Option<&FactoryRightReservation>,
    deployment: &TrustedMorphDeployment,
    minimum_confirmations: u64,
    enforce_reservation_quantity: bool,
) -> BridgeResult<ProviderEdgeDescriptor> {
    deployment.validate()?;
    evidence.asset.validate()?;
    if minimum_confirmations == 0 || evidence.confirmations < minimum_confirmations {
        return Err(BridgeError::InsufficientConfirmations);
    }
    if is_zero(&evidence.committed_block_hash) || evidence.committed_block_number == 0 {
        return Err(BridgeError::InvalidMaterialisation);
    }
    let recovery = &evidence.recovery;
    recovery.validate()?;
    if recovery.state.header.phase != Phase::Settling
        || recovery.outpoints.len() != recovery.manifest.vaults.len()
    {
        return Err(BridgeError::InvalidMaterialisation);
    }
    if recovery.state.header.chain_id != deployment.ckb_genesis_hash
        || asset_ckb_genesis_hash(&evidence.asset) != &deployment.ckb_genesis_hash
    {
        return Err(BridgeError::WrongNetwork);
    }
    if recovery.state.header.mode != Mode::BilateralPlain {
        return Err(BridgeError::InvalidMaterialisation);
    }
    deployment
        .state_type
        .matches(&recovery.scripts.state_type)?;
    deployment
        .state_lock
        .matches(&recovery.scripts.state_lock)?;
    deployment
        .vault_lock
        .matches(&recovery.scripts.vault_lock)?;
    evidence.state.validate()?;
    if evidence.state.lock != recovery.scripts.state_lock
        || evidence.state.type_script.as_ref() != Some(&recovery.scripts.state_type)
        || evidence.state.capacity != recovery.state_carrier_capacity
    {
        return Err(BridgeError::InvalidMaterialisation);
    }
    let actual = MultiAssetStateHeader::parse(&evidence.state.data)
        .map_err(|_| BridgeError::InvalidMaterialisation)?;
    let saved_raw = recovery.state.encode()?;
    let saved = MultiAssetStateHeader::parse(&saved_raw)
        .map_err(|_| BridgeError::InvalidMaterialisation)?;
    if !actual.vaults_are_bound()
        || !actual.same_context_except_progress(&saved)
        || actual.state_number() > saved.state_number()
        || (actual.state_number() == saved.state_number() && actual.as_bytes() != saved.as_bytes())
    {
        return Err(BridgeError::InvalidMaterialisation);
    }
    validate_complete_vaults(evidence)?;
    validate_participant_identities(&recovery.authorization, &evidence.participants)
        .map_err(|_| BridgeError::InvalidMaterialisation)?;
    let allocation = directional_asset_liquidity(recovery, &evidence.asset)?;
    let participant_liquidity = |participant: &ChannelParticipant| -> BridgeResult<Amount> {
        let index = recovery
            .settlement
            .participant_lock_hashes
            .iter()
            .position(|lock| *lock == participant.settlement_lock_hash)
            .ok_or(BridgeError::InvalidMaterialisation)?;
        Ok(allocation[index])
    };
    if evidence.participants[0].settlement_lock_hash
        == evidence.participants[1].settlement_lock_hash
    {
        return Err(BridgeError::InvalidMaterialisation);
    }
    let directional_liquidity = [
        participant_liquidity(&evidence.participants[0])?,
        participant_liquidity(&evidence.participants[1])?,
    ];
    validate_factory_origin(
        evidence,
        reservation,
        deployment,
        directional_liquidity,
        enforce_reservation_quantity,
    )?;
    match (&evidence.asset, evidence.rgbpp_proof_commitment) {
        (AgentAsset::Rgbpp(_), Some(commitment)) if !is_zero(&commitment) => {}
        (AgentAsset::Rgbpp(_), _) | (_, Some(_)) => return Err(BridgeError::RgbppProofMismatch),
        _ => {}
    }
    let mut edge = ProviderEdgeDescriptor {
        edge_id: [0; 32],
        channel_id: recovery.state.header.channel_id,
        funding_context_id: recovery.state.funding_context_id()?,
        funding_epoch: recovery.state.header.funding_epoch,
        state_number: recovery.state.header.state_number,
        participants: evidence
            .participants
            .each_ref()
            .map(|participant| participant.node_id),
        participant_pubkeys_sec1: [
            signer_pubkey_for_node(&recovery.authorization, &evidence.participants[0].node_id)?,
            signer_pubkey_for_node(&recovery.authorization, &evidence.participants[1].node_id)?,
        ],
        asset: evidence.asset.clone(),
        directional_liquidity,
        deployment_id: deployment.deployment_id()?,
        factory_id: reservation.map(|reservation| reservation.factory_id),
        factory_update_number: reservation.map(|reservation| reservation.factory_update_number),
        factory_reservation_id: reservation.map(|reservation| reservation.reservation_id),
        evidence_block_hash: evidence.committed_block_hash,
        evidence_block_number: evidence.committed_block_number,
        opaque_morph_commitment: recovery.state.signing_digest()?,
    };
    edge.edge_id = edge.derive_id()?;
    Ok(edge)
}

fn validate_complete_vaults(evidence: &MaterializedChannelEvidence) -> BridgeResult<()> {
    let recovery = &evidence.recovery;
    if evidence.vaults.len() != recovery.manifest.vaults.len() {
        return Err(BridgeError::InvalidMaterialisation);
    }
    for ((actual, vault), point) in evidence
        .vaults
        .iter()
        .zip(&recovery.manifest.vaults)
        .zip(&recovery.outpoints)
    {
        actual.validate()?;
        let expected_type = match vault.asset {
            VaultAsset::Ckb => None,
            VaultAsset::Xudt(hash) => Some(
                &recovery
                    .scripts
                    .type_scripts
                    .iter()
                    .find(|entry| entry.type_hash == hash)
                    .ok_or(BridgeError::InvalidMaterialisation)?
                    .script,
            ),
        };
        let expected_data = match vault.asset {
            VaultAsset::Ckb => vec![],
            VaultAsset::Xudt(_) => vault.value.amount.to_le_bytes().to_vec(),
        };
        if actual.out_point.tx_hash != point.tx_hash
            || actual.out_point.index != point.index
            || actual.out_point == evidence.state.out_point
            || actual.lock != recovery.scripts.vault_lock
            || actual.type_script.as_ref() != expected_type
            || actual.capacity != vault.value.capacity()?
            || actual.data != expected_data
        {
            return Err(BridgeError::InvalidMaterialisation);
        }
    }
    Ok(())
}

fn directional_asset_liquidity(
    recovery: &MultiAssetRecoveryPackage,
    asset: &AgentAsset,
) -> BridgeResult<[Amount; 2]> {
    if let Some(hash) = asset_type_hash(asset) {
        let payout = recovery
            .settlement
            .payouts
            .iter()
            .find(|payout| payout.asset == VaultAsset::Xudt(hash))
            .ok_or(BridgeError::InvalidDescriptor)?;
        return Ok(payout.values.map(|value| value.amount));
    }
    let mut amounts = [0u128; 2];
    for payout in &recovery.settlement.payouts {
        for (amount, value) in amounts.iter_mut().zip(payout.values) {
            *amount = amount
                .checked_add(u128::from(value.business_ckb))
                .ok_or(BridgeError::InvalidDescriptor)?;
        }
    }
    Ok(amounts)
}

fn validate_factory_origin(
    evidence: &MaterializedChannelEvidence,
    reservation: Option<&FactoryRightReservation>,
    deployment: &TrustedMorphDeployment,
    liquidity: [Amount; 2],
    enforce_quantity: bool,
) -> BridgeResult<()> {
    let args = morph_script_common::multi_asset::MultiAssetStateTypeArgs::parse(
        &evidence.recovery.scripts.state_type[53..],
    )
    .map_err(|_| BridgeError::FactoryOriginMismatch)?;
    match (reservation, &evidence.factory_origin, args.factory_origin()) {
        (None, None, None) => Ok(()),
        (Some(reservation), Some(origin), Some(committed_origin)) => {
            deployment.factory_type.matches(&origin.source.state_type)?;
            deployment
                .factory_vault_lock
                .matches(&origin.source.vault_lock)?;
            deployment.state_lock.matches(&origin.source.state_lock)?;
            origin
                .source
                .validate()
                .map_err(|_| BridgeError::FactoryOriginMismatch)?;
            let source = origin
                .source
                .state()
                .map_err(|_| BridgeError::FactoryOriginMismatch)?;
            let membership = crate::factory_membership_commitment(&origin.members)
                .map_err(|_| BridgeError::FactoryOriginMismatch)?;
            let factory_hash = blake2b256(&origin.source.state_type);
            if source.factory_id() != reservation.factory_id
                || source.chain_id() != evidence.recovery.state.header.chain_id
                || source.participants_commitment() != membership
                || source.state_root() != reservation.factory_state_root
                || source.update_number() != reservation.factory_update_number
                || committed_origin != factory_hash
                || reservation.right.subchannel != evidence.recovery.state.header.channel_id
                || reservation.right.asset_type != asset_type_hash(&evidence.asset)
            {
                return Err(BridgeError::FactoryOriginMismatch);
            }
            let owner = origin
                .members
                .iter()
                .find(|member| member.participant == reservation.right.participant)
                .ok_or(BridgeError::FactoryOriginMismatch)?;
            let node_id = blake2b256(&owner.pubkey_sec1);
            let member = evidence
                .participants
                .iter()
                .position(|member| member.node_id == node_id)
                .ok_or(BridgeError::FactoryOriginMismatch)?;
            if enforce_quantity && reservation.quantity > liquidity[member] {
                return Err(BridgeError::FactoryOriginMismatch);
            }
            Ok(())
        }
        _ => Err(BridgeError::FactoryOriginMismatch),
    }
}

fn signer_pubkey_for_node(
    authorization: &StateAuthorization,
    node_id: &Bytes32,
) -> BridgeResult<Vec<u8>> {
    authorization
        .signatures
        .iter()
        .find(|signature| blake2b256(&signature.pubkey_sec1) == *node_id)
        .map(|signature| signature.pubkey_sec1.clone())
        .ok_or(BridgeError::InvalidMaterialisation)
}
fn asset_ckb_genesis_hash(asset: &AgentAsset) -> &Bytes32 {
    match asset {
        AgentAsset::Ckb { ckb_genesis_hash }
        | AgentAsset::Xudt {
            ckb_genesis_hash, ..
        } => ckb_genesis_hash,
        AgentAsset::Rgbpp(asset) => &asset.ckb_genesis_hash,
    }
}
fn asset_type_hash(asset: &AgentAsset) -> Option<Bytes32> {
    match asset {
        AgentAsset::Ckb { .. } => None,
        AgentAsset::Xudt {
            type_script_hash, ..
        } => Some(*type_script_hash),
        AgentAsset::Rgbpp(asset) => Some(asset.xudt_type_script_hash),
    }
}

fn encode_right_id(right: &FactoryRightId, out: &mut Vec<u8>) {
    out.extend_from_slice(&right.participant);
    out.extend_from_slice(&right.subchannel);
    out.push(match right.kind {
        FactoryRightKind::Balance => 0,
        FactoryRightKind::ReserveClaim => 1,
        FactoryRightKind::Membership => 2,
        FactoryRightKind::ExitPath => 3,
        FactoryRightKind::SponsorBudgetClaim => 4,
    });
    encode_option_bytes32(right.asset_type, out);
}

fn encode_option_bytes32(value: Option<Bytes32>, out: &mut Vec<u8>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value);
        }
        None => out.push(0),
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BridgeError {
    #[error("trusted Morph deployment profile is invalid")]
    InvalidDeployment,
    #[error("Factory reservation is invalid")]
    InvalidReservation,
    #[error("Factory reservation id does not match its canonical fields")]
    ReservationIdMismatch,
    #[error("Factory reservation has expired")]
    ReservationExpired,
    #[error("Factory reservation is not yet valid")]
    ReservationNotYetValid,
    #[error("Factory right kind cannot fund a routable channel")]
    UnsupportedFactoryRight,
    #[error("Factory right proof does not match the reserved root, right, or quantity")]
    InvalidFactoryProof,
    #[error("reservation idempotency key conflicts with another reservation")]
    IdempotencyConflict,
    #[error("Factory reservation already exists with conflicting state")]
    ReservationConflict,
    #[error("Factory reservation was not found")]
    ReservationNotFound,
    #[error("edge lifecycle does not permit this operation")]
    InvalidLifecycle,
    #[error("another active funding context already owns this channel edge")]
    ActiveEdgeConflict,
    #[error("the physical asset balance is registered under a different asset identity")]
    AssetAliasConflict,
    #[error("provider edge refresh is stale or changes stable edge identity")]
    StaleEdgeEvidence,
    #[error("provider edge was not found")]
    EdgeNotFound,
    #[error("edge disable/invalidation reason is invalid")]
    InvalidReason,
    #[error("materialised State/Vault evidence is invalid")]
    InvalidMaterialisation,
    #[error("materialised channel uses an untrusted Morph deployment")]
    UntrustedDeployment,
    #[error("materialised channel or asset belongs to another CKB network")]
    WrongNetwork,
    #[error("Factory origin does not match the materialised child")]
    FactoryOriginMismatch,
    #[error("materialised channel has too few CKB confirmations")]
    InsufficientConfirmations,
    #[error("settlement descriptor is invalid for the advertised asset")]
    InvalidDescriptor,
    #[error("RGB++ proof commitment is missing or unexpected")]
    RgbppProofMismatch,
    #[error(transparent)]
    Agent(#[from] crate::agent::AgentError),
    #[error(transparent)]
    Evidence(#[from] MultiAssetError),
}

pub type BridgeResult<T> = Result<T, BridgeError>;

fn is_zero(value: &Bytes32) -> bool {
    value.iter().all(|byte| *byte == 0)
}
