//! Independent current Factory authority and exact-body host validation.
//!
//! There is one 306-byte Factory State codec, supplied by script-common. This
//! module checks canonical packed CKB objects and known custody. Canonical
//! chain liveness, code dependencies, external funding ownership and VM execution
//! remain prerequisites imposed by the durable native operator before signing.
use std::collections::BTreeSet;

use ckb_types::{packed, prelude::*};
use morph_script_common::{ScriptError, factory_multi_asset as wire, multi_asset as asset};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Bytes32, FactoryParticipantKey, FactoryParticipantSignature, FactoryRight, FactoryRightKind,
    MultiAssetError, MultiAssetManifest, MultiAssetOutPoint, MultiAssetTypeScript, VaultAsset,
    blake2b256, encode_factory_all_participant_signatures, encode_multi_asset_outpoints,
    factory_right_sparse_root, multi_asset_outpoint_commitment,
};

pub const FACTORY_MAX_TRANSACTION_BYTES: usize = 512 * 1024;
/// Current host operating bound, not the sparse-tree's consensus capacity.
pub const FACTORY_MAX_RIGHTS_SNAPSHOT: usize = 512;

pub fn factory_membership_commitment(
    members: &[FactoryParticipantKey],
) -> FactoryBackendResult<Bytes32> {
    for member in members {
        let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&member.pubkey_sec1)
            .map_err(|_| FactoryBackendError::InvalidMembers)?;
        if key.to_sec1_point(true).as_bytes() != member.pubkey_sec1 {
            return Err(FactoryBackendError::InvalidMembers);
        }
    }
    let placeholders = members
        .iter()
        .map(|member| FactoryParticipantSignature {
            participant: member.participant,
            pubkey_sec1: member.pubkey_sec1.clone(),
            signature: vec![0; 64],
        })
        .collect::<Vec<_>>();
    let encoded = encode_factory_all_participant_signatures(&placeholders)?;
    Ok(morph_script_common::FactorySignatureWitness::parse(&encoded)?.participants_commitment())
}

/// Unified admission invariant for a complete rights snapshot. All three value
/// kinds share one per-asset claim budget: ReducedRights can reclassify them,
/// so checking ReserveClaim alone would allow later over-issuance. This does
/// not prove each member has enough CKB to execute every independent exit.
pub fn validate_factory_initial_rights(
    members: &[FactoryParticipantKey],
    manifest: &MultiAssetManifest,
    rights: &[FactoryRight],
) -> FactoryBackendResult<()> {
    factory_membership_commitment(members)?;
    manifest.encode()?;
    if rights.len() > FACTORY_MAX_RIGHTS_SNAPSHOT
        || rights.windows(2).any(|pair| pair[0].id >= pair[1].id)
    {
        return Err(FactoryBackendError::InvalidRights);
    }
    let mut backing = std::collections::BTreeMap::new();
    let mut ckb = 0u128;
    for vault in &manifest.vaults {
        ckb = ckb
            .checked_add(u128::from(vault.value.capacity()?))
            .ok_or(FactoryBackendError::InvalidRights)?;
        if let VaultAsset::Xudt(hash) = vault.asset {
            backing.insert(Some(hash), vault.value.amount);
        }
    }
    backing.insert(None, ckb);
    let mut claims = std::collections::BTreeMap::new();
    for right in rights {
        if !members
            .iter()
            .any(|member| member.participant == right.id.participant)
            || right.id.asset_type == Some([0; 32])
        {
            return Err(FactoryBackendError::InvalidRights);
        }
        if matches!(
            right.id.kind,
            FactoryRightKind::Balance
                | FactoryRightKind::ReserveClaim
                | FactoryRightKind::SponsorBudgetClaim
        ) {
            let sum = claims.entry(right.id.asset_type).or_insert(0u128);
            *sum = sum
                .checked_add(right.quantity)
                .ok_or(FactoryBackendError::InvalidRights)?;
            if *sum > backing.get(&right.id.asset_type).copied().unwrap_or(0) {
                return Err(FactoryBackendError::InvalidRights);
            }
        }
    }
    factory_right_sparse_root(rights).map_err(|_| FactoryBackendError::InvalidRights)?;
    Ok(())
}

/// Complete bound Factory custody. Before confirmation this may describe a
/// predicted result; only the native canonical-chain gate can admit it as live.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryCustody {
    pub header: Vec<u8>,
    pub state_out_point: MultiAssetOutPoint,
    pub manifest: MultiAssetManifest,
    pub vault_outpoints: Vec<MultiAssetOutPoint>,
    pub state_type: Vec<u8>,
    pub state_lock: Vec<u8>,
    pub vault_lock: Vec<u8>,
    pub type_scripts: Vec<MultiAssetTypeScript>,
    pub state_carrier_capacity: u64,
}

impl FactoryCustody {
    pub fn state(&self) -> FactoryBackendResult<wire::FactoryMultiAssetStateHeader<'_>> {
        Ok(wire::FactoryMultiAssetStateHeader::parse(&self.header)?)
    }
    pub fn validate(&self) -> FactoryBackendResult<()> {
        let header = self.state()?;
        let manifest = self.manifest.encode()?;
        if !header.vaults_are_bound()
            || self.state_out_point.tx_hash == [0; 32]
            || header.content_root() != self.manifest.commitment()?
            || header.vault_count() != self.manifest.vaults.len()
            || self.vault_outpoints.len() != self.manifest.vaults.len()
            || header.outpoint_root()
                != multi_asset_outpoint_commitment(&self.manifest, &self.vault_outpoints)?
            || self.vault_outpoints.contains(&self.state_out_point)
        {
            return Err(FactoryBackendError::InvalidCustody);
        }
        let state_type = canonical_script(&self.state_type)?;
        asset::require_immutable_authority_script(&self.state_type)?;
        let state_lock = canonical_script(&self.state_lock)?;
        let vault_lock = canonical_script(&self.vault_lock)?;
        let type_args = state_type.args().raw_data();
        let factory_id = wire::parse_factory_multi_asset_type_args(&type_args)?;
        let type_hash = state_type.calc_script_hash();
        let reserve_args = vault_lock.args().raw_data();
        if factory_id != header.factory_id()
            || state_lock.args().raw_data().as_ref() != type_hash.as_slice()
            || reserve_args.len() != 64
            || &reserve_args[..32] != header.factory_id()
            || &reserve_args[32..] != type_hash.as_slice()
        {
            return Err(FactoryBackendError::InvalidCustody);
        }
        if asset::multi_asset_occupied_capacity(
            &self.state_lock,
            Some(&self.state_type),
            self.header.len() as u64,
        )? > self.state_carrier_capacity
        {
            return Err(FactoryBackendError::InvalidCustody);
        }
        let registry = self.manifest.registry()?;
        if self.type_scripts.len() != registry.xudt_types.len()
            || !self
                .type_scripts
                .iter()
                .map(|entry| &entry.type_hash)
                .eq(registry.xudt_types.iter())
        {
            return Err(FactoryBackendError::InvalidCustody);
        }
        for ty in &self.type_scripts {
            canonical_script(&ty.script)?;
            if blake2b256(&ty.script) != ty.type_hash {
                return Err(FactoryBackendError::InvalidCustody);
            }
        }
        let parsed_manifest = asset::MultiAssetVaultManifest::parse(&manifest)?;
        for index in 0..parsed_manifest.count() {
            let vault = parsed_manifest.entry(index)?;
            if vault.lock_hash != blake2b256(&self.vault_lock) {
                return Err(FactoryBackendError::InvalidCustody);
            }
            let ty = self.type_script(vault.asset)?;
            if asset::multi_asset_occupied_capacity(
                &self.vault_lock,
                ty,
                if ty.is_some() { 16 } else { 0 },
            )? > vault.allocation.reserve
            {
                return Err(FactoryBackendError::InvalidCustody);
            }
        }
        Ok(())
    }
    pub fn type_script(&self, asset: asset::MultiAssetId) -> FactoryBackendResult<Option<&[u8]>> {
        if asset.kind == 0 {
            return Ok(None);
        }
        self.type_scripts
            .iter()
            .find(|entry| entry.type_hash == asset.type_hash)
            .map(|entry| Some(entry.script.as_slice()))
            .ok_or(FactoryBackendError::InvalidCustody)
    }
    pub fn identity_matches(&self, next: &Self) -> FactoryBackendResult<bool> {
        Ok(self.state()?.same_identity(&next.state()?)
            && self.state_type == next.state_type
            && self.state_lock == next.state_lock
            && self.vault_lock == next.vault_lock)
    }
}

fn canonical_script(raw: &[u8]) -> FactoryBackendResult<packed::Script> {
    asset::multi_asset_script_occupied_bytes(raw)?;
    packed::Script::from_slice(raw).map_err(|_| FactoryBackendError::InvalidTransaction)
}

fn validate_raw(raw: &packed::RawTransaction) -> FactoryBackendResult<()> {
    if raw.as_slice().len() > FACTORY_MAX_TRANSACTION_BYTES
        || u32::from(raw.version()) != 0
        || !(1..=64).contains(&raw.inputs().len())
        || !(1..=64).contains(&raw.outputs().len())
        || raw.outputs().len() != raw.outputs_data().len()
        || raw.cell_deps().len() > 64
        || raw.header_deps().len() > 64
    {
        return Err(FactoryBackendError::InvalidTransaction);
    }
    let mut inputs = BTreeSet::new();
    for input in raw.inputs() {
        if !inputs.insert(input.previous_output().as_slice().to_vec()) {
            return Err(FactoryBackendError::InvalidTransaction);
        }
    }
    for (output, data) in raw.outputs().into_iter().zip(raw.outputs_data()) {
        let lock = output.lock();
        let ty = output.type_().to_opt();
        let needed = asset::multi_asset_occupied_capacity(
            lock.as_slice(),
            ty.as_ref().map(Entity::as_slice),
            data.raw_data().len() as u64,
        )?;
        if u64::from(output.capacity()) < needed {
            return Err(FactoryBackendError::InvalidTransaction);
        }
    }
    Ok(())
}

fn outpoint_bytes(point: &MultiAssetOutPoint) -> Vec<u8> {
    let mut raw = point.tx_hash.to_vec();
    raw.extend_from_slice(&point.index.to_le_bytes());
    raw
}
fn check_input(
    raw: &packed::RawTransaction,
    index: usize,
    point: &[u8],
) -> FactoryBackendResult<()> {
    let input = raw
        .inputs()
        .get(index)
        .ok_or(FactoryBackendError::InvalidTransaction)?;
    if u64::from(input.since()) != 0 || input.previous_output().as_slice() != point {
        return Err(FactoryBackendError::InvalidTransaction);
    }
    Ok(())
}
fn check_output(
    raw: &packed::RawTransaction,
    index: usize,
    lock: &[u8],
    ty: Option<&[u8]>,
    capacity: u64,
    data: &[u8],
) -> FactoryBackendResult<()> {
    let output = raw
        .outputs()
        .get(index)
        .ok_or(FactoryBackendError::InvalidTransaction)?;
    let actual_type = output.type_().to_opt();
    if output.lock().as_slice() != lock
        || actual_type.as_ref().map(Entity::as_slice) != ty
        || u64::from(output.capacity()) != capacity
        || raw
            .outputs_data()
            .get(index)
            .ok_or(FactoryBackendError::InvalidTransaction)?
            .raw_data()
            .as_ref()
            != data
    {
        return Err(FactoryBackendError::InvalidTransaction);
    }
    Ok(())
}
fn check_vault_output(
    raw: &packed::RawTransaction,
    index: usize,
    vault: asset::MultiAssetVaultEntry,
    lock: &[u8],
    ty: Option<&[u8]>,
) -> FactoryBackendResult<()> {
    let data = if vault.asset.kind == 0 {
        vec![]
    } else {
        vault.allocation.amount.to_le_bytes().to_vec()
    };
    check_output(raw, index, lock, ty, vault.allocation.capacity()?, &data)
}

/// The one signed current transition view used by policy, native submission and
/// signer journals. A standalone verified frame does not authenticate input-cell
/// contents; `validate_against` binds it to separately chain-checked custody.
pub struct FactoryTransactionView {
    transaction: packed::Transaction,
    frame: Vec<u8>,
}
impl FactoryTransactionView {
    pub fn parse(bytes: &[u8]) -> FactoryBackendResult<Self> {
        if bytes.len() > FACTORY_MAX_TRANSACTION_BYTES {
            return Err(FactoryBackendError::InvalidTransaction);
        }
        let transaction = packed::Transaction::from_slice(bytes)
            .map_err(|_| FactoryBackendError::InvalidTransaction)?;
        validate_raw(&transaction.raw())?;
        if transaction.witnesses().len() > transaction.raw().inputs().len() {
            return Err(FactoryBackendError::InvalidTransaction);
        }
        let first = transaction
            .witnesses()
            .get(0)
            .ok_or(FactoryBackendError::InvalidTransaction)?
            .raw_data();
        let witness = packed::WitnessArgs::from_slice(&first)
            .map_err(|_| FactoryBackendError::InvalidTransaction)?;
        if witness.input_type().to_opt().is_some() {
            return Err(FactoryBackendError::InvalidTransaction);
        }
        let frame = witness
            .output_type()
            .to_opt()
            .ok_or(FactoryBackendError::InvalidTransaction)?
            .raw_data()
            .to_vec();
        let current = wire::FactoryReducedReleaseWitness::parse(&frame)?;
        current.verify()?;
        check_transition_body(&transaction.raw(), &current)?;
        Ok(Self { transaction, frame })
    }
    pub fn transaction(&self) -> &packed::Transaction {
        &self.transaction
    }
    pub fn witness(&self) -> FactoryBackendResult<wire::FactoryReducedReleaseWitness<'_>> {
        Ok(wire::FactoryReducedReleaseWitness::parse(&self.frame)?)
    }
    pub fn validate_against(&self, source: &FactoryCustody) -> FactoryBackendResult<()> {
        source.validate()?;
        let frame = self.witness()?;
        if frame.before().as_bytes() != source.header
            || frame.source().as_bytes() != source.manifest.encode()?
            || frame.source_points() != encode_multi_asset_outpoints(&source.vault_outpoints)?
            || frame.old_state_outpoint() != outpoint_bytes(&source.state_out_point)
            || frame.factory_lock_script() != source.vault_lock
            || frame.carrier_capacity() != source.state_carrier_capacity
        {
            return Err(FactoryBackendError::InvalidCustody);
        }
        let output = self
            .transaction
            .raw()
            .outputs()
            .get(0)
            .ok_or(FactoryBackendError::InvalidTransaction)?;
        if output.lock().as_slice() != source.state_lock
            || output.type_().to_opt().as_ref().map(Entity::as_slice)
                != Some(source.state_type.as_slice())
        {
            return Err(FactoryBackendError::InvalidCustody);
        }
        for vault in &source.manifest.vaults {
            let id = crate::multi_asset::wire_asset(&vault.asset);
            if frame.type_script(id)? != source.type_script(id)? {
                return Err(FactoryBackendError::InvalidCustody);
            }
        }
        Ok(())
    }

    /// Derive the exact retained custody from the sole checked physical frame.
    /// A moving transition predicts its bound header; the native caller must
    /// still confirm permissionless activation before adopting a live State.
    pub fn retained_custody(
        &self,
        source: &FactoryCustody,
    ) -> FactoryBackendResult<FactoryCustody> {
        self.validate_against(source)?;
        let frame = self.witness()?;
        let manifest = crate::MultiAssetManifest::decode(frame.retained().as_bytes())?;
        let hash: Bytes32 = self.transaction.calc_tx_hash().unpack();
        let vault_outpoints = if frame.operation().moves_custody() {
            (0..manifest.vaults.len())
                .map(|index| MultiAssetOutPoint {
                    tx_hash: hash,
                    index: index as u32 + 1,
                })
                .collect()
        } else {
            source.vault_outpoints.clone()
        };
        let mut header = frame.after().fields();
        header.outpoint_root = crate::multi_asset_outpoint_commitment(&manifest, &vault_outpoints)?;
        let type_scripts = manifest
            .vaults
            .iter()
            .filter_map(|vault| match vault.asset {
                crate::VaultAsset::Ckb => None,
                crate::VaultAsset::Xudt(type_hash) => Some((|| {
                    let script = frame
                        .type_script(asset::MultiAssetId::xudt(type_hash))?
                        .ok_or(FactoryBackendError::InvalidCustody)?
                        .to_vec();
                    Ok(crate::MultiAssetTypeScript { type_hash, script })
                })()),
            })
            .collect::<FactoryBackendResult<Vec<_>>>()?;
        let target = FactoryCustody {
            header: header.encode()?.to_vec(),
            state_out_point: MultiAssetOutPoint {
                tx_hash: hash,
                index: 0,
            },
            manifest,
            vault_outpoints,
            state_type: source.state_type.clone(),
            state_lock: source.state_lock.clone(),
            vault_lock: source.vault_lock.clone(),
            type_scripts,
            state_carrier_capacity: source.state_carrier_capacity,
        };
        target.validate()?;
        Ok(target)
    }
}

fn check_transition_body(
    raw: &packed::RawTransaction,
    frame: &wire::FactoryReducedReleaseWitness<'_>,
) -> FactoryBackendResult<()> {
    validate_raw(raw)?;
    if frame.transaction_hash() != raw.calc_tx_hash().as_slice() {
        return Err(FactoryBackendError::InvalidTransaction);
    }
    check_input(raw, 0, frame.old_state_outpoint())?;
    let mut claimed = BTreeSet::new();
    claimed.insert(0usize);
    if frame.operation().moves_custody() {
        for index in 0..frame.source().count() {
            check_input(
                raw,
                index + 1,
                &frame.source_points()[index * 36..(index + 1) * 36],
            )?;
        }
        for index in 0..frame.retained().count() {
            let vault = frame.retained().entry(index)?;
            check_vault_output(
                raw,
                index + 1,
                vault,
                frame.factory_lock_script(),
                frame.type_script(vault.asset)?,
            )?;
            claimed.insert(index + 1);
        }
    } else {
        for point in frame.source_points().chunks_exact(36) {
            if raw
                .inputs()
                .into_iter()
                .any(|input| input.previous_output().as_slice() == point)
            {
                return Err(FactoryBackendError::InvalidTransaction);
            }
        }
    }
    let output = raw
        .outputs()
        .get(0)
        .ok_or(FactoryBackendError::InvalidTransaction)?;
    let state_type = output
        .type_()
        .to_opt()
        .ok_or(FactoryBackendError::InvalidTransaction)?;
    if wire::parse_factory_multi_asset_type_args(&state_type.args().raw_data())?
        != frame.after().factory_id()
        || output.lock().args().raw_data().as_ref() != state_type.calc_script_hash().as_slice()
        || &frame.factory_lock_script()[85..117] != state_type.calc_script_hash().as_slice()
    {
        return Err(FactoryBackendError::InvalidTransaction);
    }
    check_output(
        raw,
        0,
        output.lock().as_slice(),
        Some(state_type.as_slice()),
        frame.carrier_capacity(),
        frame.after().as_bytes(),
    )?;
    for index in 0..frame.payout_count() {
        let payout = frame.payout(index)?;
        check_output(
            raw,
            payout.output_index,
            payout.lock_script,
            frame.type_script(payout.asset)?,
            payout.allocation.capacity()?,
            &if payout.asset.kind == 0 {
                vec![]
            } else {
                payout.allocation.amount.to_le_bytes().to_vec()
            },
        )?;
        if !claimed.insert(payout.output_index) {
            return Err(FactoryBackendError::InvalidTransaction);
        }
    }
    if let Some(intent) = frame.child_intent() {
        check_children(raw, intent, &mut claimed)?;
    }
    for index in 0..raw.outputs().len() {
        let output = raw
            .outputs()
            .get(index)
            .ok_or(FactoryBackendError::InvalidTransaction)?;
        if !claimed.contains(&index)
            && (output.lock().as_slice() == frame.factory_lock_script()
                || output.type_().to_opt().is_some_and(|ty| ty == state_type)
                || frame
                    .child_intent()
                    .map(|intent| {
                        intent.is_custody_lock(&output.lock().calc_script_hash().unpack())
                    })
                    .transpose()?
                    .unwrap_or(false))
        {
            return Err(FactoryBackendError::InvalidTransaction);
        }
    }
    Ok(())
}
fn check_children(
    raw: &packed::RawTransaction,
    intent: &wire::FactoryMaterialisationIntent<'_>,
    claimed: &mut BTreeSet<usize>,
) -> FactoryBackendResult<()> {
    for index in 0..intent.child_count() {
        let child = intent.child(index)?;
        let position = child.state_output_index;
        if !claimed.insert(position) {
            return Err(FactoryBackendError::InvalidTransaction);
        }
        check_output(
            raw,
            position,
            child.evidence.scripts().script(5)?,
            Some(child.evidence.scripts().script(4)?),
            child.carrier_capacity,
            &child.creation_header()?,
        )?;
        for vault_index in 0..child.evidence.manifest().count() {
            let vault = child.evidence.manifest().entry(vault_index)?;
            let point = child.evidence.outpoint(vault_index)?;
            let position = position + 1 + vault_index;
            if !claimed.insert(position)
                || point[..32] != raw.calc_tx_hash().as_slice()[..]
                || morph_script_common::read_u32(point, 32) as usize != position
            {
                return Err(FactoryBackendError::InvalidTransaction);
            }
            let ty = if vault.asset.kind == 0 {
                None
            } else {
                let mut result = None;
                for script_index in 6..6 + child.evidence.manifest().count() {
                    if let Ok(script) = child.evidence.scripts().script(script_index)
                        && blake2b256(script) == vault.asset.type_hash
                    {
                        result = Some(script);
                        break;
                    }
                }
                Some(result.ok_or(FactoryBackendError::InvalidTransaction)?)
            };
            check_vault_output(
                raw,
                position,
                vault,
                child.evidence.scripts().script(3)?,
                ty,
            )?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactorySigningRole {
    RootFunding,
    MetadataUpdate,
    Materialisation,
    Transition,
}
impl FactorySigningRole {
    fn tag(self) -> u8 {
        match self {
            Self::RootFunding => 0,
            Self::MetadataUpdate => 1,
            Self::Materialisation => 2,
            Self::Transition => 3,
        }
    }
}

/// Public parent-authorisation request. Private child exit signatures never
/// belong here: child parties validate and retain their own recovery packets
/// before issuing the two delivery attestations required by this ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactorySigningRequest {
    pub role: FactorySigningRole,
    #[serde(deserialize_with = "required_factory_option")]
    pub source: Option<FactoryCustody>,
    #[serde(deserialize_with = "required_factory_option")]
    pub target: Option<FactoryCustody>,
    /// Exact packed RawTransaction, before any wallet/Factory witnesses.
    pub transaction: Vec<u8>,
    /// Current MORPHFS/MORPHFM/transition frame with zero Factory signatures.
    pub witness: Vec<u8>,
    pub target_rights: Vec<FactoryRight>,
    pub deliveries: Vec<FactoryChildDeliveryReceipt>,
}
fn required_factory_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryChildDeliveryReceipt {
    pub child_index: u16,
    pub pubkey_sec1: Vec<u8>,
    pub signature: Vec<u8>,
}

enum PublicChildren<'a> {
    Materialisation(Box<wire::FactoryMaterialisationWitness<'a>>),
    Transition(Box<wire::FactoryReducedReleaseWitness<'a>>),
}
impl<'a> PublicChildren<'a> {
    fn intent(&self) -> FactoryBackendResult<&wire::FactoryMaterialisationIntent<'a>> {
        match self {
            Self::Materialisation(frame) => Ok(frame.intent()),
            Self::Transition(frame) => frame
                .child_intent()
                .ok_or(FactoryBackendError::InvalidDelivery),
        }
    }
    fn pubkey(&self, child: usize, participant: usize) -> FactoryBackendResult<&[u8]> {
        Ok(match self {
            Self::Materialisation(frame) => frame.child_pubkey(child, participant)?,
            Self::Transition(frame) => frame.child_pubkey(child, participant)?,
        })
    }
}

impl FactoryChildDeliveryReceipt {
    /// The child signer has to receive and verify the COMPLETE valid private
    /// recovery before this function invokes their key. There is deliberately
    /// no constructor that accepts a naked hash or initial-exit digest.
    pub fn new_signed(
        request: &FactorySigningRequest,
        child_index: u16,
        recovery: &crate::MultiAssetRecoveryPackage,
        key: &k256::ecdsa::SigningKey,
    ) -> FactoryBackendResult<Self> {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        request.verify_child_recovery(child_index, recovery)?;
        let pubkey_sec1 = key.verifying_key().to_sec1_point(true).as_bytes().to_vec();
        let digest = delivery_digest(request, child_index, &pubkey_sec1)?;
        let signature: k256::ecdsa::Signature = key
            .sign_prehash(&digest)
            .map_err(|_| FactoryBackendError::InvalidSignature)?;
        Ok(Self {
            child_index,
            pubkey_sec1,
            signature: signature.to_bytes().to_vec(),
        })
    }
    pub fn verify(&self, request: &FactorySigningRequest) -> FactoryBackendResult<()> {
        verify_factory_signature(
            &self.pubkey_sec1,
            &self.signature,
            &delivery_digest(request, self.child_index, &self.pubkey_sec1)?,
        )
    }
}
fn delivery_digest(
    request: &FactorySigningRequest,
    child_index: u16,
    pubkey: &[u8],
) -> FactoryBackendResult<Bytes32> {
    let view = request
        .children()?
        .ok_or(FactoryBackendError::InvalidDelivery)?;
    let child = view.intent()?.child(usize::from(child_index))?;
    if (0..2).all(|index| view.pubkey(usize::from(child_index), index).ok() != Some(pubkey)) {
        return Err(FactoryBackendError::InvalidDelivery);
    }
    let mut raw = crate::hash::FACTORY_CHILD_DELIVERY_DOMAIN.to_vec();
    raw.extend_from_slice(&request.transaction_hash()?);
    raw.extend_from_slice(&view.intent()?.signing_digest());
    raw.extend_from_slice(&child_index.to_le_bytes());
    raw.extend_from_slice(&child.header.signing_digest());
    raw.extend_from_slice(pubkey);
    Ok(blake2b256(&raw))
}
fn verify_factory_signature(
    pubkey: &[u8],
    signature: &[u8],
    digest: &Bytes32,
) -> FactoryBackendResult<()> {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(pubkey)
        .map_err(|_| FactoryBackendError::InvalidSignature)?;
    if key.to_sec1_point(true).as_bytes() != pubkey {
        return Err(FactoryBackendError::InvalidSignature);
    }
    let signature = k256::ecdsa::Signature::from_slice(signature)
        .map_err(|_| FactoryBackendError::InvalidSignature)?;
    key.verify_prehash(digest, &signature)
        .map_err(|_| FactoryBackendError::InvalidSignature)
}

impl FactorySigningRequest {
    pub fn transaction_hash(&self) -> FactoryBackendResult<Bytes32> {
        let raw = self.raw_transaction()?;
        Ok(raw.calc_tx_hash().unpack())
    }
    pub fn raw_transaction(&self) -> FactoryBackendResult<packed::RawTransaction> {
        if self.transaction.len() > FACTORY_MAX_TRANSACTION_BYTES {
            return Err(FactoryBackendError::InvalidTransaction);
        }
        let raw = packed::RawTransaction::from_slice(&self.transaction)
            .map_err(|_| FactoryBackendError::InvalidTransaction)?;
        validate_raw(&raw)?;
        Ok(raw)
    }
    pub fn request_id(&self) -> FactoryBackendResult<Bytes32> {
        let mut bytes = crate::hash::FACTORY_SIGNING_REQUEST_DOMAIN.to_vec();
        bytes.push(self.role.tag());
        bytes.extend_from_slice(&self.transaction_hash()?);
        bytes.extend_from_slice(&blake2b256(&self.witness));
        // Complete sorted rights are committed by the target State root;
        // delivery signatures attest the same public terms and may be retried.
        Ok(blake2b256(&bytes))
    }
    pub fn signing_digest(&self) -> FactoryBackendResult<Bytes32> {
        let raw = self.raw_transaction()?;
        let hash = raw.calc_tx_hash().unpack();
        match self.role {
            FactorySigningRole::RootFunding => {
                let data = raw
                    .outputs_data()
                    .get(0)
                    .ok_or(FactoryBackendError::InvalidTransaction)?
                    .raw_data();
                Ok(wire::FactoryMultiAssetStateHeader::parse(&data)?
                    .root_funding_signing_digest(&hash)?)
            }
            FactorySigningRole::MetadataUpdate => Ok(self
                .target
                .as_ref()
                .ok_or(FactoryBackendError::InvalidCustody)?
                .state()?
                .update_signing_digest(&hash)?),
            FactorySigningRole::Materialisation => {
                Ok(wire::FactoryMaterialisationWitness::parse(&self.witness)?
                    .intent()
                    .signing_digest())
            }
            FactorySigningRole::Transition => {
                Ok(wire::FactoryReducedReleaseWitness::parse(&self.witness)?.signing_digest())
            }
        }
    }
    fn children(&self) -> FactoryBackendResult<Option<PublicChildren<'_>>> {
        Ok(match self.role {
            FactorySigningRole::Materialisation => Some(PublicChildren::Materialisation(Box::new(
                wire::FactoryMaterialisationWitness::parse(&self.witness)?,
            ))),
            FactorySigningRole::Transition => {
                let frame = wire::FactoryReducedReleaseWitness::parse(&self.witness)?;
                frame
                    .child_intent()
                    .map(|_| PublicChildren::Transition(Box::new(frame)))
            }
            _ => None,
        })
    }
    pub fn members(&self) -> FactoryBackendResult<Vec<FactoryParticipantKey>> {
        match self.role {
            FactorySigningRole::RootFunding | FactorySigningRole::MetadataUpdate => {
                let frame = wire::FactoryMultiAssetStateWitness::parse(&self.witness)?;
                members_from_signatures(frame.signatures()?)
            }
            FactorySigningRole::Materialisation => members_from_signatures(
                wire::FactoryMaterialisationWitness::parse(&self.witness)?.factory_signatures(),
            ),
            FactorySigningRole::Transition => {
                let frame = wire::FactoryReducedReleaseWitness::parse(&self.witness)?;
                (0..frame.member_count())
                    .map(|index| {
                        let (participant, key) = frame.member(index)?;
                        Ok(FactoryParticipantKey {
                            participant: participant
                                .try_into()
                                .map_err(|_| FactoryBackendError::InvalidMembers)?,
                            pubkey_sec1: key.to_vec(),
                        })
                    })
                    .collect()
            }
        }
    }
    pub fn required_members(&self) -> FactoryBackendResult<Vec<FactoryParticipantKey>> {
        let members = self.members()?;
        if self.role == FactorySigningRole::Transition {
            let frame = wire::FactoryReducedReleaseWitness::parse(&self.witness)?;
            if !frame.operation().is_full() {
                return members
                    .into_iter()
                    .find(|member| member.participant == frame.touched_participant())
                    .map(|member| vec![member])
                    .ok_or(FactoryBackendError::InvalidMembers);
            }
        }
        Ok(members)
    }
    pub fn validate(&self, members: &[FactoryParticipantKey]) -> FactoryBackendResult<()> {
        self.validate_for_review(members)?;
        if !self.missing_delivery_receipts()?.is_empty() {
            return Err(FactoryBackendError::InvalidDelivery);
        }
        Ok(())
    }
    /// Review shares the current schema but grants no signing authority.
    /// Every supplied receipt is verified; missing recipients stay explicit.
    pub fn validate_for_review(
        &self,
        members: &[FactoryParticipantKey],
    ) -> FactoryBackendResult<()> {
        self.validate_unsigned(members)?;
        if self.children()?.is_none() && !self.deliveries.is_empty() {
            return Err(FactoryBackendError::InvalidDelivery);
        }
        let mut delivered = BTreeSet::new();
        for receipt in &self.deliveries {
            receipt.verify(self)?;
            if !delivered.insert((receipt.child_index, receipt.pubkey_sec1.clone())) {
                return Err(FactoryBackendError::InvalidDelivery);
            }
        }
        Ok(())
    }
    pub fn missing_delivery_receipts(&self) -> FactoryBackendResult<Vec<(u16, Vec<u8>)>> {
        let Some(children) = self.children()? else {
            return Ok(vec![]);
        };
        let delivered = self
            .deliveries
            .iter()
            .map(|receipt| (receipt.child_index, receipt.pubkey_sec1.clone()))
            .collect::<BTreeSet<_>>();
        let mut missing = vec![];
        for child in 0..children.intent()?.child_count() {
            for participant in 0..2 {
                let entry = (child as u16, children.pubkey(child, participant)?.to_vec());
                if !delivered.contains(&entry) {
                    missing.push(entry);
                }
            }
        }
        Ok(missing)
    }
    pub fn child_count(&self) -> FactoryBackendResult<usize> {
        self.children()?
            .map_or(Ok(0), |children| Ok(children.intent()?.child_count()))
    }
    /// Public initial terms only, with no publishable child exit signatures.
    pub fn public_child(
        &self,
        index: usize,
    ) -> FactoryBackendResult<wire::FactoryMaterialisationChild<'_>> {
        let children = self
            .children()?
            .ok_or(FactoryBackendError::InvalidDelivery)?;
        Ok(*children.intent()?.child(index)?)
    }
    /// The sole fixed initial exit committed by this exact public parent body.
    /// This returns unsigned proposal contents, never authenticated recovery.
    pub fn expected_child_recovery(
        &self,
        child_index: u16,
    ) -> FactoryBackendResult<crate::MultiAssetRecoveryPackage> {
        self.validate_unsigned(&self.members()?)?;
        let children = self
            .children()?
            .ok_or(FactoryBackendError::InvalidDelivery)?;
        let child = children.intent()?.child(usize::from(child_index))?;
        let mut recovery = crate::MultiAssetRecoveryPackage::decode_evidence(
            child.header.as_bytes(),
            &child.evidence,
            child.carrier_capacity,
        )?;
        recovery.authorization.signatures = (0..2)
            .map(|index| {
                Ok(crate::ParticipantSignature {
                    pubkey_sec1: children.pubkey(usize::from(child_index), index)?.to_vec(),
                    signature: vec![],
                })
            })
            .collect::<FactoryBackendResult<Vec<_>>>()?;
        Ok(recovery)
    }
    /// Verify complete private recovery against public canonical child terms.
    /// Parent signing requests and Factory lineage retain no exit signatures.
    pub fn verify_child_recovery(
        &self,
        child_index: u16,
        recovery: &crate::MultiAssetRecoveryPackage,
    ) -> FactoryBackendResult<()> {
        recovery.validate()?;
        let expected = self.expected_child_recovery(child_index)?;
        if recovery.state != expected.state
            || recovery.manifest != expected.manifest
            || recovery.settlement != expected.settlement
            || recovery.outpoints != expected.outpoints
            || recovery.scripts != expected.scripts
            || recovery.state_carrier_capacity != expected.state_carrier_capacity
            || recovery
                .authorization
                .signatures
                .iter()
                .zip(&expected.authorization.signatures)
                .any(|(actual, expected)| actual.pubkey_sec1 != expected.pubkey_sec1)
        {
            return Err(FactoryBackendError::InvalidDelivery);
        }
        Ok(())
    }
    fn validate_unsigned(&self, members: &[FactoryParticipantKey]) -> FactoryBackendResult<()> {
        if self.members()? != members {
            return Err(FactoryBackendError::InvalidMembers);
        }
        let member_commitment = factory_membership_commitment(members)?;
        let raw = self.raw_transaction()?;
        let source = self.source.as_ref();
        let target = self.target.as_ref();
        if let Some(source) = source {
            source.validate()?;
            if source.state()?.participants_commitment() != member_commitment {
                return Err(FactoryBackendError::InvalidMembers);
            }
        }
        if let Some(target) = target {
            target.validate()?;
            if target.state()?.participants_commitment() != member_commitment
                || target.state_out_point.tx_hash != self.transaction_hash()?
                || target.state_out_point.index != 0
            {
                return Err(FactoryBackendError::InvalidCustody);
            }
            validate_factory_initial_rights(members, &target.manifest, &self.target_rights)?;
            if factory_right_sparse_root(&self.target_rights)
                .map_err(|_| FactoryBackendError::InvalidRights)?
                != target.state()?.state_root()
            {
                return Err(FactoryBackendError::InvalidRights);
            }
        } else if !self.target_rights.is_empty() {
            return Err(FactoryBackendError::InvalidRights);
        }
        if let (Some(before), Some(after)) = (source, target)
            && (!before.identity_matches(after)?
                || after.state()?.update_number() <= before.state()?.update_number())
        {
            return Err(FactoryBackendError::InvalidCustody);
        }
        match self.role {
            FactorySigningRole::RootFunding | FactorySigningRole::MetadataUpdate => {
                let target = target.ok_or(FactoryBackendError::InvalidCustody)?;
                let frame = wire::FactoryMultiAssetStateWitness::parse(&self.witness)?;
                require_zero_signatures(frame.signatures()?)?;
                let expected_kind = if self.role == FactorySigningRole::RootFunding {
                    wire::FACTORY_STATE_WITNESS_ROOT
                } else {
                    wire::FACTORY_STATE_WITNESS_UPDATE
                };
                if frame.kind() != expected_kind {
                    return Err(FactoryBackendError::WrongRole);
                }
                let output_data = raw
                    .outputs_data()
                    .get(0)
                    .ok_or(FactoryBackendError::InvalidTransaction)?
                    .raw_data();
                let body_header = wire::FactoryMultiAssetStateHeader::parse(&output_data)?;
                frame.validate_header(&body_header)?;
                check_output(
                    &raw,
                    0,
                    &target.state_lock,
                    Some(&target.state_type),
                    target.state_carrier_capacity,
                    &output_data,
                )?;
                if self.role == FactorySigningRole::RootFunding {
                    if source.is_some()
                        || !body_header.is_activation_to(&target.state()?)
                        || body_header.update_number() != 0
                    {
                        return Err(FactoryBackendError::InvalidCustody);
                    }
                    let input = raw
                        .inputs()
                        .get(0)
                        .ok_or(FactoryBackendError::InvalidTransaction)?;
                    let mut anchor = input.as_slice().to_vec();
                    anchor.extend_from_slice(&0u64.to_le_bytes());
                    if blake2b256(&anchor) != body_header.factory_id() {
                        return Err(FactoryBackendError::InvalidCustody);
                    }
                    check_target_vaults(&raw, target)?;
                    deny_extra_factory_outputs(
                        &raw,
                        target,
                        &(0..=target.manifest.vaults.len()).collect::<Vec<_>>(),
                    )?;
                } else {
                    let source = source.ok_or(FactoryBackendError::InvalidCustody)?;
                    if output_data.as_ref() != target.header
                        || source.manifest != target.manifest
                        || source.vault_outpoints != target.vault_outpoints
                        || source.state_carrier_capacity != target.state_carrier_capacity
                    {
                        return Err(FactoryBackendError::InvalidCustody);
                    }
                    check_input(&raw, 0, &outpoint_bytes(&source.state_out_point))?;
                    check_no_custody_inputs(&raw, source)?;
                    deny_extra_factory_outputs(&raw, target, &[0])?;
                }
            }
            FactorySigningRole::Materialisation => {
                let source = source.ok_or(FactoryBackendError::InvalidCustody)?;
                let frame = wire::FactoryMaterialisationWitness::parse(&self.witness)?;
                frame.validate_public_contents()?;
                require_zero_signatures(frame.factory_signatures())?;
                validate_materialisation_source(source, frame.intent())?;
                check_materialisation_body(&raw, source, target, frame.intent())?;
            }
            FactorySigningRole::Transition => {
                let source = source.ok_or(FactoryBackendError::InvalidCustody)?;
                let target = target.ok_or(FactoryBackendError::InvalidCustody)?;
                let frame = wire::FactoryReducedReleaseWitness::parse(&self.witness)?;
                frame.validate_transition()?;
                for index in 0..frame.signature_count() {
                    if frame.signature(index)?.iter().any(|byte| *byte != 0) {
                        return Err(FactoryBackendError::HiddenSignature);
                    }
                }
                check_transition_body(&raw, &frame)?;
                validate_transition_source(source, &frame)?;
                if frame.retained().as_bytes() != target.manifest.encode()? {
                    return Err(FactoryBackendError::InvalidCustody);
                }
                if frame.operation().moves_custody() {
                    if !frame.after().is_activation_to(&target.state()?) {
                        return Err(FactoryBackendError::InvalidCustody);
                    }
                    check_target_vaults(&raw, target)?;
                } else if frame.after().as_bytes() != target.header
                    || target.vault_outpoints != source.vault_outpoints
                {
                    return Err(FactoryBackendError::InvalidCustody);
                }
                let output = raw
                    .outputs()
                    .get(0)
                    .ok_or(FactoryBackendError::InvalidTransaction)?;
                if output.lock().as_slice() != source.state_lock
                    || output.type_().to_opt().as_ref().map(Entity::as_slice)
                        != Some(source.state_type.as_slice())
                {
                    return Err(FactoryBackendError::InvalidCustody);
                }
            }
        }
        self.signing_digest()?;
        Ok(())
    }
    pub fn verify_participant_signature(
        &self,
        signature: &FactoryParticipantSignature,
    ) -> FactoryBackendResult<()> {
        if !self.required_members()?.iter().any(|member| {
            member.participant == signature.participant
                && member.pubkey_sec1 == signature.pubkey_sec1
        }) {
            return Err(FactoryBackendError::InvalidMembers);
        }
        verify_factory_signature(
            &signature.pubkey_sec1,
            &signature.signature,
            &self.signing_digest()?,
        )
    }
    /// One exact signed-body check for wallet signing and keyless submission.
    /// Wallet lock witnesses may still be incomplete here; VM preflight and
    /// per-wallet ownership checks remain the native operator's responsibility.
    pub fn authorization_from_transaction(
        &self,
        transaction: &packed::Transaction,
    ) -> FactoryBackendResult<Vec<FactoryParticipantSignature>> {
        self.validate(&self.members()?)?;
        if transaction.raw().as_slice() != self.transaction
            || transaction.as_slice().len() > FACTORY_MAX_TRANSACTION_BYTES
            || transaction.witnesses().len() > transaction.raw().inputs().len()
        {
            return Err(FactoryBackendError::InvalidTransaction);
        }
        let first = transaction
            .witnesses()
            .get(0)
            .ok_or(FactoryBackendError::InvalidTransaction)?
            .raw_data();
        let witness = packed::WitnessArgs::from_slice(&first)
            .map_err(|_| FactoryBackendError::InvalidTransaction)?;
        let payload = match self.role {
            FactorySigningRole::RootFunding | FactorySigningRole::MetadataUpdate => {
                if witness.output_type().to_opt().is_some() {
                    return Err(FactoryBackendError::WrongRole);
                }
                witness.input_type().to_opt()
            }
            FactorySigningRole::Materialisation | FactorySigningRole::Transition => {
                if witness.input_type().to_opt().is_some() {
                    return Err(FactoryBackendError::WrongRole);
                }
                witness.output_type().to_opt()
            }
        }
        .ok_or(FactoryBackendError::InvalidTransaction)?
        .raw_data();
        let authorization = match self.role {
            FactorySigningRole::RootFunding | FactorySigningRole::MetadataUpdate => {
                let frame = wire::FactoryMultiAssetStateWitness::parse(&payload)?;
                authorizations_from_signatures(frame.signatures()?)?
            }
            FactorySigningRole::Materialisation => authorizations_from_signatures(
                wire::FactoryMaterialisationWitness::parse(&payload)?.factory_signatures(),
            )?,
            FactorySigningRole::Transition => {
                let frame = wire::FactoryReducedReleaseWitness::parse(&payload)?;
                (0..frame.signature_count())
                    .map(|index| {
                        let (member, key) = frame.authorized_member(index)?;
                        Ok(FactoryParticipantSignature {
                            participant: member
                                .try_into()
                                .map_err(|_| FactoryBackendError::InvalidMembers)?,
                            pubkey_sec1: key.to_vec(),
                            signature: frame.signature(index)?.to_vec(),
                        })
                    })
                    .collect::<FactoryBackendResult<Vec<_>>>()?
            }
        };
        if self.authorized_witness(&authorization)? != payload.as_ref() {
            return Err(FactoryBackendError::InvalidTransaction);
        }
        Ok(authorization)
    }
    pub fn verify_authorized_transaction(
        &self,
        transaction: &packed::Transaction,
    ) -> FactoryBackendResult<()> {
        self.authorization_from_transaction(transaction).map(|_| ())
    }
    pub fn authorized_witness(
        &self,
        authorization: &[FactoryParticipantSignature],
    ) -> FactoryBackendResult<Vec<u8>> {
        self.validate(&self.members()?)?;
        let required = self.required_members()?;
        if authorization.len() != required.len() {
            return Err(FactoryBackendError::IncompleteSignatures);
        }
        for (signature, member) in authorization.iter().zip(&required) {
            if signature.participant != member.participant
                || signature.pubkey_sec1 != member.pubkey_sec1
            {
                return Err(FactoryBackendError::InvalidMembers);
            }
            self.verify_participant_signature(signature)?;
        }
        Ok(match self.role {
            FactorySigningRole::RootFunding | FactorySigningRole::MetadataUpdate => {
                let frame = wire::FactoryMultiAssetStateWitness::parse(&self.witness)?;
                let manifest = MultiAssetManifest::decode(frame.manifest().as_bytes())?;
                let points = frame
                    .points()
                    .chunks_exact(36)
                    .map(|bytes| {
                        Ok(MultiAssetOutPoint {
                            tx_hash: bytes[..32]
                                .try_into()
                                .map_err(|_| FactoryBackendError::InvalidCustody)?,
                            index: morph_script_common::read_u32(bytes, 32),
                        })
                    })
                    .collect::<FactoryBackendResult<Vec<_>>>()?;
                crate::encode_factory_multi_asset_state_witness(
                    frame.kind(),
                    &manifest,
                    &points,
                    authorization,
                )?
            }
            FactorySigningRole::Materialisation => {
                let frame = wire::FactoryMaterialisationWitness::parse(&self.witness)?;
                let keys = (0..frame.intent().child_count())
                    .map(|child| {
                        Ok([
                            frame.child_pubkey(child, 0)?.to_vec(),
                            frame.child_pubkey(child, 1)?.to_vec(),
                        ])
                    })
                    .collect::<FactoryBackendResult<Vec<_>>>()?;
                let encoded = crate::encode_factory_materialisation_public_witness(
                    frame.intent().as_bytes(),
                    authorization,
                    &keys,
                )?;
                wire::FactoryMaterialisationWitness::parse(&encoded)?.verify()?;
                encoded
            }
            FactorySigningRole::Transition => {
                let signatures = authorization
                    .iter()
                    .map(|entry| {
                        entry
                            .signature
                            .as_slice()
                            .try_into()
                            .map_err(|_| FactoryBackendError::InvalidSignature)
                    })
                    .collect::<FactoryBackendResult<Vec<[u8; 64]>>>()?;
                crate::authorize_factory_transition(&self.witness, &signatures)?
            }
        })
    }
}
fn members_from_signatures(
    signatures: &morph_script_common::FactorySignatureWitness<'_>,
) -> FactoryBackendResult<Vec<FactoryParticipantKey>> {
    (0..usize::from(signatures.count()))
        .map(|index| {
            Ok(FactoryParticipantKey {
                participant: signatures
                    .participant(index)
                    .try_into()
                    .map_err(|_| FactoryBackendError::InvalidMembers)?,
                pubkey_sec1: signatures.pubkey(index).to_vec(),
            })
        })
        .collect()
}
fn authorizations_from_signatures(
    signatures: &morph_script_common::FactorySignatureWitness<'_>,
) -> FactoryBackendResult<Vec<FactoryParticipantSignature>> {
    (0..usize::from(signatures.count()))
        .map(|index| {
            Ok(FactoryParticipantSignature {
                participant: signatures
                    .participant(index)
                    .try_into()
                    .map_err(|_| FactoryBackendError::InvalidMembers)?,
                pubkey_sec1: signatures.pubkey(index).to_vec(),
                signature: signatures.signature(index).to_vec(),
            })
        })
        .collect()
}
fn require_zero_signatures(
    signatures: &morph_script_common::FactorySignatureWitness<'_>,
) -> FactoryBackendResult<()> {
    if (0..usize::from(signatures.count()))
        .any(|index| signatures.signature(index).iter().any(|byte| *byte != 0))
    {
        return Err(FactoryBackendError::HiddenSignature);
    }
    Ok(())
}
fn check_no_custody_inputs(
    raw: &packed::RawTransaction,
    source: &FactoryCustody,
) -> FactoryBackendResult<()> {
    for point in &source.vault_outpoints {
        let point = outpoint_bytes(point);
        if raw
            .inputs()
            .into_iter()
            .any(|input| input.previous_output().as_slice() == point)
        {
            return Err(FactoryBackendError::InvalidTransaction);
        }
    }
    Ok(())
}
fn check_target_vaults(
    raw: &packed::RawTransaction,
    target: &FactoryCustody,
) -> FactoryBackendResult<()> {
    let manifest_bytes = target.manifest.encode()?;
    let manifest = asset::MultiAssetVaultManifest::parse(&manifest_bytes)?;
    for index in 0..manifest.count() {
        let vault = manifest.entry(index)?;
        if target.vault_outpoints[index].tx_hash != raw.calc_tx_hash().as_slice()
            || target.vault_outpoints[index].index as usize != index + 1
        {
            return Err(FactoryBackendError::InvalidCustody);
        }
        check_vault_output(
            raw,
            index + 1,
            vault,
            &target.vault_lock,
            target.type_script(vault.asset)?,
        )?;
    }
    Ok(())
}
fn deny_extra_factory_outputs(
    raw: &packed::RawTransaction,
    custody: &FactoryCustody,
    claimed: &[usize],
) -> FactoryBackendResult<()> {
    for index in 0..raw.outputs().len() {
        let output = raw
            .outputs()
            .get(index)
            .ok_or(FactoryBackendError::InvalidTransaction)?;
        if !claimed.contains(&index)
            && (output.lock().as_slice() == custody.vault_lock
                || output.type_().to_opt().as_ref().map(Entity::as_slice)
                    == Some(custody.state_type.as_slice()))
        {
            return Err(FactoryBackendError::InvalidTransaction);
        }
    }
    Ok(())
}
fn validate_transition_source(
    source: &FactoryCustody,
    frame: &wire::FactoryReducedReleaseWitness<'_>,
) -> FactoryBackendResult<()> {
    if frame.before().as_bytes() != source.header
        || frame.source().as_bytes() != source.manifest.encode()?
        || frame.source_points() != encode_multi_asset_outpoints(&source.vault_outpoints)?
        || frame.old_state_outpoint() != outpoint_bytes(&source.state_out_point)
        || frame.factory_lock_script() != source.vault_lock
        || frame.carrier_capacity() != source.state_carrier_capacity
    {
        return Err(FactoryBackendError::InvalidCustody);
    }
    for vault in &source.manifest.vaults {
        let id = crate::multi_asset::wire_asset(&vault.asset);
        if frame.type_script(id)? != source.type_script(id)? {
            return Err(FactoryBackendError::InvalidCustody);
        }
    }
    Ok(())
}
fn validate_materialisation_source(
    source: &FactoryCustody,
    intent: &wire::FactoryMaterialisationIntent<'_>,
) -> FactoryBackendResult<()> {
    if intent.chain_id() != source.state()?.chain_id()
        || intent.factory_id() != source.state()?.factory_id()
        || intent.participants_commitment() != source.state()?.participants_commitment()
        || intent.old_state_outpoint() != outpoint_bytes(&source.state_out_point)
        || intent.source().as_bytes() != source.manifest.encode()?
        || intent.source_points() != encode_multi_asset_outpoints(&source.vault_outpoints)?
        || intent.factory_carrier_capacity() != source.state_carrier_capacity
        || intent.factory_lock_script() != source.vault_lock
    {
        return Err(FactoryBackendError::InvalidCustody);
    }
    Ok(())
}
fn check_materialisation_body(
    raw: &packed::RawTransaction,
    source: &FactoryCustody,
    target: Option<&FactoryCustody>,
    intent: &wire::FactoryMaterialisationIntent<'_>,
) -> FactoryBackendResult<()> {
    if intent.transaction_hash() != raw.calc_tx_hash().as_slice() {
        return Err(FactoryBackendError::InvalidTransaction);
    }
    check_input(raw, 0, intent.old_state_outpoint())?;
    for index in 0..intent.source().count() {
        check_input(
            raw,
            index + 1,
            &intent.source_points()[index * 36..(index + 1) * 36],
        )?;
    }
    let mut claimed = BTreeSet::new();
    claimed.insert(0);
    match (intent.retained(), target) {
        (Some(retained), Some(target)) => {
            let data = raw
                .outputs_data()
                .get(0)
                .ok_or(FactoryBackendError::InvalidTransaction)?
                .raw_data();
            let header = wire::FactoryMultiAssetStateHeader::parse(&data)?;
            if !header.is_activation_to(&target.state()?)
                || retained.as_bytes() != target.manifest.encode()?
                || !source.identity_matches(target)?
            {
                return Err(FactoryBackendError::InvalidCustody);
            }
            check_output(
                raw,
                0,
                &source.state_lock,
                Some(&source.state_type),
                source.state_carrier_capacity,
                &data,
            )?;
            check_target_vaults(raw, target)?;
            for index in 1..=retained.count() {
                claimed.insert(index);
            }
        }
        (None, None) => check_output(
            raw,
            0,
            intent.refund_script(),
            None,
            source.state_carrier_capacity,
            &[],
        )?,
        _ => return Err(FactoryBackendError::InvalidCustody),
    }
    check_children(raw, intent, &mut claimed)?;
    for index in 0..raw.outputs().len() {
        let output = raw
            .outputs()
            .get(index)
            .ok_or(FactoryBackendError::InvalidTransaction)?;
        if !claimed.contains(&index)
            && (output.type_().to_opt().as_ref().map(Entity::as_slice)
                == Some(source.state_type.as_slice())
                || intent.is_custody_lock(&output.lock().calc_script_hash().unpack())?)
        {
            return Err(FactoryBackendError::InvalidTransaction);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactorySigningReservation {
    pub request_id: Bytes32,
    pub sequence: u64,
    pub role: FactorySigningRole,
    pub signing_digest: Bytes32,
    #[serde(deserialize_with = "required_factory_option")]
    pub source_state: Option<MultiAssetOutPoint>,
    #[serde(deserialize_with = "required_factory_option")]
    pub target_update_number: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FactoryObservedCustody {
    custody: FactoryCustody,
    rights: Vec<FactoryRight>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FactoryJournalRequest {
    request: FactorySigningRequest,
    #[serde(deserialize_with = "required_factory_option")]
    reservation_sequence: Option<u64>,
    #[serde(deserialize_with = "required_factory_option")]
    replacement_of: Option<Bytes32>,
    signatures: Vec<FactoryParticipantSignature>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FactoryJournalSnapshot {
    identity: FactoryCustody,
    members: Vec<FactoryParticipantKey>,
    local_participant: Bytes32,
    observed: Vec<FactoryObservedCustody>,
    #[serde(deserialize_with = "required_factory_option")]
    current: Option<MultiAssetOutPoint>,
    #[serde(deserialize_with = "required_factory_option")]
    active_request: Option<Bytes32>,
    requests: Vec<FactoryJournalRequest>,
}

/// One independent participant's monotonic authority journal. Reservations are
/// keyed by the EXACT source State OutPoint, across ALL roles/numbers. Ordinary
/// preparation cannot create another intent for a reserved source. An explicit
/// replacement receives a higher local sequence and RETAINS both authorizations:
/// either can win on chain, and signing is never an off-chain settlement receipt.
/// A changed canonical source is a new context; revisiting an old source still
/// sees every previous vote. Root authority is one exact request per immutable
/// Factory identity/first funding input. Never clone/roll back this authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "FactoryJournalSnapshot", into = "FactoryJournalSnapshot")]
pub struct FactorySignerJournal {
    snapshot: FactoryJournalSnapshot,
}
impl From<FactorySignerJournal> for FactoryJournalSnapshot {
    fn from(journal: FactorySignerJournal) -> Self {
        journal.snapshot
    }
}
impl TryFrom<FactoryJournalSnapshot> for FactorySignerJournal {
    type Error = FactoryBackendError;
    fn try_from(snapshot: FactoryJournalSnapshot) -> FactoryBackendResult<Self> {
        let journal = Self { snapshot };
        journal.validate()?;
        Ok(journal)
    }
}
impl FactorySignerJournal {
    pub fn new_root(
        request: FactorySigningRequest,
        members: Vec<FactoryParticipantKey>,
        local_participant: Bytes32,
    ) -> FactoryBackendResult<Self> {
        if request.role != FactorySigningRole::RootFunding {
            return Err(FactoryBackendError::WrongRole);
        }
        request.validate(&members)?;
        let identity = request
            .target
            .clone()
            .ok_or(FactoryBackendError::InvalidCustody)?;
        let id = request.request_id()?;
        Self::try_from(FactoryJournalSnapshot {
            identity,
            members,
            local_participant,
            observed: vec![],
            current: None,
            active_request: Some(id),
            requests: vec![FactoryJournalRequest {
                request,
                reservation_sequence: None,
                replacement_of: None,
                signatures: vec![],
            }],
        })
    }
    /// Guarded import/handoff only. Native operational commands must establish
    /// canonical provenance and keep the same stable locked journal path; this
    /// constructor is not permission to create a second signing authority.
    pub fn from_confirmed(
        custody: FactoryCustody,
        rights: Vec<FactoryRight>,
        members: Vec<FactoryParticipantKey>,
        local_participant: Bytes32,
    ) -> FactoryBackendResult<Self> {
        Self::try_from(FactoryJournalSnapshot {
            identity: custody.clone(),
            members,
            local_participant,
            current: Some(custody.state_out_point.clone()),
            observed: vec![FactoryObservedCustody { custody, rights }],
            active_request: None,
            requests: vec![],
        })
    }
    pub fn validate(&self) -> FactoryBackendResult<()> {
        self.snapshot.identity.validate()?;
        let commitment = factory_membership_commitment(&self.snapshot.members)?;
        if self.snapshot.identity.state()?.participants_commitment() != commitment
            || !self
                .snapshot
                .members
                .iter()
                .any(|member| member.participant == self.snapshot.local_participant)
        {
            return Err(FactoryBackendError::InvalidMembers);
        }
        let mut points = BTreeSet::new();
        for observed in &self.snapshot.observed {
            self.validate_observed(&observed.custody, &observed.rights)?;
            if !points.insert(outpoint_bytes(&observed.custody.state_out_point)) {
                return Err(FactoryBackendError::InvalidCustody);
            }
        }
        if self.snapshot.current.as_ref().is_some_and(|point| {
            !self
                .snapshot
                .observed
                .iter()
                .any(|entry| &entry.custody.state_out_point == point)
        }) {
            return Err(FactoryBackendError::InvalidCustody);
        }
        let mut ids = BTreeSet::new();
        let mut reserved_sources = BTreeSet::new();
        let mut sequences = BTreeSet::new();
        for (entry_index, entry) in self.snapshot.requests.iter().enumerate() {
            entry.request.validate(&self.snapshot.members)?;
            let anchor = entry
                .request
                .target
                .as_ref()
                .or(entry.request.source.as_ref())
                .ok_or(FactoryBackendError::InvalidCustody)?;
            if !self.snapshot.identity.identity_matches(anchor)? {
                return Err(FactoryBackendError::InvalidCustody);
            }
            let id = entry.request.request_id()?;
            if !ids.insert(id) {
                return Err(FactoryBackendError::ConflictingVote);
            }
            if let Some(source) = &entry.request.source
                && !self
                    .snapshot
                    .observed
                    .iter()
                    .any(|observed| &observed.custody == source)
            {
                return Err(FactoryBackendError::InvalidCustody);
            }
            if let Some(previous_id) = entry.replacement_of {
                let previous = self.snapshot.requests[..entry_index]
                    .iter()
                    .find(|previous| previous.request.request_id().ok() == Some(previous_id))
                    .ok_or(FactoryBackendError::ConflictingVote)?;
                if entry.request.role == FactorySigningRole::RootFunding
                    || previous.request.source.is_none()
                    || request_source_key(&entry.request) != request_source_key(&previous.request)
                    || (previous.reservation_sequence.is_none() && previous.signatures.is_empty())
                {
                    return Err(FactoryBackendError::ConflictingVote);
                }
            }
            if let Some(sequence) = entry.reservation_sequence {
                if sequence == 0 || !sequences.insert(sequence) {
                    return Err(FactoryBackendError::ConflictingVote);
                }
                if !reserved_sources.insert(request_source_key(&entry.request))
                    && entry.replacement_of.is_none()
                {
                    return Err(FactoryBackendError::ConflictingVote);
                }
                if let Some(previous_id) = entry.replacement_of {
                    let previous = self.snapshot.requests[..entry_index]
                        .iter()
                        .find(|previous| previous.request.request_id().ok() == Some(previous_id))
                        .ok_or(FactoryBackendError::ConflictingVote)?;
                    if previous
                        .reservation_sequence
                        .is_some_and(|previous| previous >= sequence)
                    {
                        return Err(FactoryBackendError::ConflictingVote);
                    }
                }
            }
            let required = entry.request.required_members()?;
            if entry.reservation_sequence.is_some()
                && !required
                    .iter()
                    .any(|member| member.participant == self.snapshot.local_participant)
            {
                return Err(FactoryBackendError::InvalidMembers);
            }
            let mut signers = BTreeSet::new();
            for signature in &entry.signatures {
                entry.request.verify_participant_signature(signature)?;
                if !signers.insert(signature.participant) {
                    return Err(FactoryBackendError::InvalidSignature);
                }
                if signature.participant == self.snapshot.local_participant
                    && entry.reservation_sequence.is_none()
                {
                    return Err(FactoryBackendError::UnreservedSignature);
                }
            }
            if entry
                .signatures
                .windows(2)
                .any(|pair| pair[0].participant >= pair[1].participant)
            {
                return Err(FactoryBackendError::InvalidSignature);
            }
        }
        if sequences
            .last()
            .is_some_and(|last| *last != sequences.len() as u64)
        {
            return Err(FactoryBackendError::ConflictingVote);
        }
        if let Some(id) = self.snapshot.active_request {
            let entry = self.entry(&id)?;
            if !self.request_uses_current(&entry.request) {
                return Err(FactoryBackendError::WrongContext);
            }
        }
        Ok(())
    }
    fn validate_observed(
        &self,
        custody: &FactoryCustody,
        rights: &[FactoryRight],
    ) -> FactoryBackendResult<()> {
        custody.validate()?;
        if !self.snapshot.identity.identity_matches(custody)? {
            return Err(FactoryBackendError::InvalidCustody);
        }
        validate_factory_initial_rights(&self.snapshot.members, &custody.manifest, rights)?;
        if factory_right_sparse_root(rights).map_err(|_| FactoryBackendError::InvalidRights)?
            != custody.state()?.state_root()
        {
            return Err(FactoryBackendError::InvalidRights);
        }
        Ok(())
    }
    pub fn members(&self) -> &[FactoryParticipantKey] {
        &self.snapshot.members
    }
    pub fn local_participant(&self) -> Bytes32 {
        self.snapshot.local_participant
    }
    pub fn current(&self) -> Option<&FactoryCustody> {
        let point = self.snapshot.current.as_ref()?;
        self.snapshot
            .observed
            .iter()
            .find(|entry| &entry.custody.state_out_point == point)
            .map(|entry| &entry.custody)
    }
    pub fn current_rights(&self) -> Option<&[FactoryRight]> {
        let point = self.snapshot.current.as_ref()?;
        self.snapshot
            .observed
            .iter()
            .find(|entry| &entry.custody.state_out_point == point)
            .map(|entry| entry.rights.as_slice())
    }
    pub fn active_request_id(&self) -> Option<Bytes32> {
        self.snapshot.active_request
    }
    pub fn request(&self, id: &Bytes32) -> FactoryBackendResult<&FactorySigningRequest> {
        Ok(&self.entry(id)?.request)
    }
    pub fn signatures(&self, id: &Bytes32) -> FactoryBackendResult<&[FactoryParticipantSignature]> {
        Ok(&self.entry(id)?.signatures)
    }
    fn entry(&self, id: &Bytes32) -> FactoryBackendResult<&FactoryJournalRequest> {
        self.snapshot
            .requests
            .iter()
            .find(|entry| entry.request.request_id().ok().as_ref() == Some(id))
            .ok_or(FactoryBackendError::UnknownRequest)
    }
    fn entry_mut(&mut self, id: &Bytes32) -> FactoryBackendResult<&mut FactoryJournalRequest> {
        self.snapshot
            .requests
            .iter_mut()
            .find(|entry| entry.request.request_id().ok().as_ref() == Some(id))
            .ok_or(FactoryBackendError::UnknownRequest)
    }
    fn request_uses_current(&self, request: &FactorySigningRequest) -> bool {
        match (&request.source, self.current()) {
            (Some(source), Some(current)) => source == current,
            (None, None) => {
                request.role == FactorySigningRole::RootFunding && self.snapshot.observed.is_empty()
            }
            _ => false,
        }
    }
    pub fn prepare_request(
        &mut self,
        request: FactorySigningRequest,
    ) -> FactoryBackendResult<Bytes32> {
        self.validate()?;
        if !self.request_uses_current(&request) {
            return Err(FactoryBackendError::WrongContext);
        }
        let id = request.request_id()?;
        if self.snapshot.requests.iter().any(|entry| {
            entry.reservation_sequence.is_some()
                && request_source_key(&entry.request) == request_source_key(&request)
                && entry.request.request_id().ok() != Some(id)
        }) {
            return Err(FactoryBackendError::ConflictingVote);
        }
        request.validate(&self.snapshot.members)?;
        let anchor = request
            .target
            .as_ref()
            .or(request.source.as_ref())
            .ok_or(FactoryBackendError::InvalidCustody)?;
        if !self.snapshot.identity.identity_matches(anchor)? {
            return Err(FactoryBackendError::InvalidCustody);
        }
        if let Some(active) = self.snapshot.active_request
            && active != id
        {
            return Err(FactoryBackendError::PendingRequest);
        }
        if let Some(existing) = self
            .snapshot
            .requests
            .iter()
            .find(|entry| entry.request.request_id().ok() == Some(id))
        {
            // Valid alternative delivery signatures attest the same terms.
            if existing.request.transaction != request.transaction
                || existing.request.witness != request.witness
                || existing.request.source != request.source
                || existing.request.target != request.target
                || existing.request.target_rights != request.target_rights
            {
                return Err(FactoryBackendError::ConflictingVote);
            }
        } else {
            self.snapshot.requests.push(FactoryJournalRequest {
                request,
                reservation_sequence: None,
                replacement_of: None,
                signatures: vec![],
            });
        }
        self.snapshot.active_request = Some(id);
        Ok(id)
    }
    /// Explicitly approve an alternative spend of the SAME exact source.
    /// The previous approval is NOT revoked, even if a peer withholds the last
    /// N-of-N signature. Both packets remain exportable; the first canonical
    /// spend consumes the source and makes every alternative unspendable.
    /// This keeps a reduced escape available without changing consensus +1.
    pub fn prepare_replacement(
        &mut self,
        previous_id: &Bytes32,
        request: FactorySigningRequest,
    ) -> FactoryBackendResult<Bytes32> {
        self.validate()?;
        let previous = self.entry(previous_id)?;
        if request.role == FactorySigningRole::RootFunding
            || previous.request.source.is_none()
            || (previous.reservation_sequence.is_none() && previous.signatures.is_empty())
            || request_source_key(&previous.request) != request_source_key(&request)
            || !self.request_uses_current(&request)
        {
            return Err(FactoryBackendError::WrongContext);
        }
        request.validate(&self.snapshot.members)?;
        let id = request.request_id()?;
        if self
            .snapshot
            .active_request
            .is_some_and(|active| active != *previous_id && active != id)
        {
            return Err(FactoryBackendError::PendingRequest);
        }
        if id == *previous_id {
            return Err(FactoryBackendError::ConflictingVote);
        }
        if let Ok(existing) = self.entry(&id) {
            if existing.replacement_of != Some(*previous_id) || existing.request != request {
                return Err(FactoryBackendError::ConflictingVote);
            }
        } else {
            self.snapshot.requests.push(FactoryJournalRequest {
                request,
                reservation_sequence: None,
                replacement_of: Some(*previous_id),
                signatures: vec![],
            });
        }
        self.snapshot.active_request = Some(id);
        Ok(id)
    }
    pub fn source_authorizations(
        &self,
        source: &MultiAssetOutPoint,
    ) -> FactoryBackendResult<Vec<FactorySigningReservation>> {
        self.snapshot
            .requests
            .iter()
            .filter_map(|entry| {
                let sequence = entry.reservation_sequence?;
                if entry
                    .request
                    .source
                    .as_ref()
                    .map(|custody| &custody.state_out_point)
                    != Some(source)
                {
                    return None;
                }
                Some(signing_reservation(&entry.request, sequence))
            })
            .collect()
    }
    /// Persist and fsync the journal before invoking the local parent key.
    pub fn reserve_signature(
        &mut self,
        id: &Bytes32,
    ) -> FactoryBackendResult<FactorySigningReservation> {
        self.validate()?;
        if self.snapshot.active_request != Some(*id) {
            return Err(FactoryBackendError::WrongContext);
        }
        let request = &self.entry(id)?.request;
        if !self.request_uses_current(request) {
            return Err(FactoryBackendError::WrongContext);
        }
        if !request
            .required_members()?
            .iter()
            .any(|member| member.participant == self.snapshot.local_participant)
        {
            return Err(FactoryBackendError::InvalidMembers);
        }
        let key = request_source_key(request);
        let replacement = self.entry(id)?.replacement_of.is_some();
        if !replacement
            && self.snapshot.requests.iter().any(|entry| {
                entry.reservation_sequence.is_some()
                    && request_source_key(&entry.request) == key
                    && entry.request.request_id().ok() != Some(*id)
            })
        {
            return Err(FactoryBackendError::ConflictingVote);
        }
        let sequence = match self.entry(id)?.reservation_sequence {
            Some(sequence) => sequence,
            None => self
                .snapshot
                .requests
                .iter()
                .filter_map(|entry| entry.reservation_sequence)
                .max()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(FactoryBackendError::ConflictingVote)?,
        };
        let reservation = signing_reservation(request, sequence)?;
        self.entry_mut(id)?.reservation_sequence = Some(sequence);
        Ok(reservation)
    }
    /// Persist before disclosing a local signature. Importing peer receipts and
    /// exporting completed historical packets never require a new signature.
    pub fn record_signature(
        &mut self,
        id: &Bytes32,
        signature: FactoryParticipantSignature,
    ) -> FactoryBackendResult<()> {
        self.validate()?;
        let entry = self.entry(id)?;
        entry.request.verify_participant_signature(&signature)?;
        if signature.participant == self.snapshot.local_participant
            && entry.reservation_sequence.is_none()
        {
            return Err(FactoryBackendError::UnreservedSignature);
        }
        if let Some(existing) = entry
            .signatures
            .iter()
            .find(|entry| entry.participant == signature.participant)
        {
            return if existing == &signature {
                Ok(())
            } else {
                Err(FactoryBackendError::InvalidSignature)
            };
        }
        let entry = self.entry_mut(id)?;
        entry.signatures.push(signature);
        entry.signatures.sort_by_key(|entry| entry.participant);
        Ok(())
    }
    pub fn authorized_witness(&self, id: &Bytes32) -> FactoryBackendResult<Vec<u8>> {
        self.validate()?;
        let entry = self.entry(id)?;
        entry.request.authorized_witness(&entry.signatures)
    }
    pub fn cancel_request(&mut self, id: &Bytes32) -> FactoryBackendResult<()> {
        self.validate()?;
        let entry = self.entry(id)?;
        if entry.reservation_sequence.is_some() || !entry.signatures.is_empty() {
            return Err(FactoryBackendError::ConflictingVote);
        }
        if self.snapshot.active_request != Some(*id) {
            return Err(FactoryBackendError::WrongContext);
        }
        self.snapshot.active_request = None;
        Ok(())
    }
    /// Called only after the native operator verifies canonical unique Factory
    /// lineage, actual authenticated State/Vault cells and complete rights data.
    /// Reorg observations may revisit an old source; its previous vote survives.
    pub fn observe_canonical(
        &mut self,
        custody: FactoryCustody,
        rights: Vec<FactoryRight>,
    ) -> FactoryBackendResult<()> {
        self.validate()?;
        self.validate_observed(&custody, &rights)?;
        let point = custody.state_out_point.clone();
        if let Some(known) = self
            .snapshot
            .observed
            .iter()
            .find(|entry| entry.custody.state_out_point == point)
        {
            if known.custody != custody || known.rights != rights {
                return Err(FactoryBackendError::InvalidCustody);
            }
        } else {
            self.snapshot
                .observed
                .push(FactoryObservedCustody { custody, rights });
        }
        self.snapshot.current = Some(point);
        if let Some(id) = self.snapshot.active_request
            && !self.request_uses_current(&self.entry(&id)?.request)
        {
            self.snapshot.active_request = None;
        }
        Ok(())
    }
    /// The wrapper proves the exact request canonical and, when needed, its
    /// whole-set activation. Candidate source facts alone are not confirmation.
    pub fn confirm_request(
        &mut self,
        id: &Bytes32,
        observed: Option<FactoryCustody>,
    ) -> FactoryBackendResult<()> {
        self.authorized_witness(id)?;
        let request = self.entry(id)?.request.clone();
        if !self.request_uses_current(&request) {
            return Err(FactoryBackendError::WrongContext);
        }
        match (&request.target, observed) {
            (Some(target), Some(observed)) => {
                let mut expected = target.clone();
                if request.requires_activation()? {
                    expected.state_out_point = observed.state_out_point.clone();
                }
                if expected != observed {
                    return Err(FactoryBackendError::InvalidCustody);
                }
                self.observe_canonical(observed, request.target_rights)?;
            }
            (None, None) if request.role == FactorySigningRole::Materialisation => {
                self.snapshot.current = None;
                self.snapshot.active_request = None;
            }
            _ => return Err(FactoryBackendError::InvalidCustody),
        }
        Ok(())
    }
}
fn request_source_key(request: &FactorySigningRequest) -> Vec<u8> {
    match &request.source {
        None => vec![0],
        Some(source) => {
            let mut key = vec![1];
            key.extend_from_slice(&outpoint_bytes(&source.state_out_point));
            key
        }
    }
}
fn signing_reservation(
    request: &FactorySigningRequest,
    sequence: u64,
) -> FactoryBackendResult<FactorySigningReservation> {
    Ok(FactorySigningReservation {
        request_id: request.request_id()?,
        sequence,
        role: request.role,
        signing_digest: request.signing_digest()?,
        source_state: request
            .source
            .as_ref()
            .map(|source| source.state_out_point.clone()),
        target_update_number: request
            .target
            .as_ref()
            .map(|target| target.state().map(|header| header.update_number()))
            .transpose()?,
    })
}
impl FactorySigningRequest {
    pub fn requires_activation(&self) -> FactoryBackendResult<bool> {
        Ok(match self.role {
            FactorySigningRole::RootFunding => true,
            FactorySigningRole::Materialisation => self.target.is_some(),
            FactorySigningRole::Transition => {
                wire::FactoryReducedReleaseWitness::parse(&self.witness)?
                    .operation()
                    .moves_custody()
            }
            FactorySigningRole::MetadataUpdate => false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FactoryBackendError {
    #[error("another intent was permanently reserved for this exact Factory source")]
    ConflictingVote,
    #[error("Factory request is not based on the observed canonical source")]
    WrongContext,
    #[error("another Factory request is pending")]
    PendingRequest,
    #[error("Factory request was not found")]
    UnknownRequest,
    #[error("local signature has no matching durable reservation")]
    UnreservedSignature,
    #[error("Factory request uses the wrong signing role")]
    WrongRole,
    #[error("unsigned Factory request already contains a spending signature")]
    HiddenSignature,
    #[error("both child parties must attest possession of the exact complete private exit")]
    InvalidDelivery,
    #[error("invalid Factory participant signature")]
    InvalidSignature,
    #[error("required Factory signatures are incomplete")]
    IncompleteSignatures,
    #[error("Factory membership is not the canonical committed N-of-N set")]
    InvalidMembers,
    #[error("Factory rights are noncanonical, unowned or exceed per-asset physical backing")]
    InvalidRights,
    #[error("Factory custody is incomplete or does not match the current identity")]
    InvalidCustody,
    #[error("Factory packed transaction differs from its exact current authorization")]
    InvalidTransaction,
    #[error(transparent)]
    Evidence(#[from] MultiAssetError),
}
impl From<ScriptError> for FactoryBackendError {
    fn from(error: ScriptError) -> Self {
        Self::Evidence(error.into())
    }
}
pub type FactoryBackendResult<T> = Result<T, FactoryBackendError>;
