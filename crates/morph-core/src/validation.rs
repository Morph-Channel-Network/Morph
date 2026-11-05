use crate::hash::blake2b256;
use crate::types::*;
use morph_script_common::{
    FACTORY_COMPACT_PROOF_MAX_SIBLINGS, FACTORY_RIGHT_EMPTY_DOMAIN, FACTORY_RIGHT_KEY_DOMAIN,
    FACTORY_RIGHT_LEAF_DOMAIN, FACTORY_RIGHT_NODE_DOMAIN,
};
use std::collections::BTreeMap;
use thiserror::Error;
const FACTORY_SPARSE_MERKLE_DEPTH: usize = 256;
pub const FACTORY_RIGHT_EMPTY_SUBTREE_DOMAIN: &[u8] = FACTORY_RIGHT_EMPTY_DOMAIN;
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MorphError {
    #[error("output capacity is below occupied capacity")]
    OutputBelowOccupiedCapacity,
    #[error("classified cell fields are inconsistent with its declared class")]
    InvalidCellClassification,
    #[error("unrelated cell participates in channel semantics")]
    UnrelatedCellUsed,
    #[error("channel reserve is not conserved")]
    ReserveNotConserved,
    #[error("business CKB is not conserved")]
    BusinessCkbNotConserved,
    #[error("xUDT asset type is not registered")]
    UnregisteredXudtType,
    #[error("xUDT amount is not conserved for registered type")]
    XudtNotConserved,
    #[error("State Cell carrier capacity is not conserved")]
    StateCarrierNotConserved,
    #[error("sponsor partition does not exactly pay the transaction fee")]
    SponsorFeeMismatch,
    #[error("sponsor output carries channel business asset or vault lock")]
    SponsorChangeContaminated,
    #[error("sponsor policy channel mismatch")]
    SponsorChannelMismatch,
    #[error("sponsor policy state number outside authorised range")]
    SponsorStateOutOfRange,
    #[error("sponsor publication state type hash mismatch")]
    SponsorStateTypeMismatch,
    #[error("sponsor change lock mismatch")]
    SponsorChangeLockMismatch,
    #[error("sponsor fee exceeds per-transaction limit")]
    SponsorFeeTooHigh,
    #[error("sponsor total budget exceeded")]
    SponsorBudgetExceeded,
    #[error("sponsor policy may only pay publication or supersede transactions")]
    SponsorOperationNotAllowed,
    #[error("factory update has duplicate right identifiers")]
    FactoryDuplicateRight,
    #[error("factory Merkle proof is invalid")]
    FactoryMerkleProofInvalid,
    #[error("factory Merkle proof changes data outside the proved right")]
    FactoryMerkleProofInterference,
}
pub type Result<T> = std::result::Result<T, MorphError>;
pub fn validate_sponsor_policy(policy: &SponsorPolicy, spend: &SponsorSpend) -> Result<()> {
    if spend.channel_id != policy.channel_id {
        return Err(MorphError::SponsorChannelMismatch);
    }
    if spend.state_number < policy.min_state_number || spend.state_number > policy.max_state_number
    {
        return Err(MorphError::SponsorStateOutOfRange);
    }
    if spend.publication_state_type_hash != policy.publication_state_type_hash {
        return Err(MorphError::SponsorStateTypeMismatch);
    }
    if spend.change_lock != policy.change_lock {
        return Err(MorphError::SponsorChangeLockMismatch);
    }
    if spend.fee > policy.max_fee_per_tx {
        return Err(MorphError::SponsorFeeTooHigh);
    }
    if policy
        .already_spent
        .checked_add(spend.fee)
        .ok_or(MorphError::SponsorBudgetExceeded)?
        > policy.max_total_fee
    {
        return Err(MorphError::SponsorBudgetExceeded);
    }
    if !spend.operation.is_publication_or_supersede() {
        return Err(MorphError::SponsorOperationNotAllowed);
    }
    Ok(())
}

pub fn verify_factory_right_merkle_proof(
    expected_root: Bytes32,
    proof: &FactoryRightMerkleProof,
) -> Result<()> {
    if proof.siblings.len() != FACTORY_SPARSE_MERKLE_DEPTH {
        return Err(MorphError::FactoryMerkleProofInvalid);
    }
    let mut current = factory_right_leaf_hash(&proof.right);
    for (depth, sibling) in proof.siblings.iter().enumerate().rev() {
        current = match sibling.side {
            FactoryMerkleSiblingSide::Left => factory_right_node_hash(depth, sibling.hash, current),
            FactoryMerkleSiblingSide::Right => {
                factory_right_node_hash(depth, current, sibling.hash)
            }
        };
    }
    if current == expected_root {
        Ok(())
    } else {
        Err(MorphError::FactoryMerkleProofInvalid)
    }
}

pub fn factory_right_sparse_root(rights: &[FactoryRight]) -> Result<Bytes32> {
    let entries = factory_sparse_entries(rights)?;
    let empty_hashes = factory_empty_hashes();
    Ok(factory_sparse_subtree_root(&entries, 0, &empty_hashes))
}

pub fn factory_right_sparse_proof(
    rights: &[FactoryRight],
    id: &FactoryRightId,
) -> Result<FactoryRightMerkleProof> {
    let entries = factory_sparse_entries(rights)?;
    let key = factory_right_key(id);
    let empty_hashes = factory_empty_hashes();
    let mut siblings = Vec::with_capacity(FACTORY_SPARSE_MERKLE_DEPTH);
    let right = factory_sparse_proof_inner(&entries, key, 0, &empty_hashes, &mut siblings)?;
    Ok(FactoryRightMerkleProof { right, siblings })
}

pub fn factory_empty_subtree_hash(height: usize) -> Bytes32 {
    factory_empty_hashes()[height]
}

pub fn factory_right_sparse_proof_compact(
    rights: &[FactoryRight],
    id: &FactoryRightId,
) -> Result<FactoryCompactRightProof> {
    let full = factory_right_sparse_proof(rights, id)?;
    let empty_hashes = factory_empty_hashes();
    let mut siblings = Vec::new();
    for (depth, sibling) in full.siblings.iter().enumerate() {
        if sibling.hash != empty_hashes[FACTORY_SPARSE_MERKLE_DEPTH - depth - 1] {
            siblings.push(FactoryCompactMerkleSibling {
                depth: depth as u16,
                hash: sibling.hash,
            });
        }
    }
    if siblings.len() > FACTORY_COMPACT_PROOF_MAX_SIBLINGS {
        return Err(MorphError::FactoryMerkleProofInvalid);
    }
    siblings.reverse();
    Ok(FactoryCompactRightProof {
        right: full.right,
        siblings,
    })
}

pub fn verify_factory_right_compact_proof(
    expected_root: Bytes32,
    proof: &FactoryCompactRightProof,
) -> Result<()> {
    if proof.siblings.len() > FACTORY_COMPACT_PROOF_MAX_SIBLINGS {
        return Err(MorphError::FactoryMerkleProofInvalid);
    }
    let key = factory_right_key(&proof.right.id);
    let mut current = factory_right_leaf_hash(&proof.right);
    let mut pair_index = 0usize;
    let mut empty = blake2b256(FACTORY_RIGHT_EMPTY_DOMAIN);
    for depth in (0..FACTORY_SPARSE_MERKLE_DEPTH).rev() {
        let sibling = match proof.siblings.get(pair_index) {
            Some(sibling) if usize::from(sibling.depth) == depth => {
                pair_index += 1;
                sibling.hash
            }
            _ => empty,
        };
        current = if factory_key_bit(&key, depth) {
            factory_right_node_hash(depth, sibling, current)
        } else {
            factory_right_node_hash(depth, current, sibling)
        };
        empty = factory_right_node_hash(depth, empty, empty);
    }
    if pair_index != proof.siblings.len() || current != expected_root {
        return Err(MorphError::FactoryMerkleProofInvalid);
    }
    Ok(())
}

pub fn verify_factory_right_compact_proof_pair(
    before_root: Bytes32,
    after_root: Bytes32,
    before_proof: &FactoryCompactRightProof,
    after_proof: &FactoryCompactRightProof,
    other_keys: &[Bytes32],
) -> Result<()> {
    if before_proof.siblings.len() > FACTORY_COMPACT_PROOF_MAX_SIBLINGS
        || after_proof.siblings.len() > FACTORY_COMPACT_PROOF_MAX_SIBLINGS
        || before_proof.right.id != after_proof.right.id
    {
        return Err(MorphError::FactoryMerkleProofInvalid);
    }
    let key = factory_right_key(&before_proof.right.id);
    let mut current_before = factory_right_leaf_hash(&before_proof.right);
    let mut current_after = factory_right_leaf_hash(&after_proof.right);
    let mut pair_before = 0usize;
    let mut pair_after = 0usize;
    let mut empty = blake2b256(FACTORY_RIGHT_EMPTY_DOMAIN);
    for depth in (0..FACTORY_SPARSE_MERKLE_DEPTH).rev() {
        let sibling_before = match before_proof.siblings.get(pair_before) {
            Some(sibling) if usize::from(sibling.depth) == depth => {
                pair_before += 1;
                sibling.hash
            }
            _ => empty,
        };
        let sibling_after = match after_proof.siblings.get(pair_after) {
            Some(sibling) if usize::from(sibling.depth) == depth => {
                pair_after += 1;
                sibling.hash
            }
            _ => empty,
        };
        if sibling_before != sibling_after {
            let sibling_bit = !factory_key_bit(&key, depth);
            if !other_keys
                .iter()
                .any(|other| factory_key_in_sibling_subtree(&key, other, depth, sibling_bit))
            {
                return Err(MorphError::FactoryMerkleProofInterference);
            }
        }
        current_before = if factory_key_bit(&key, depth) {
            factory_right_node_hash(depth, sibling_before, current_before)
        } else {
            factory_right_node_hash(depth, current_before, sibling_before)
        };
        current_after = if factory_key_bit(&key, depth) {
            factory_right_node_hash(depth, sibling_after, current_after)
        } else {
            factory_right_node_hash(depth, current_after, sibling_after)
        };
        empty = factory_right_node_hash(depth, empty, empty);
    }
    if pair_before != before_proof.siblings.len()
        || pair_after != after_proof.siblings.len()
        || current_before != before_root
        || current_after != after_root
    {
        return Err(MorphError::FactoryMerkleProofInvalid);
    }
    Ok(())
}

fn factory_key_in_sibling_subtree(
    key: &Bytes32,
    candidate: &Bytes32,
    depth: usize,
    sibling_bit: bool,
) -> bool {
    let full_bytes = depth / 8;
    if candidate[..full_bytes] != key[..full_bytes] {
        return false;
    }
    let remainder = depth % 8;
    if remainder != 0 {
        let mask = 0xffu8 << (8 - remainder);
        if candidate[full_bytes] & mask != key[full_bytes] & mask {
            return false;
        }
    }
    factory_key_bit(candidate, depth) == sibling_bit
}

pub fn factory_right_key(id: &FactoryRightId) -> Bytes32 {
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(FACTORY_RIGHT_KEY_DOMAIN);
    bytes.extend_from_slice(&id.participant);
    bytes.extend_from_slice(&id.subchannel);
    bytes.push(factory_right_kind_byte(id.kind));
    match id.asset_type {
        Some(asset_type) => {
            bytes.push(1);
            bytes.extend_from_slice(&asset_type);
        }
        None => {
            bytes.push(0);
            bytes.extend_from_slice(&[0u8; 32]);
        }
    }
    blake2b256(&bytes)
}

pub fn factory_right_leaf_hash(right: &FactoryRight) -> Bytes32 {
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(FACTORY_RIGHT_LEAF_DOMAIN);
    bytes.extend_from_slice(&factory_right_key(&right.id));
    bytes.extend_from_slice(&right.id.participant);
    bytes.extend_from_slice(&right.id.subchannel);
    bytes.push(factory_right_kind_byte(right.id.kind));
    match right.id.asset_type {
        Some(asset_type) => {
            bytes.push(1);
            bytes.extend_from_slice(&asset_type);
        }
        None => {
            bytes.push(0);
            bytes.extend_from_slice(&[0u8; 32]);
        }
    }
    bytes.extend_from_slice(&right.quantity.to_le_bytes());
    blake2b256(&bytes)
}

pub fn validate_partition_conservation(
    tx: &PartitionedTransaction,
    registry: &AssetRegistry,
) -> Result<PartitionTotals> {
    for output in &tx.outputs {
        if output.capacity < output.occupied_capacity {
            return Err(MorphError::OutputBelowOccupiedCapacity);
        }
    }
    for cell in tx.inputs.iter().chain(tx.outputs.iter()) {
        validate_classified_cell(cell)?;
    }

    let mut totals = PartitionTotals {
        reserve_in: 0,
        reserve_out: 0,
        business_ckb_in: 0,
        business_ckb_out: 0,
        xudt_in: BTreeMap::new(),
        xudt_out: BTreeMap::new(),
        state_carrier_in: 0,
        state_carrier_out: 0,
        sponsor_in: 0,
        sponsor_out: 0,
    };

    fold_cells(&tx.inputs, registry, true, &mut totals)?;
    fold_cells(&tx.outputs, registry, false, &mut totals)?;

    let reserve_out_with_refund = totals
        .reserve_out
        .checked_add(tx.authorised_reserve_refund)
        .ok_or(MorphError::ReserveNotConserved)?;
    if reserve_out_with_refund != totals.reserve_in {
        return Err(MorphError::ReserveNotConserved);
    }
    if totals.state_carrier_in != totals.state_carrier_out {
        return Err(MorphError::StateCarrierNotConserved);
    }
    if totals.business_ckb_in != totals.business_ckb_out {
        return Err(MorphError::BusinessCkbNotConserved);
    }
    for asset_type in &registry.xudt_types {
        let input = totals.xudt_in.get(asset_type).copied().unwrap_or_default();
        let output = totals.xudt_out.get(asset_type).copied().unwrap_or_default();
        if input != output {
            return Err(MorphError::XudtNotConserved);
        }
    }
    let sponsor_fee = totals
        .sponsor_in
        .checked_sub(totals.sponsor_out)
        .ok_or(MorphError::SponsorFeeMismatch)?;
    if sponsor_fee != tx.tx_fee {
        return Err(MorphError::SponsorFeeMismatch);
    }
    for output in &tx.outputs {
        if matches!(output.class, CellClass::Sponsor)
            && (output.carries_registered_xudt || output.uses_channel_vault_lock)
        {
            return Err(MorphError::SponsorChangeContaminated);
        }
    }

    Ok(totals)
}

fn factory_sparse_entries(
    rights: &[FactoryRight],
) -> Result<Vec<(Bytes32, Bytes32, FactoryRight)>> {
    let mut entries = rights
        .iter()
        .map(|right| {
            (
                factory_right_key(&right.id),
                factory_right_leaf_hash(right),
                right.clone(),
            )
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    if entries.windows(2).any(|window| window[0].0 == window[1].0) {
        return Err(MorphError::FactoryDuplicateRight);
    }
    Ok(entries)
}

fn factory_sparse_proof_inner(
    entries: &[(Bytes32, Bytes32, FactoryRight)],
    target_key: Bytes32,
    depth: usize,
    empty_hashes: &[Bytes32; FACTORY_SPARSE_MERKLE_DEPTH + 1],
    siblings: &mut Vec<FactoryMerkleSibling>,
) -> Result<FactoryRight> {
    if depth == FACTORY_SPARSE_MERKLE_DEPTH {
        return entries
            .iter()
            .find(|(key, _, _)| *key == target_key)
            .map(|(_, _, right)| right.clone())
            .ok_or(MorphError::FactoryMerkleProofInvalid);
    }

    let split = entries.partition_point(|(key, _, _)| !factory_key_bit(key, depth));
    let target_is_right = factory_key_bit(&target_key, depth);
    let (branch, sibling, side) = if target_is_right {
        (
            &entries[split..],
            &entries[..split],
            FactoryMerkleSiblingSide::Left,
        )
    } else {
        (
            &entries[..split],
            &entries[split..],
            FactoryMerkleSiblingSide::Right,
        )
    };
    let sibling_hash = factory_sparse_subtree_root(sibling, depth + 1, empty_hashes);
    siblings.push(FactoryMerkleSibling {
        side,
        hash: sibling_hash,
    });
    factory_sparse_proof_inner(branch, target_key, depth + 1, empty_hashes, siblings)
}

fn factory_sparse_subtree_root(
    entries: &[(Bytes32, Bytes32, FactoryRight)],
    depth: usize,
    empty_hashes: &[Bytes32; FACTORY_SPARSE_MERKLE_DEPTH + 1],
) -> Bytes32 {
    if entries.is_empty() {
        return empty_hashes[FACTORY_SPARSE_MERKLE_DEPTH - depth];
    }
    if depth == FACTORY_SPARSE_MERKLE_DEPTH {
        return entries[0].1;
    }

    let split = entries.partition_point(|(key, _, _)| !factory_key_bit(key, depth));
    let left = factory_sparse_subtree_root(&entries[..split], depth + 1, empty_hashes);
    let right = factory_sparse_subtree_root(&entries[split..], depth + 1, empty_hashes);
    factory_right_node_hash(depth, left, right)
}

fn factory_empty_hashes() -> [Bytes32; FACTORY_SPARSE_MERKLE_DEPTH + 1] {
    let mut out = [[0u8; 32]; FACTORY_SPARSE_MERKLE_DEPTH + 1];
    out[0] = blake2b256(FACTORY_RIGHT_EMPTY_DOMAIN);
    for height in 1..=FACTORY_SPARSE_MERKLE_DEPTH {
        out[height] = factory_right_node_hash(
            FACTORY_SPARSE_MERKLE_DEPTH - height,
            out[height - 1],
            out[height - 1],
        );
    }
    out
}

fn factory_right_node_hash(depth: usize, left: Bytes32, right: Bytes32) -> Bytes32 {
    let mut bytes = Vec::with_capacity(72);
    bytes.extend_from_slice(FACTORY_RIGHT_NODE_DOMAIN);
    bytes.extend_from_slice(&(depth as u16).to_le_bytes());
    bytes.extend_from_slice(&left);
    bytes.extend_from_slice(&right);
    blake2b256(&bytes)
}

fn factory_key_bit(key: &Bytes32, depth: usize) -> bool {
    let byte = key[depth / 8];
    let mask = 0x80u8 >> (depth % 8);
    byte & mask != 0
}

fn factory_right_kind_byte(kind: FactoryRightKind) -> u8 {
    match kind {
        FactoryRightKind::Balance => 0,
        FactoryRightKind::ReserveClaim => 1,
        FactoryRightKind::Membership => 2,
        FactoryRightKind::ExitPath => 3,
        FactoryRightKind::SponsorBudgetClaim => 4,
    }
}

fn validate_classified_cell(cell: &ClassifiedCell) -> Result<()> {
    if cell.capacity < cell.occupied_capacity {
        return Err(MorphError::InvalidCellClassification);
    }

    let no_business_assets =
        cell.business_ckb == 0 && cell.xudt_amount == 0 && !cell.carries_registered_xudt;
    let shape_is_valid = match cell.class {
        CellClass::ChannelReserve => {
            no_business_assets
                && cell.uses_channel_vault_lock
                && cell.read_by_channel_script
                && cell.contributes_to_conservation
        }
        CellClass::BusinessCkb => {
            cell.business_ckb == cell.capacity - cell.occupied_capacity
                && cell.xudt_amount == 0
                && !cell.carries_registered_xudt
                && cell.uses_channel_vault_lock
                && cell.read_by_channel_script
                && cell.contributes_to_conservation
        }
        CellClass::BusinessXudt(_) => {
            cell.business_ckb == cell.capacity - cell.occupied_capacity
                && cell.carries_registered_xudt
                && cell.uses_channel_vault_lock
                && cell.read_by_channel_script
                && cell.contributes_to_conservation
        }
        CellClass::StateCarrier => {
            no_business_assets
                && !cell.uses_channel_vault_lock
                && cell.read_by_channel_script
                && cell.contributes_to_conservation
        }
        CellClass::Sponsor => {
            if cell.carries_registered_xudt || cell.uses_channel_vault_lock {
                return Err(MorphError::SponsorChangeContaminated);
            }
            no_business_assets && !cell.read_by_channel_script && !cell.contributes_to_conservation
        }
        CellClass::Unrelated => {
            if cell.read_by_channel_script || cell.contributes_to_conservation {
                return Err(MorphError::UnrelatedCellUsed);
            }
            no_business_assets && !cell.uses_channel_vault_lock
        }
    };
    if !shape_is_valid {
        return Err(MorphError::InvalidCellClassification);
    }
    Ok(())
}

fn fold_cells(
    cells: &[ClassifiedCell],
    registry: &AssetRegistry,
    input: bool,
    totals: &mut PartitionTotals,
) -> Result<()> {
    for cell in cells {
        match &cell.class {
            CellClass::ChannelReserve => {
                if input {
                    totals.reserve_in = totals
                        .reserve_in
                        .checked_add(cell.capacity)
                        .ok_or(MorphError::ReserveNotConserved)?;
                } else {
                    totals.reserve_out = totals
                        .reserve_out
                        .checked_add(cell.capacity)
                        .ok_or(MorphError::ReserveNotConserved)?;
                }
            }
            CellClass::BusinessCkb => {
                if input {
                    totals.business_ckb_in = totals
                        .business_ckb_in
                        .checked_add(cell.business_ckb)
                        .ok_or(MorphError::BusinessCkbNotConserved)?;
                } else {
                    totals.business_ckb_out = totals
                        .business_ckb_out
                        .checked_add(cell.business_ckb)
                        .ok_or(MorphError::BusinessCkbNotConserved)?;
                }
            }
            CellClass::BusinessXudt(asset_type) => {
                if !registry.contains(asset_type) {
                    return Err(MorphError::UnregisteredXudtType);
                }
                if input {
                    totals.business_ckb_in = totals
                        .business_ckb_in
                        .checked_add(cell.business_ckb)
                        .ok_or(MorphError::BusinessCkbNotConserved)?;
                } else {
                    totals.business_ckb_out = totals
                        .business_ckb_out
                        .checked_add(cell.business_ckb)
                        .ok_or(MorphError::BusinessCkbNotConserved)?;
                }
                let target = if input {
                    &mut totals.xudt_in
                } else {
                    &mut totals.xudt_out
                };
                let amount = target.entry(*asset_type).or_default();
                *amount = amount
                    .checked_add(cell.xudt_amount)
                    .ok_or(MorphError::XudtNotConserved)?;
            }
            CellClass::Sponsor => {
                if input {
                    totals.sponsor_in = totals
                        .sponsor_in
                        .checked_add(cell.capacity)
                        .ok_or(MorphError::SponsorFeeMismatch)?;
                } else {
                    totals.sponsor_out = totals
                        .sponsor_out
                        .checked_add(cell.capacity)
                        .ok_or(MorphError::SponsorFeeMismatch)?;
                }
            }
            CellClass::StateCarrier => {
                if input {
                    totals.state_carrier_in = totals
                        .state_carrier_in
                        .checked_add(cell.capacity)
                        .ok_or(MorphError::StateCarrierNotConserved)?;
                } else {
                    totals.state_carrier_out = totals
                        .state_carrier_out
                        .checked_add(cell.capacity)
                        .ok_or(MorphError::StateCarrierNotConserved)?;
                }
            }
            CellClass::Unrelated => {}
        }
    }
    Ok(())
}
