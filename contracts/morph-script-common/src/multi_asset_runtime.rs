//! CKB syscall verification for the versioned multi-asset profile.

use alloc::vec::Vec;
use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::prelude::*;
use ckb_std::error::SysError;
use ckb_std::high_level::{
    load_cell_capacity, load_cell_data, load_cell_lock_hash, load_cell_occupied_capacity,
    load_cell_type_hash, load_input_out_point, load_witness_args,
};

use crate::multi_asset::{
    MULTI_ASSET_MAX_VAULTS, MultiAssetAllocation, MultiAssetId, MultiAssetWitness,
};
use crate::{Result, ScriptError, read_u128};

pub const MULTI_ASSET_MAX_TRANSACTION_CELLS: usize = 64;

pub fn multi_asset_evidence(index: usize, source: Source) -> Result<Vec<u8>> {
    let witness =
        load_witness_args(index, source).map_err(|_| ScriptError::SettlementWitnessMissing)?;
    let evidence = witness
        .output_type()
        .to_opt()
        .ok_or(ScriptError::SettlementWitnessMissing)?;
    let raw = evidence.raw_data();
    if raw.starts_with(crate::multi_asset_splice::MULTI_ASSET_SPLICE_MAGIC) {
        let splice = crate::multi_asset_splice::MultiAssetSpliceWitness::parse(&raw)?;
        Ok(splice.new_evidence().as_bytes().to_vec())
    } else {
        Ok(raw.to_vec())
    }
}

fn actual_asset(index: usize, source: Source) -> Result<MultiAssetId> {
    Ok(
        match load_cell_type_hash(index, source).map_err(|_| ScriptError::Encoding)? {
            Some(hash) => MultiAssetId::xudt(hash),
            None => MultiAssetId::CKB,
        },
    )
}

pub(crate) fn verify_value(
    index: usize,
    source: Source,
    lock: &[u8],
    asset: MultiAssetId,
    value: MultiAssetAllocation,
) -> Result<()> {
    if load_cell_lock_hash(index, source)
        .map_err(|_| ScriptError::Encoding)?
        .as_slice()
        != lock
        || load_cell_capacity(index, source).map_err(|_| ScriptError::Encoding)?
            != value.capacity()?
        || actual_asset(index, source)? != asset
        || load_cell_occupied_capacity(index, source).map_err(|_| ScriptError::Encoding)?
            > value.reserve
    {
        return Err(ScriptError::MultiAssetCapacityMismatch);
    }
    let data = load_cell_data(index, source).map_err(|_| ScriptError::Encoding)?;
    if asset.kind == 0 {
        if !data.is_empty() || value.amount != 0 {
            return Err(ScriptError::MultiAssetConservationMismatch);
        }
    } else if data.len() != 16 || read_u128(&data, 0) != value.amount {
        return Err(ScriptError::MultiAssetConservationMismatch);
    }
    Ok(())
}

pub fn verify_multi_asset_vault_at(
    evidence: &MultiAssetWitness,
    entry_index: usize,
    cell_index: usize,
    source: Source,
) -> Result<()> {
    let entry = evidence.manifest().entry(entry_index)?;
    verify_value(
        cell_index,
        source,
        &entry.lock_hash,
        entry.asset,
        entry.allocation,
    )
}

/// Finds every committed asset exactly once and rejects extra Vault Cells.
/// Input verification also checks the exact OutPoint, not just content.
pub fn verify_multi_asset_vault_set(
    evidence: &MultiAssetWitness,
    source: Source,
    exact_inputs: bool,
) -> Result<[usize; MULTI_ASSET_MAX_VAULTS]> {
    verify_vault_manifest_set(
        evidence.manifest(),
        exact_inputs.then_some(evidence.outpoints()),
        source,
    )
}

pub fn verify_vault_manifest_set(
    manifest: &crate::multi_asset::MultiAssetVaultManifest,
    expected_points: Option<&[u8]>,
    source: Source,
) -> Result<[usize; MULTI_ASSET_MAX_VAULTS]> {
    if expected_points.is_some_and(|points| points.len() != manifest.count() * 36) {
        return Err(ScriptError::VaultOutPointMismatch);
    }
    let mut found = [usize::MAX; MULTI_ASSET_MAX_VAULTS];
    let expected_lock = manifest.entry(0)?.lock_hash;
    let mut ended = false;
    for index in 0..=MULTI_ASSET_MAX_TRANSACTION_CELLS {
        match load_cell_capacity(index, source) {
            Ok(_) => {
                if index == MULTI_ASSET_MAX_TRANSACTION_CELLS {
                    return Err(ScriptError::MultiAssetVaultSetIncomplete);
                }
                if load_cell_lock_hash(index, source).map_err(|_| ScriptError::Encoding)?
                    != expected_lock
                {
                    continue;
                }
                let asset = actual_asset(index, source)?;
                let mut matched = false;
                for (entry_index, position) in found.iter_mut().enumerate().take(manifest.count()) {
                    if manifest.entry(entry_index)?.asset != asset {
                        continue;
                    }
                    if *position != usize::MAX {
                        return Err(ScriptError::MultiAssetVaultSetIncomplete);
                    }
                    let entry = manifest.entry(entry_index)?;
                    verify_value(
                        index,
                        source,
                        &entry.lock_hash,
                        entry.asset,
                        entry.allocation,
                    )?;
                    if expected_points.is_some()
                        && load_input_out_point(index, source)
                            .map_err(|_| ScriptError::Encoding)?
                            .as_slice()
                            != &expected_points.ok_or(ScriptError::VaultOutPointMismatch)?
                                [entry_index * 36..(entry_index + 1) * 36]
                    {
                        return Err(ScriptError::VaultOutPointMismatch);
                    }
                    *position = index;
                    matched = true;
                    break;
                }
                if !matched {
                    return Err(ScriptError::MultiAssetVaultSetIncomplete);
                }
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => {
                ended = true;
                break;
            }
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    if !ended || found[..manifest.count()].contains(&usize::MAX) {
        return Err(ScriptError::MultiAssetVaultSetIncomplete);
    }
    Ok(found)
}

/// Payouts occupy canonical output positions in asset/participant order;
/// zero-capacity empty allocations are omitted. The carrier refund follows.
pub fn verify_multi_asset_settlement_outputs(
    evidence: &MultiAssetWitness,
    state_input_index: usize,
    state_source: Source,
) -> Result<()> {
    let descriptor = evidence.descriptor();
    let mut output_index = 0;
    for i in 0..descriptor.count() {
        let payout = descriptor.entry(i)?;
        for participant in 0..2 {
            let allocation = payout.allocations[participant];
            if allocation.capacity()? == 0 {
                continue;
            }
            let asset = if allocation.amount == 0 {
                MultiAssetId::CKB
            } else {
                payout.asset
            };
            verify_value(
                output_index,
                Source::Output,
                descriptor.lock_hash(participant)?,
                asset,
                allocation,
            )?;
            output_index += 1;
        }
    }
    let carrier_capacity =
        load_cell_capacity(state_input_index, state_source).map_err(|_| ScriptError::Encoding)?;
    verify_value(
        output_index,
        Source::Output,
        descriptor.carrier_refund_lock(),
        MultiAssetId::CKB,
        MultiAssetAllocation {
            reserve: carrier_capacity,
            business_ckb: 0,
            amount: 0,
        },
    )?;
    output_index += 1;
    let vault_lock = evidence.manifest().entry(0)?.lock_hash;
    let mut ended = false;
    for index in output_index..MULTI_ASSET_MAX_TRANSACTION_CELLS {
        match load_cell_capacity(index, Source::Output) {
            Ok(_) => {
                let lock = load_cell_lock_hash(index, Source::Output)
                    .map_err(|_| ScriptError::Encoding)?;
                // Canonical positions already account for every channel
                // allocation and the complete carrier refund. Plain fee
                // change may share a recipient address without being counted
                // a second time toward those lanes.
                if lock == vault_lock {
                    return Err(ScriptError::MultiAssetConservationMismatch);
                }
                let asset = actual_asset(index, Source::Output)?;
                if asset.kind == 1 {
                    for i in 0..evidence.manifest().count() {
                        if evidence.manifest().entry(i)?.asset == asset {
                            return Err(ScriptError::MultiAssetConservationMismatch);
                        }
                    }
                }
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => {
                ended = true;
                break;
            }
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    if !ended {
        return Err(ScriptError::MultiAssetEncoding);
    }
    Ok(())
}
