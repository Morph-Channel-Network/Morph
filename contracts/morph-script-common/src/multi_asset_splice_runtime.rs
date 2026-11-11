//! Complete, jointly authorised re-anchor execution. Every authority checks the
//! exact transaction identity, old provenance and canonical new custody.
use crate::multi_asset::{MultiAssetId, MultiAssetStateHeader, MultiAssetVaultArgs};
use crate::multi_asset_runtime::{MULTI_ASSET_MAX_TRANSACTION_CELLS, verify_value};
use crate::multi_asset_splice::{
    MULTI_ASSET_SPLICE_MAGIC, MULTI_ASSET_SPLICE_MAX_FLOWS, MultiAssetSpliceWitness,
};
use crate::{Result, ScriptError, read_u64, read_u128};
use alloc::vec::Vec;
use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::prelude::*;
use ckb_std::high_level::{
    load_cell_capacity, load_cell_data, load_cell_lock, load_cell_lock_hash, load_cell_type,
    load_cell_type_hash, load_input, load_input_out_point, load_transaction, load_tx_hash,
    load_witness_args,
};

pub fn splice_evidence(index: usize, source: Source) -> Result<Option<Vec<u8>>> {
    let witness =
        load_witness_args(index, source).map_err(|_| ScriptError::SettlementWitnessMissing)?;
    let Some(data) = witness.output_type().to_opt() else {
        return Ok(None);
    };
    let raw = data.raw_data();
    Ok(raw
        .starts_with(MULTI_ASSET_SPLICE_MAGIC)
        .then(|| raw.to_vec()))
}

/// New State and Vault groups bind the same immutable old Type, global frame
/// and exact body. The old Type must retire, forcing its complete verifier.
/// New State creation signatures are still independently checked by its Type.
pub fn verify_splice_gate(raw: &[u8]) -> Result<()> {
    let proof = MultiAssetSpliceWitness::parse(raw)?;
    let tx = load_transaction().map_err(|_| ScriptError::Encoding)?;
    let inputs = tx.raw().inputs().len();
    let outputs = tx.raw().outputs().len();
    if inputs < 1 + proof.old_manifest().count()
        || outputs < 1 + proof.new_evidence().manifest().count()
        || inputs > MULTI_ASSET_MAX_TRANSACTION_CELLS
        || outputs > MULTI_ASSET_MAX_TRANSACTION_CELLS
        || tx.raw().cell_deps().len() > 64
        || tx.raw().header_deps().len() > 64
        || load_tx_hash()
            .map_err(|_| ScriptError::Encoding)?
            .as_slice()
            != proof.header().transaction_hash()
    {
        return Err(ScriptError::MultiAssetSpliceMismatch);
    }
    let input = load_input(0, Source::Input).map_err(|_| ScriptError::Encoding)?;
    if input.since().unpack() != 0u64
        || input.previous_output().as_slice() != proof.header().old_state_outpoint()
    {
        return Err(ScriptError::MultiAssetSpliceMismatch);
    }
    let data = load_cell_data(0, Source::Input).map_err(|_| ScriptError::Encoding)?;
    let old = MultiAssetStateHeader::parse(&data)?;
    proof.validate_old_context(&old)?;
    verify_authority(&proof, &old)?;
    let old_type = load_cell_type_hash(0, Source::Input)
        .map_err(|_| ScriptError::Encoding)?
        .ok_or(ScriptError::StateTypeMismatch)?;
    for i in 0..outputs {
        if load_cell_type_hash(i, Source::Output).map_err(|_| ScriptError::Encoding)?
            == Some(old_type)
        {
            return Err(ScriptError::WrongGroupShape);
        }
    }
    if load_cell_data(0, Source::Output)
        .map_err(|_| ScriptError::Encoding)?
        .as_slice()
        != proof.new_header().as_bytes()
    {
        return Err(ScriptError::MultiAssetSpliceMismatch);
    }
    Ok(())
}

pub fn verify_splice(raw: &[u8]) -> Result<()> {
    let proof = MultiAssetSpliceWitness::parse(raw)?;
    let tx = load_transaction().map_err(|_| ScriptError::Encoding)?;
    let inputs = tx.raw().inputs().len();
    let outputs = tx.raw().outputs().len();
    let old_count = proof.old_manifest().count();
    let new_count = proof.new_evidence().manifest().count();
    if inputs < 1 + old_count
        || outputs < 1 + new_count
        || inputs > MULTI_ASSET_MAX_TRANSACTION_CELLS
        || outputs > MULTI_ASSET_MAX_TRANSACTION_CELLS
        || tx.raw().cell_deps().len() > 64
        || tx.raw().header_deps().len() > 64
    {
        return Err(ScriptError::MultiAssetSpliceMismatch);
    }
    let state_input = load_input(0, Source::Input).map_err(|_| ScriptError::Encoding)?;
    if state_input.since().unpack() != 0u64
        || state_input.previous_output().as_slice() != proof.header().old_state_outpoint()
        || load_tx_hash()
            .map_err(|_| ScriptError::Encoding)?
            .as_slice()
            != proof.header().transaction_hash()
    {
        return Err(ScriptError::MultiAssetSpliceMismatch);
    }
    let old_data = load_cell_data(0, Source::Input).map_err(|_| ScriptError::Encoding)?;
    let old = MultiAssetStateHeader::parse(&old_data)?;
    proof.validate_old_header(&old)?;
    if load_cell_data(0, Source::Output)
        .map_err(|_| ScriptError::Encoding)?
        .as_slice()
        != proof.new_header().as_bytes()
        || load_cell_capacity(0, Source::Input).map_err(|_| ScriptError::Encoding)?
            != load_cell_capacity(0, Source::Output).map_err(|_| ScriptError::Encoding)?
    {
        return Err(ScriptError::StateCarrierMismatch);
    }
    verify_authority(&proof, &old)?;
    let old_lock = proof.old_manifest().entry(0)?.lock_hash;
    let new_lock = proof.new_evidence().manifest().entry(0)?.lock_hash;
    for index in 0..old_count {
        let entry = proof.old_manifest().entry(index)?;
        if entry.lock_hash != old_lock
            || load_input_out_point(index + 1, Source::Input)
                .map_err(|_| ScriptError::Encoding)?
                .as_slice()
                != &proof.old_outpoints()[index * 36..(index + 1) * 36]
        {
            return Err(ScriptError::VaultOutPointMismatch);
        }
        verify_value(
            index + 1,
            Source::Input,
            &entry.lock_hash,
            entry.asset,
            entry.allocation,
        )?;
    }
    for index in old_count + 1..inputs {
        if load_cell_lock_hash(index, Source::Input).map_err(|_| ScriptError::Encoding)? == old_lock
        {
            return Err(ScriptError::MultiAssetVaultSetIncomplete);
        }
    }
    for index in 0..new_count {
        let entry = proof.new_evidence().manifest().entry(index)?;
        verify_value(
            index + 1,
            Source::Output,
            &entry.lock_hash,
            entry.asset,
            entry.allocation,
        )?;
    }
    let mut position = 1 + new_count;
    for index in 0..proof.flows().count() {
        let flow = proof.flows().entry(index)?;
        if flow.withdrawal.capacity()? == 0 {
            continue;
        }
        let asset = if flow.withdrawal.amount == 0 {
            MultiAssetId::CKB
        } else {
            flow.asset
        };
        verify_value(
            position,
            Source::Output,
            proof.header().withdrawal_lock_hash(),
            asset,
            flow.withdrawal,
        )?;
        position += 1;
    }
    let old_type = load_cell_type_hash(0, Source::Input)
        .map_err(|_| ScriptError::Encoding)?
        .ok_or(ScriptError::StateTypeMismatch)?;
    let new_type = load_cell_type_hash(0, Source::Output)
        .map_err(|_| ScriptError::Encoding)?
        .ok_or(ScriptError::StateTypeMismatch)?;
    for index in 0..outputs {
        let lock = load_cell_lock_hash(index, Source::Output).map_err(|_| ScriptError::Encoding)?;
        let kind = load_cell_type_hash(index, Source::Output).map_err(|_| ScriptError::Encoding)?;
        if lock == old_lock
            || (lock == new_lock && !(1..=new_count).contains(&index))
            || kind == Some(old_type)
            || (kind == Some(new_type) && index != 0)
        {
            return Err(ScriptError::MultiAssetSpliceMismatch);
        }
    }
    verify_token_conservation(&proof, inputs, outputs)
}

fn verify_authority(proof: &MultiAssetSpliceWitness, old: &MultiAssetStateHeader) -> Result<()> {
    let old_type = load_cell_type(0, Source::Input)
        .map_err(|_| ScriptError::Encoding)?
        .ok_or(ScriptError::StateTypeMismatch)?;
    crate::multi_asset::require_immutable_authority_script(old_type.as_slice())?;
    let old_state_lock = load_cell_lock(0, Source::Input).map_err(|_| ScriptError::Encoding)?;
    let old_vault = load_cell_lock(1, Source::Input).map_err(|_| ScriptError::Encoding)?;
    let new_type = load_cell_type(0, Source::Output)
        .map_err(|_| ScriptError::Encoding)?
        .ok_or(ScriptError::StateTypeMismatch)?;
    let new_state_lock = load_cell_lock(0, Source::Output).map_err(|_| ScriptError::Encoding)?;
    let scripts = proof.new_evidence().scripts();
    let new_vault = scripts.script(3)?;
    let old_vault_args = old_vault.args().raw_data();
    let a = MultiAssetVaultArgs::parse(&old_vault_args)?;
    let b = MultiAssetVaultArgs::parse(&new_vault[53..])?;
    let old_args = old_type.args().raw_data();
    let new_args = new_type.args().raw_data();
    if !matches!(old_type.as_slice().len(), 93 | 125)
        || old_type.as_slice().len() != new_type.as_slice().len()
        || old_args[32..old_args.len() - 8] != new_args[32..new_args.len() - 8]
        || old_state_lock.as_slice().len() != 85
        || old_type.as_slice()[..49] != new_type.as_slice()[..49]
        || old_state_lock.as_slice()[..49] != new_state_lock.as_slice()[..49]
        || old_vault.as_slice()[..49] != new_vault[..49]
        || new_type.as_slice() != scripts.script(4)?
        || new_state_lock.as_slice() != scripts.script(5)?
        || old_type.calc_script_hash() == new_type.calc_script_hash()
        || &old_args[..32] != old.funding_anchor()
        || read_u64(&old_args, old_args.len() - 8) != a.finalise_since()
        || &new_args[..32] != proof.new_header().funding_anchor()
        || read_u64(&new_args, new_args.len() - 8) != a.finalise_since()
        || a.finalise_since() != b.finalise_since()
        || a.funding_anchor() != old.funding_anchor()
        || a.state_type_hash() != old_type.calc_script_hash().as_slice()
        || a.state_lock_hash() != old_state_lock.calc_script_hash().as_slice()
        || old_state_lock.args().raw_data().as_ref() != old_type.calc_script_hash().as_slice()
    {
        return Err(ScriptError::MultiAssetSpliceMismatch);
    }
    Ok(())
}

fn verify_token_conservation(
    proof: &MultiAssetSpliceWitness,
    inputs: usize,
    outputs: usize,
) -> Result<()> {
    let mut before = [0u128; MULTI_ASSET_SPLICE_MAX_FLOWS];
    let mut after = before;
    for (source, count, totals) in [
        (Source::Input, inputs, &mut before),
        (Source::Output, outputs, &mut after),
    ] {
        for index in 0..count {
            let Some(hash) =
                load_cell_type_hash(index, source).map_err(|_| ScriptError::Encoding)?
            else {
                continue;
            };
            for (flow_index, total) in totals.iter_mut().enumerate().take(proof.flows().count()) {
                let asset = proof.flows().entry(flow_index)?.asset;
                if asset.kind != 1 || asset.type_hash != hash {
                    continue;
                }
                let data = load_cell_data(index, source).map_err(|_| ScriptError::Encoding)?;
                if data.len() != 16 {
                    return Err(ScriptError::MultiAssetConservationMismatch);
                }
                *total = total
                    .checked_add(read_u128(&data, 0))
                    .ok_or(ScriptError::MultiAssetConservationMismatch)?;
                break;
            }
        }
    }
    if before != after {
        return Err(ScriptError::MultiAssetConservationMismatch);
    }
    Ok(())
}
