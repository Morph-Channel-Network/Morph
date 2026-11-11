//! Complete cooperative-close checks shared by StateType and every Vault lock.
use crate::multi_asset::MultiAssetStateHeader;
use crate::multi_asset_close::{MULTI_ASSET_CLOSE_MAGIC, MultiAssetCloseWitness};
use crate::multi_asset_runtime::{
    MULTI_ASSET_MAX_TRANSACTION_CELLS, verify_multi_asset_settlement_outputs,
    verify_multi_asset_vault_set,
};
use crate::{Result, ScriptError};
use alloc::vec::Vec;
use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::prelude::*;
use ckb_std::high_level::{
    load_cell_capacity, load_cell_data, load_cell_lock, load_cell_type, load_cell_type_hash,
    load_input, load_input_out_point, load_transaction, load_tx_hash, load_witness_args,
};

pub fn close_evidence(index: usize, source: Source) -> Result<Option<Vec<u8>>> {
    let witness =
        load_witness_args(index, source).map_err(|_| ScriptError::SettlementWitnessMissing)?;
    Ok(witness.output_type().to_opt().and_then(|data| {
        let raw = data.raw_data();
        raw.starts_with(MULTI_ASSET_CLOSE_MAGIC)
            .then(|| raw.to_vec())
    }))
}

pub fn verify_close(raw: &[u8]) -> Result<()> {
    let frame = MultiAssetCloseWitness::parse(raw)?;
    let evidence = frame.evidence();
    let tx = load_transaction().map_err(|_| ScriptError::Encoding)?;
    let inputs = tx.raw().inputs().len();
    let outputs = tx.raw().outputs().len();
    let count = evidence.manifest().count();
    // Match the existing scanners: an end-of-input/output sentinel must fit.
    if inputs < 1 + count
        || inputs >= MULTI_ASSET_MAX_TRANSACTION_CELLS
        || outputs >= MULTI_ASSET_MAX_TRANSACTION_CELLS
        || tx.raw().cell_deps().len() > 64
        || tx.raw().header_deps().len() > 64
        || load_input(0, Source::Input)
            .map_err(|_| ScriptError::Encoding)?
            .since()
            .unpack()
            != 0u64
        || load_tx_hash().map_err(|_| ScriptError::Encoding)? != frame.transaction_hash()
    {
        return Err(ScriptError::MultiAssetCloseMismatch);
    }
    let source_raw = load_cell_data(0, Source::Input).map_err(|_| ScriptError::Encoding)?;
    let source = MultiAssetStateHeader::parse(&source_raw)?;
    frame.validate_source(&source)?;
    let state_type = load_cell_type(0, Source::Input)
        .map_err(|_| ScriptError::Encoding)?
        .ok_or(ScriptError::StateTypeMismatch)?;
    if state_type.as_slice() != evidence.scripts().script(4)?
        || load_cell_lock(0, Source::Input)
            .map_err(|_| ScriptError::Encoding)?
            .as_slice()
            != evidence.scripts().script(5)?
    {
        return Err(ScriptError::StateTypeMismatch);
    }
    let positions = verify_multi_asset_vault_set(evidence, Source::Input, true)?;
    for (index, position) in positions.iter().enumerate().take(count) {
        if *position != index + 1
            || load_input_out_point(index + 1, Source::Input)
                .map_err(|_| ScriptError::Encoding)?
                .as_slice()
                != evidence.outpoint(index)?
        {
            return Err(ScriptError::VaultOutPointMismatch);
        }
    }
    // No unrelated typed custody or second channel is admitted as fee funding.
    for index in count + 1..inputs {
        require_plain(index, Source::Input)?;
    }
    let state_hash = state_type.calc_script_hash();
    for index in 0..outputs {
        if load_cell_type_hash(index, Source::Output)
            .map_err(|_| ScriptError::Encoding)?
            .as_ref()
            .is_some_and(|hash| hash.as_slice() == state_hash.as_slice())
        {
            return Err(ScriptError::WrongGroupShape);
        }
    }
    verify_multi_asset_settlement_outputs(evidence, 0, Source::Input, frame.target())?;
    let descriptor = evidence.descriptor();
    let conditional = descriptor.conditional()?;
    let mut terminal_outputs = 1usize; // Entire State carrier refund.
    for index in 0..descriptor.count() {
        let payout = descriptor.entry(index)?;
        if conditional
            .map(|value| value.index_of(payout.asset))
            .transpose()?
            .flatten()
            .is_some()
        {
            terminal_outputs += 1;
        } else {
            for allocation in payout.allocations {
                terminal_outputs += usize::from(allocation.capacity()? != 0);
            }
        }
    }
    for index in terminal_outputs..outputs {
        require_plain(index, Source::Output)?;
    }
    let total = |source, count| -> Result<u64> {
        let mut sum = 0u64;
        for index in 0..count {
            sum = sum
                .checked_add(load_cell_capacity(index, source).map_err(|_| ScriptError::Encoding)?)
                .ok_or(ScriptError::CapacityUnderflow)?;
        }
        Ok(sum)
    };
    if total(Source::Input, inputs)? < total(Source::Output, outputs)? {
        return Err(ScriptError::CapacityUnderflow);
    }
    Ok(())
}

fn require_plain(index: usize, source: Source) -> Result<()> {
    if load_cell_type_hash(index, source)
        .map_err(|_| ScriptError::Encoding)?
        .is_some()
        || !load_cell_data(index, source)
            .map_err(|_| ScriptError::Encoding)?
            .is_empty()
    {
        return Err(ScriptError::MultiAssetCloseMismatch);
    }
    Ok(())
}
