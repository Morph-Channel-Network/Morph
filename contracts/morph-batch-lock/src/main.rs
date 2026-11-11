#![cfg_attr(target_arch = "riscv64", no_std)]
#![cfg_attr(target_arch = "riscv64", no_main)]
#![forbid(unsafe_code)]

#[cfg(target_arch = "riscv64")]
use ckb_std::ckb_constants::Source;
#[cfg(target_arch = "riscv64")]
use ckb_std::ckb_types::prelude::*;
#[cfg(target_arch = "riscv64")]
use ckb_std::error::SysError;
#[cfg(target_arch = "riscv64")]
use ckb_std::high_level::{
    load_cell_capacity, load_cell_data, load_cell_lock_hash, load_cell_type_hash, load_input,
    load_script, load_witness_args,
};
#[cfg(target_arch = "riscv64")]
use ckb_std::{default_alloc, entry};
#[cfg(target_arch = "riscv64")]
use morph_script_common::{BYTE32_LEN, ConditionalBatchResolutionWitness, Result, ScriptError};

#[cfg(target_arch = "riscv64")]
const BATCH_ARGS_LEN: usize =
    morph_script_common::multi_asset_conditional::MULTI_ASSET_BATCH_ARGS_LEN;

#[cfg(target_arch = "riscv64")]
entry!(program_entry);
#[cfg(target_arch = "riscv64")]
default_alloc!();

#[cfg(target_arch = "riscv64")]
fn program_entry() -> i8 {
    match main() {
        Ok(()) => 0,
        Err(error) => error as i8,
    }
}

#[cfg(not(target_arch = "riscv64"))]
fn main() {}

#[cfg(target_arch = "riscv64")]
fn main() -> Result<()> {
    let script = load_script().map_err(|_| ScriptError::Encoding)?;
    let args = script.args().raw_data();
    if args.len() != BATCH_ARGS_LEN
        || args.as_ref()[..BYTE32_LEN].iter().all(|byte| *byte == 0)
        || args.as_ref()[BYTE32_LEN..2 * BYTE32_LEN]
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(ScriptError::WrongArgsLength);
    }
    let mut state_number_bytes = [0u8; 8];
    state_number_bytes.copy_from_slice(&args.as_ref()[2 * BYTE32_LEN..2 * BYTE32_LEN + 8]);
    if u64::from_le_bytes(state_number_bytes) == 0 {
        return Err(ScriptError::ConditionalBatchLockMismatch);
    }
    require_single_leading_group_input()?;

    let witness_args = load_witness_args(0, Source::GroupInput)
        .map_err(|_| ScriptError::ConditionalResolutionEncoding)?;
    let input_type = witness_args
        .input_type()
        .to_opt()
        .ok_or(ScriptError::ConditionalResolutionEncoding)?;
    let witness_raw = input_type.raw_data();
    let witness = ConditionalBatchResolutionWitness::parse(witness_raw.as_ref())?;
    let descriptor = witness.descriptor()?;
    if descriptor.commitment().as_slice() != &args.as_ref()[2 * BYTE32_LEN + 8..BATCH_ARGS_LEN] {
        return Err(ScriptError::ConditionalBatchLockMismatch);
    }

    let input_capacity =
        load_cell_capacity(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    if descriptor.checked_total_capacity()? != input_capacity {
        return Err(ScriptError::ConditionalValueMismatch);
    }
    let input = load_input(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let input_since: u64 = input.since().unpack();
    let asset = descriptor.asset()?;
    let input_type =
        load_cell_type_hash(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let input_data = load_cell_data(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let expected_type = if asset.kind == 1 {
        Some(asset.type_hash)
    } else {
        None
    };
    let valid_data = if asset.kind == 1 {
        input_data.as_slice() == descriptor.checked_total_amount()?.to_le_bytes()
    } else {
        input_data.is_empty()
    };
    if input_type != expected_type || !valid_data {
        return Err(ScriptError::ConditionalBatchLockMismatch);
    }
    let values = witness.resolved_values(input_since)?;
    verify_exact_output(0, descriptor.lock_hash(0), values[0], asset)?;
    verify_exact_output(1, descriptor.lock_hash(1), values[1], asset)?;
    verify_plain_fee_change()
}

#[cfg(target_arch = "riscv64")]
fn require_single_leading_group_input() -> Result<()> {
    // Payouts are matched transaction-wide. Reserve input zero for this Batch so
    // another Batch group cannot reuse them, even through a different code hash
    // or hash type. Independent fee inputs may follow the Batch input.
    let group_input = load_input(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let first_input = load_input(0, Source::Input).map_err(|_| ScriptError::Encoding)?;
    if group_input != first_input {
        return Err(ScriptError::WrongGroupShape);
    }
    match load_cell_capacity(1, Source::GroupInput) {
        Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => {}
        Err(_) => return Err(ScriptError::Encoding),
        Ok(_) => return Err(ScriptError::WrongGroupShape),
    }
    let mut ended = false;
    for index in 1..64 {
        match load_cell_capacity(index, Source::Input) {
            Ok(_) => {
                if load_cell_type_hash(index, Source::Input)
                    .map_err(|_| ScriptError::Encoding)?
                    .is_some()
                    || !load_cell_data(index, Source::Input)
                        .map_err(|_| ScriptError::Encoding)?
                        .is_empty()
                {
                    return Err(ScriptError::ConditionalBatchLockMismatch);
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
        return Err(ScriptError::WrongGroupShape);
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn verify_exact_output(
    index: usize,
    expected_lock: &[u8],
    expected: morph_script_common::ConditionalValue,
    asset: morph_script_common::multi_asset::MultiAssetId,
) -> Result<()> {
    let output_type = if asset.kind == 1 && expected.amount > 0 {
        Some(asset.type_hash)
    } else {
        None
    };
    let data = load_cell_data(index, Source::Output)
        .map_err(|_| ScriptError::ConditionalBatchOutputMismatch)?;
    let valid_data = if output_type.is_some() {
        data.as_slice() == expected.amount.to_le_bytes()
    } else {
        data.is_empty()
    };
    if load_cell_lock_hash(index, Source::Output)
        .map_err(|_| ScriptError::ConditionalBatchOutputMismatch)?
        .as_slice()
        != expected_lock
        || load_cell_capacity(index, Source::Output)
            .map_err(|_| ScriptError::ConditionalBatchOutputMismatch)?
            != expected.capacity
        || load_cell_type_hash(index, Source::Output)
            .map_err(|_| ScriptError::ConditionalBatchOutputMismatch)?
            != output_type
        || !valid_data
    {
        return Err(ScriptError::ConditionalBatchOutputMismatch);
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn verify_plain_fee_change() -> Result<()> {
    // Payouts are exactly outputs 0 and 1. Plain external fee change may use a
    // participant's own address; a second Batch cannot reuse these positions
    // because every Batch must independently be transaction input zero.
    let mut input_capacity = 0u64;
    let mut input_end = false;
    for index in 0..64 {
        match load_cell_capacity(index, Source::Input) {
            Ok(value) => {
                input_capacity = input_capacity
                    .checked_add(value)
                    .ok_or(ScriptError::ConditionalValueMismatch)?
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => {
                input_end = true;
                break;
            }
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    let mut output_capacity = 0u64;
    let mut output_end = false;
    for index in 0..64 {
        match load_cell_capacity(index, Source::Output) {
            Ok(value) => {
                output_capacity = output_capacity
                    .checked_add(value)
                    .ok_or(ScriptError::ConditionalValueMismatch)?;
                if index >= 2
                    && (load_cell_type_hash(index, Source::Output)
                        .map_err(|_| ScriptError::Encoding)?
                        .is_some()
                        || !load_cell_data(index, Source::Output)
                            .map_err(|_| ScriptError::Encoding)?
                            .is_empty())
                {
                    return Err(ScriptError::ConditionalBatchOutputMismatch);
                }
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => {
                output_end = true;
                break;
            }
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    if !input_end || !output_end {
        return Err(ScriptError::WrongGroupShape);
    }
    if output_capacity > input_capacity {
        return Err(ScriptError::ConditionalBatchOutputMismatch);
    }
    Ok(())
}
