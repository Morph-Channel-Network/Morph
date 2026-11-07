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
    require_single_plain_leading_group_input()?;

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
    let capacities = witness.resolved_capacities(input_since)?;
    verify_exact_plain_output(descriptor.lock_hash(0), capacities[0])?;
    verify_exact_plain_output(descriptor.lock_hash(1), capacities[1])
}

#[cfg(target_arch = "riscv64")]
fn require_single_plain_leading_group_input() -> Result<()> {
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
    let type_hash =
        load_cell_type_hash(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let data = load_cell_data(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    if type_hash.is_some() || !data.is_empty() {
        return Err(ScriptError::ConditionalBatchLockMismatch);
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn verify_exact_plain_output(expected_lock: &[u8], expected_capacity: u64) -> Result<()> {
    let mut matches = 0u8;
    let mut index = 0;
    loop {
        match load_cell_lock_hash(index, Source::Output) {
            Ok(lock_hash) => {
                if lock_hash.as_slice() == expected_lock {
                    matches = matches
                        .checked_add(1)
                        .ok_or(ScriptError::ConditionalBatchOutputMismatch)?;
                    if matches != 1
                        || load_cell_capacity(index, Source::Output)
                            .map_err(|_| ScriptError::Encoding)?
                            != expected_capacity
                        || load_cell_type_hash(index, Source::Output)
                            .map_err(|_| ScriptError::Encoding)?
                            .is_some()
                        || !load_cell_data(index, Source::Output)
                            .map_err(|_| ScriptError::Encoding)?
                            .is_empty()
                    {
                        return Err(ScriptError::ConditionalBatchOutputMismatch);
                    }
                }
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    if matches != 1 {
        return Err(ScriptError::ConditionalBatchOutputMismatch);
    }
    Ok(())
}
