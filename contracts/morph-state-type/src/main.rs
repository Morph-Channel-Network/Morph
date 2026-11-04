#![cfg_attr(target_arch = "riscv64", no_std)]
#![cfg_attr(target_arch = "riscv64", no_main)]
#![forbid(unsafe_code)]

#[cfg(target_arch = "riscv64")]
mod multi_asset;
#[cfg(target_arch = "riscv64")]
use ckb_std::ckb_constants::Source;
#[cfg(target_arch = "riscv64")]
use ckb_std::ckb_types::prelude::*;
#[cfg(target_arch = "riscv64")]
use ckb_std::error::SysError;
#[cfg(target_arch = "riscv64")]
use ckb_std::high_level::{
    QueryIter, load_cell_capacity, load_cell_data, load_cell_lock, load_cell_occupied_capacity,
    load_cell_type_hash, load_input, load_script, load_script_hash,
};
#[cfg(target_arch = "riscv64")]
use ckb_std::{default_alloc, entry};
#[cfg(target_arch = "riscv64")]
use morph_script_common::{Result, ScriptError, blake2b256};
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
    let raw_args = script.args().raw_data();
    let args = morph_script_common::multi_asset::MultiAssetStateTypeArgs::parse(&raw_args)?;
    let before = zero_or_one_group_cell_data(Source::GroupInput)?;
    let after = zero_or_one_group_cell_data(Source::GroupOutput)?;
    multi_asset::validate(
        args.funding_anchor(),
        args.finalise_since(),
        before.as_deref(),
        after.as_deref(),
        args.factory_origin(),
    )
}

#[cfg(target_arch = "riscv64")]
fn validate_group_output_capacity() -> Result<()> {
    let cap = load_cell_capacity(0, Source::GroupOutput).map_err(|_| ScriptError::Encoding)?;
    let occupied =
        load_cell_occupied_capacity(0, Source::GroupOutput).map_err(|_| ScriptError::Encoding)?;
    if cap < occupied {
        return Err(ScriptError::OutputBelowOccupiedCapacity);
    }

    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_anchor_derivation(expected_funding_anchor: &[u8]) -> Result<()> {
    let script_hash = load_script_hash().map_err(|_| ScriptError::Encoding)?;
    let output_index = QueryIter::new(load_cell_type_hash, Source::Output)
        .position(|type_hash| type_hash == Some(script_hash))
        .ok_or(ScriptError::FundingAnchorMismatch)? as u64;
    let input = load_input(0, Source::Input).map_err(|_| ScriptError::Encoding)?;
    let index = output_index.to_le_bytes();
    let derived = blake2b256(&[input.as_slice(), &index]);
    if derived.as_slice() != expected_funding_anchor {
        return Err(ScriptError::FundingAnchorMismatch);
    }
    let mut input_index = 1;
    loop {
        match load_input(input_index, Source::Input) {
            Ok(input) => {
                if blake2b256(&[input.as_slice(), &index]).as_slice() == expected_funding_anchor {
                    return Err(ScriptError::FundingAnchorMismatch);
                }
                input_index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_preserved_carrier_capacity() -> Result<()> {
    let input = load_cell_capacity(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let output = load_cell_capacity(0, Source::GroupOutput).map_err(|_| ScriptError::Encoding)?;
    if input != output {
        return Err(ScriptError::StateCarrierMismatch);
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_output_lock_preserved() -> Result<()> {
    let input_lock = load_cell_lock(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let output_lock = load_cell_lock(0, Source::GroupOutput).map_err(|_| ScriptError::Encoding)?;
    if input_lock != output_lock {
        return Err(ScriptError::StateTypeMismatch);
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_output_lock_args_bind_output_type(index: usize, source: Source) -> Result<()> {
    let type_hash = load_cell_type_hash(index, source)
        .map_err(|_| ScriptError::Encoding)?
        .ok_or(ScriptError::StateTypeMismatch)?;
    let lock = load_cell_lock(index, source).map_err(|_| ScriptError::Encoding)?;
    let lock_args = lock.args().raw_data();
    if lock_args.as_ref() != type_hash.as_slice() {
        return Err(ScriptError::StateTypeMismatch);
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn zero_or_one_group_cell_data(source: Source) -> Result<Option<alloc::vec::Vec<u8>>> {
    let data = match load_cell_data(0, source) {
        Ok(data) => data,
        Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => return Ok(None),
        Err(_) => return Err(ScriptError::WrongGroupShape),
    };
    match load_cell_data(1, source) {
        Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => Ok(Some(data)),
        Err(_) => Err(ScriptError::Encoding),
        Ok(_) => Err(ScriptError::WrongGroupShape),
    }
}
