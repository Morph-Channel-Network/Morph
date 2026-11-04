#![cfg_attr(target_arch = "riscv64", no_std)]
#![cfg_attr(target_arch = "riscv64", no_main)]
#![forbid(unsafe_code)]
#[cfg(target_arch = "riscv64")]
use ckb_std::{default_alloc, entry};
#[cfg(target_arch = "riscv64")]
entry!(program_entry);
#[cfg(target_arch = "riscv64")]
default_alloc!();
#[cfg(not(target_arch = "riscv64"))]
fn main() {}
#[cfg(target_arch = "riscv64")]
fn program_entry() -> i8 {
    match validate() {
        Ok(()) => 0,
        Err(error) => error as i8,
    }
}
#[cfg(target_arch = "riscv64")]
fn validate() -> morph_script_common::Result<()> {
    use morph_script_common::{ScriptError, factory_multi_asset_runtime as runtime};
    let script = ckb_std::high_level::load_script().map_err(|_| ScriptError::Encoding)?;
    let args = script.args().raw_data();
    if args.len() != 64 {
        return Err(ScriptError::WrongArgsLength);
    }
    let raw = match runtime::reduced_release_evidence()? {
        Some(raw) => raw,
        None => runtime::materialisation_evidence()?
            .ok_or(ScriptError::FactoryMultiAssetPartitionMismatch)?,
    };
    runtime::validate_vault_gate(&raw, &args[..32], &args[32..])
}
