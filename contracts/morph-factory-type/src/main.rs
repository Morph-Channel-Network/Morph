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
    match morph_script_common::factory_multi_asset_runtime::validate_type() {
        Ok(()) => 0,
        Err(error) => error as i8,
    }
}
