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
    load_cell_capacity, load_cell_data, load_cell_lock_hash, load_cell_type_hash,
    load_input_out_point, load_script, load_script_hash, load_witness_args,
};
#[cfg(target_arch = "riscv64")]
use ckb_std::{default_alloc, entry};
#[cfg(target_arch = "riscv64")]
use morph_script_common::{
    BILATERAL_CKB_DESCRIPTOR_LEN, BILATERAL_CKB_XUDT_DESCRIPTOR_LEN, BYTE32_LEN,
    BilateralCkbSettlementDescriptor, BilateralCkbXudtSettlementDescriptor,
    FactoryLocalExitWitness, FactoryReducedExitWitness, FactoryReducedSpliceWitness,
    FactorySpliceWitness, FactoryStateHeader, FactoryVaultDelta, FactoryVaultDeltas,
    FactoryVaultDescriptor, Result, ScriptError, UNBOUND_VAULT_OUTPOINT_COMMITMENT,
    VAULT_ASSET_KIND_CKB, VAULT_ASSET_KIND_XUDT, WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT,
    WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_EXIT, WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_SPLICE,
    WITNESS_ENVELOPE_KIND_FACTORY_SPLICE, WitnessEnvelope, read_u128, vault_cell_commitment,
    vault_outpoint_commitment, verify_factory_reduced_exit_update,
    verify_factory_reduced_splice_update, verify_factory_splice_update,
    verify_factory_state_signatures,
};

#[cfg(target_arch = "riscv64")]
entry!(program_entry);
#[cfg(target_arch = "riscv64")]
default_alloc!();

#[cfg(target_arch = "riscv64")]
fn program_entry() -> i8 {
    match main() {
        Ok(()) => 0,
        Err(err) => err as i8,
    }
}

#[cfg(not(target_arch = "riscv64"))]
fn main() {}

#[cfg(target_arch = "riscv64")]
fn main() -> Result<()> {
    let script = load_script().map_err(|_| ScriptError::Encoding)?;
    let args = script.args().raw_data();
    if args.len() != 2 * BYTE32_LEN {
        return Err(ScriptError::WrongArgsLength);
    }
    let factory_id = &args.as_ref()[..BYTE32_LEN];
    let factory_type_hash = &args.as_ref()[BYTE32_LEN..2 * BYTE32_LEN];

    if morph_script_common::factory_multi_asset_runtime::has_multi_asset_factory_source(
        factory_type_hash,
    )? {
        let raw = morph_script_common::factory_multi_asset_runtime::materialisation_evidence()?
            .ok_or(ScriptError::FactoryMultiAssetPartitionMismatch)?;
        return morph_script_common::factory_multi_asset_runtime::validate_vault_gate(
            &raw,
            factory_id,
            factory_type_hash,
        );
    }

    let witness_args = load_witness_args(0, Source::GroupInput)
        .map_err(|_| ScriptError::ParticipantWitnessMissing)?;
    let input_type = witness_args
        .input_type()
        .to_opt()
        .ok_or(ScriptError::ParticipantWitnessMissing)?;
    let input_type_data = input_type.raw_data();
    let envelope = WitnessEnvelope::parse(input_type_data.as_ref())?;
    let input_type_raw = envelope.body();

    let old_header_data =
        find_unique_factory_state_data(Source::Input, factory_id, factory_type_hash)?;
    let new_header_data =
        find_unique_factory_state_data(Source::Output, factory_id, factory_type_hash)?;
    let old_header = FactoryStateHeader::parse(&old_header_data)?;
    let new_header = FactoryStateHeader::parse(&new_header_data)?;
    old_header.validate_profile()?;
    new_header.validate_profile()?;
    if new_header.update_number() <= old_header.update_number() {
        return Err(ScriptError::NonMonotonicStateNumber);
    }
    validate_factory_vault_materialisation_roots(&old_header, &new_header)?;
    match envelope.kind() {
        WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT => {
            let witness = FactoryLocalExitWitness::parse(input_type_raw)?;
            if new_header.non_interference_digest() != witness.exit_digest().as_slice() {
                return Err(ScriptError::FactoryLocalExitMismatch);
            }
            let factory_signature = witness.factory_signature()?;
            verify_factory_state_signatures(&new_header, &factory_signature)?;
            let child_release = validate_child_vault(
                witness.vault_output_index(),
                witness.vault_lock_hash(),
                witness.settlement_descriptor(),
            )?;
            validate_factory_reduced_exit_reserve_conservation(&child_release)?;
        }
        WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_EXIT => {
            let witness = FactoryReducedExitWitness::parse(input_type_raw)?;
            let digest = witness.non_interference_digest(&old_header, &new_header)?;
            if new_header.non_interference_digest() != digest.as_slice() {
                return Err(ScriptError::FactoryReducedProofMismatch);
            }
            verify_factory_reduced_exit_update(&old_header, &new_header, &witness)?;
            let child_release = validate_child_vault(
                witness.vault_output_index(),
                witness.vault_lock_hash(),
                witness.settlement_descriptor(),
            )?;
            match child_release.xudt_type_hash {
                Some(_) => {
                    if child_release.xudt_amount != witness.release_quantity() {
                        return Err(ScriptError::FactoryReserveMismatch);
                    }
                }
                None => {
                    if child_release.capacity as u128 != witness.release_quantity() {
                        return Err(ScriptError::FactoryReserveMismatch);
                    }
                }
            }
            validate_factory_reduced_exit_reserve_conservation(&child_release)?;
        }
        WITNESS_ENVELOPE_KIND_FACTORY_SPLICE => {
            let witness = FactorySpliceWitness::parse(input_type_raw)?;
            verify_factory_splice_update(&old_header, &new_header, &witness)?;
            let header = witness.header()?;
            let old_vault = witness.old_vault()?;
            let new_vault = witness.new_vault()?;
            let deltas = witness.deltas()?;
            validate_factory_splice_vault_deltas(
                &old_vault,
                &new_vault,
                &deltas,
                header.withdrawal_lock_hash(),
            )?;
        }
        WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_SPLICE => {
            let witness = FactoryReducedSpliceWitness::parse(input_type_raw)?;
            verify_factory_reduced_splice_update(&old_header, &new_header, &witness)?;
            let header = witness.header()?;
            let old_vault = witness.old_vault()?;
            let new_vault = witness.new_vault()?;
            let deltas = witness.deltas()?;
            validate_factory_splice_vault_deltas(
                &old_vault,
                &new_vault,
                &deltas,
                header.withdrawal_lock_hash(),
            )?;
        }
        _ => return Err(ScriptError::WitnessEnvelopeEncoding),
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_factory_vault_materialisation_roots(
    old_header: &FactoryStateHeader,
    new_header: &FactoryStateHeader,
) -> Result<()> {
    if old_header.vault_outpoint_commitment() == UNBOUND_VAULT_OUTPOINT_COMMITMENT
        || new_header.vault_outpoint_commitment() != UNBOUND_VAULT_OUTPOINT_COMMITMENT
    {
        return Err(ScriptError::VaultActivationInvalid);
    }
    let current_lock_hash = load_script_hash().map_err(|_| ScriptError::Encoding)?;

    let input_capacity = single_group_capacity(Source::GroupInput)?;
    let input_type =
        load_cell_type_hash(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let input_data = load_cell_data(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let input_commitment = vault_cell_commitment(
        current_lock_hash.as_slice(),
        input_capacity,
        input_type.as_ref().map(|hash| hash.as_slice()),
        input_data.as_slice(),
    );
    if input_commitment.as_slice() != old_header.vault_materialisation_root() {
        return Err(ScriptError::FactoryReserveMismatch);
    }
    let input_outpoint =
        load_input_out_point(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let input_output_index: u32 = input_outpoint.index().unpack();
    let input_locator =
        vault_outpoint_commitment(input_outpoint.tx_hash().as_slice(), input_output_index);
    if input_locator.as_slice() != old_header.vault_outpoint_commitment() {
        return Err(ScriptError::VaultOutPointMismatch);
    }

    let output_index = single_output_index_by_lock_hash(current_lock_hash.as_slice())?;
    let output_capacity =
        load_cell_capacity(output_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    let output_type =
        load_cell_type_hash(output_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    let output_data =
        load_cell_data(output_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    let output_commitment = vault_cell_commitment(
        current_lock_hash.as_slice(),
        output_capacity,
        output_type.as_ref().map(|hash| hash.as_slice()),
        output_data.as_slice(),
    );
    if output_commitment.as_slice() != new_header.vault_materialisation_root() {
        return Err(ScriptError::FactoryReserveMismatch);
    }

    Ok(())
}

#[cfg(target_arch = "riscv64")]
#[derive(Clone, Copy)]
struct ChildVaultRelease {
    capacity: u64,
    xudt_type_hash: Option<[u8; BYTE32_LEN]>,
    xudt_amount: u128,
}

#[cfg(target_arch = "riscv64")]
fn find_unique_factory_state_data(
    source: Source,
    expected_factory_id: &[u8],
    expected_type_hash: &[u8],
) -> Result<alloc::vec::Vec<u8>> {
    let mut found: Option<alloc::vec::Vec<u8>> = None;
    let mut index = 0;
    loop {
        match load_cell_type_hash(index, source) {
            Ok(Some(type_hash)) => {
                if type_hash.as_slice() == expected_type_hash {
                    let data = load_cell_data(index, source).map_err(|_| ScriptError::Encoding)?;
                    let header = FactoryStateHeader::parse(&data)?;
                    if header.factory_id() != expected_factory_id {
                        return Err(ScriptError::FactoryIdMismatch);
                    }
                    if found.is_some() {
                        return Err(ScriptError::StateCellAmbiguous);
                    }
                    found = Some(data);
                }
                index += 1;
            }
            Ok(None) => index += 1,
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }

    found.ok_or(ScriptError::StateCellMissing)
}

#[cfg(target_arch = "riscv64")]
fn validate_child_vault(
    vault_output_index: u32,
    expected_vault_lock_hash: &[u8],
    settlement_descriptor: &[u8],
) -> Result<ChildVaultRelease> {
    let vault_index = vault_output_index as usize;
    let vault_lock_hash =
        load_cell_lock_hash(vault_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    if vault_lock_hash.as_slice() != expected_vault_lock_hash {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }
    match settlement_descriptor.len() {
        BILATERAL_CKB_DESCRIPTOR_LEN => {
            validate_ckb_child_vault(settlement_descriptor, vault_index)
        }
        BILATERAL_CKB_XUDT_DESCRIPTOR_LEN => {
            validate_xudt_child_vault(settlement_descriptor, vault_index)
        }
        _ => Err(ScriptError::SettlementDescriptorEncoding),
    }
}

#[cfg(target_arch = "riscv64")]
fn validate_ckb_child_vault(
    settlement_descriptor: &[u8],
    vault_index: usize,
) -> Result<ChildVaultRelease> {
    let descriptor = BilateralCkbSettlementDescriptor::parse(settlement_descriptor)?;
    let expected_capacity = descriptor.checked_total_capacity()?;
    let vault_data =
        load_cell_data(vault_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    if !vault_data.is_empty() {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }
    let vault_type =
        load_cell_type_hash(vault_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    if vault_type.is_some() {
        return Err(ScriptError::XudtTypeMismatch);
    }
    let vault_capacity =
        load_cell_capacity(vault_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    if vault_capacity != expected_capacity {
        return Err(ScriptError::SettlementOutputMismatch);
    }
    Ok(ChildVaultRelease {
        capacity: expected_capacity,
        xudt_type_hash: None,
        xudt_amount: 0,
    })
}

#[cfg(target_arch = "riscv64")]
fn validate_xudt_child_vault(
    settlement_descriptor: &[u8],
    vault_index: usize,
) -> Result<ChildVaultRelease> {
    let descriptor = BilateralCkbXudtSettlementDescriptor::parse(settlement_descriptor)?;
    let vault_type =
        load_cell_type_hash(vault_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    let vault_type = vault_type.ok_or(ScriptError::XudtTypeMismatch)?;
    if vault_type.as_slice() != descriptor.xudt_type_hash() {
        return Err(ScriptError::XudtTypeMismatch);
    }
    let mut type_hash = [0u8; BYTE32_LEN];
    type_hash.copy_from_slice(vault_type.as_slice());
    let vault_data =
        load_cell_data(vault_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    if vault_data.len() != 16 {
        return Err(ScriptError::XudtAmountEncoding);
    }
    let xudt_amount = read_u128(&vault_data, 0);
    if xudt_amount != descriptor.checked_total_xudt_amount()? {
        return Err(ScriptError::SettlementOutputMismatch);
    }
    let expected_capacity = descriptor.checked_total_capacity()?;
    let vault_capacity =
        load_cell_capacity(vault_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    if vault_capacity != expected_capacity {
        return Err(ScriptError::SettlementOutputMismatch);
    }
    Ok(ChildVaultRelease {
        capacity: expected_capacity,
        xudt_type_hash: Some(type_hash),
        xudt_amount,
    })
}

#[cfg(target_arch = "riscv64")]
#[derive(Clone, Copy)]
struct FactoryVaultMaterialisedAssets {
    ckb_amount: u128,
    xudt: Option<([u8; BYTE32_LEN], u128)>,
}

#[cfg(target_arch = "riscv64")]
fn validate_factory_splice_vault_deltas(
    old_vault: &FactoryVaultDescriptor,
    new_vault: &FactoryVaultDescriptor,
    deltas: &FactoryVaultDeltas,
    withdrawal_lock_hash: &[u8],
) -> Result<()> {
    let input_capacity = single_group_capacity(Source::GroupInput)?;
    let input_type =
        load_cell_type_hash(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let input_data = load_cell_data(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;

    let current_lock_hash = load_script_hash().map_err(|_| ScriptError::Encoding)?;
    let output_index = single_output_index_by_lock_hash(&current_lock_hash)?;
    let output_capacity =
        load_cell_capacity(output_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    let output_type =
        load_cell_type_hash(output_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    let output_data =
        load_cell_data(output_index, Source::Output).map_err(|_| ScriptError::Encoding)?;

    validate_factory_vault_descriptor_materialisation(
        old_vault,
        input_capacity,
        input_type.as_ref().map(|hash| hash.as_slice()),
        input_data.as_slice(),
    )?;
    validate_factory_vault_descriptor_materialisation(
        new_vault,
        output_capacity,
        output_type.as_ref().map(|hash| hash.as_slice()),
        output_data.as_slice(),
    )?;

    for index in 0..deltas.delta_count() as usize {
        let delta = deltas.delta(index)?;
        validate_factory_splice_cell_delta(
            &delta,
            input_capacity,
            input_type.as_ref().map(|hash| hash.as_slice()),
            input_data.as_slice(),
            output_capacity,
            output_type.as_ref().map(|hash| hash.as_slice()),
            output_data.as_slice(),
        )?;
        if delta.withdrawal() != 0 {
            validate_factory_splice_withdrawal_output(withdrawal_lock_hash, &delta)?;
        }
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_factory_splice_withdrawal_output(
    expected_lock_hash: &[u8],
    delta: &FactoryVaultDelta,
) -> Result<()> {
    let mut found = false;
    let mut index = 0;
    loop {
        match load_cell_lock_hash(index, Source::Output) {
            Ok(lock_hash) => {
                if lock_hash.as_slice() == expected_lock_hash {
                    let matches = match delta.asset_kind() {
                        VAULT_ASSET_KIND_CKB => {
                            let capacity_matches = u128::from(
                                load_cell_capacity(index, Source::Output)
                                    .map_err(|_| ScriptError::Encoding)?,
                            ) == delta.withdrawal();
                            let type_hash = load_cell_type_hash(index, Source::Output)
                                .map_err(|_| ScriptError::Encoding)?;
                            let data = load_cell_data(index, Source::Output)
                                .map_err(|_| ScriptError::Encoding)?;
                            capacity_matches && type_hash.is_none() && data.is_empty()
                        }
                        VAULT_ASSET_KIND_XUDT => {
                            let type_hash = load_cell_type_hash(index, Source::Output)
                                .map_err(|_| ScriptError::Encoding)?;
                            let data = load_cell_data(index, Source::Output)
                                .map_err(|_| ScriptError::Encoding)?;
                            type_hash.as_ref().map(|hash| hash.as_slice())
                                == Some(delta.asset_type())
                                && data.len() == 16
                                && read_u128(data.as_slice(), 0) == delta.withdrawal()
                        }
                        _ => return Err(ScriptError::FactorySpliceProofEncoding),
                    };
                    if matches {
                        if found {
                            return Err(ScriptError::FactorySpliceProofMismatch);
                        }
                        found = true;
                    }
                }
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    if !found {
        return Err(ScriptError::FactorySpliceProofMismatch);
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_factory_vault_descriptor_materialisation(
    descriptor: &FactoryVaultDescriptor,
    capacity: u64,
    type_hash: Option<&[u8]>,
    data: &[u8],
) -> Result<()> {
    let assets = factory_vault_descriptor_assets(descriptor)?;
    let expected_capacity =
        u64::try_from(assets.ckb_amount).map_err(|_| ScriptError::FactorySpliceProofMismatch)?;
    if capacity != expected_capacity {
        return Err(ScriptError::FactorySpliceProofMismatch);
    }

    match assets.xudt {
        None => {
            if type_hash.is_some() || !data.is_empty() {
                return Err(ScriptError::FactorySpliceProofMismatch);
            }
        }
        Some((expected_type_hash, expected_amount)) => {
            let type_hash = type_hash.ok_or(ScriptError::XudtTypeMismatch)?;
            if type_hash != expected_type_hash.as_slice() {
                return Err(ScriptError::XudtTypeMismatch);
            }
            if data.len() != 16 {
                return Err(ScriptError::XudtAmountEncoding);
            }
            if read_u128(data, 0) != expected_amount {
                return Err(ScriptError::FactorySpliceProofMismatch);
            }
        }
    }

    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn factory_vault_descriptor_assets(
    descriptor: &FactoryVaultDescriptor,
) -> Result<FactoryVaultMaterialisedAssets> {
    let mut ckb_amount = None;
    let mut xudt = None;

    for index in 0..descriptor.asset_count() as usize {
        let asset = descriptor.asset(index)?;
        match asset.asset_kind() {
            VAULT_ASSET_KIND_CKB => {
                if ckb_amount.is_some() {
                    return Err(ScriptError::FactorySpliceProofMismatch);
                }
                ckb_amount = Some(asset.amount());
            }
            VAULT_ASSET_KIND_XUDT => {
                if xudt.is_some() {
                    return Err(ScriptError::FactorySpliceProofMismatch);
                }
                let mut asset_type = [0u8; BYTE32_LEN];
                asset_type.copy_from_slice(asset.asset_type());
                xudt = Some((asset_type, asset.amount()));
            }
            _ => return Err(ScriptError::FactorySpliceProofEncoding),
        }
    }

    Ok(FactoryVaultMaterialisedAssets {
        ckb_amount: ckb_amount.ok_or(ScriptError::FactorySpliceProofMismatch)?,
        xudt,
    })
}

#[cfg(target_arch = "riscv64")]
#[allow(clippy::too_many_arguments)]
fn validate_factory_splice_cell_delta(
    delta: &FactoryVaultDelta,
    input_capacity: u64,
    input_type: Option<&[u8]>,
    input_data: &[u8],
    output_capacity: u64,
    output_type: Option<&[u8]>,
    output_data: &[u8],
) -> Result<()> {
    match delta.asset_kind() {
        VAULT_ASSET_KIND_CKB => {
            if input_capacity as u128 != delta.old_amount()
                || output_capacity as u128 != delta.new_amount()
            {
                return Err(ScriptError::FactorySpliceProofMismatch);
            }
        }
        VAULT_ASSET_KIND_XUDT => {
            if input_type != Some(delta.asset_type()) || output_type != Some(delta.asset_type()) {
                return Err(ScriptError::XudtTypeMismatch);
            }
            if input_data.len() != 16 || output_data.len() != 16 {
                return Err(ScriptError::XudtAmountEncoding);
            }
            if read_u128(input_data, 0) != delta.old_amount()
                || read_u128(output_data, 0) != delta.new_amount()
            {
                return Err(ScriptError::FactorySpliceProofMismatch);
            }
        }
        _ => return Err(ScriptError::FactorySpliceProofEncoding),
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_factory_reduced_exit_reserve_conservation(release: &ChildVaultRelease) -> Result<()> {
    // Callers verify the reduced-exit witness against the on-chain old/new
    // FactoryState headers before this arithmetic check; this function only
    // enforces the vault cell delta authorised by that witness.
    let input_capacity = single_group_capacity(Source::GroupInput)?;
    let input_type =
        load_cell_type_hash(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let input_data = load_cell_data(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;

    let current_lock_hash = load_script_hash().map_err(|_| ScriptError::Encoding)?;
    let output_index = single_output_index_by_lock_hash(&current_lock_hash)?;
    let output_capacity =
        load_cell_capacity(output_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    let output_type =
        load_cell_type_hash(output_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    let output_data =
        load_cell_data(output_index, Source::Output).map_err(|_| ScriptError::Encoding)?;

    let expected_input = output_capacity
        .checked_add(release.capacity)
        .ok_or(ScriptError::CapacityUnderflow)?;
    if input_capacity != expected_input {
        return Err(ScriptError::FactoryReserveMismatch);
    }

    match release.xudt_type_hash {
        None => {
            if input_type.is_some()
                || output_type.is_some()
                || !input_data.is_empty()
                || !output_data.is_empty()
            {
                return Err(ScriptError::FactoryReserveMismatch);
            }
        }
        Some(type_hash) => {
            let input_type = input_type.ok_or(ScriptError::XudtTypeMismatch)?;
            if input_type.as_slice() != type_hash.as_slice() {
                return Err(ScriptError::XudtTypeMismatch);
            }
            if input_data.len() != 16 {
                return Err(ScriptError::XudtAmountEncoding);
            }
            let input_amount = read_u128(&input_data, 0);
            if input_amount < release.xudt_amount {
                return Err(ScriptError::FactoryReserveMismatch);
            }
            let remaining_amount = input_amount - release.xudt_amount;
            match output_type {
                Some(output_type) => {
                    if remaining_amount == 0 || output_type.as_slice() != type_hash.as_slice() {
                        return Err(ScriptError::XudtTypeMismatch);
                    }
                    if output_data.len() != 16 {
                        return Err(ScriptError::XudtAmountEncoding);
                    }
                    if read_u128(&output_data, 0) != remaining_amount {
                        return Err(ScriptError::FactoryReserveMismatch);
                    }
                }
                None => {
                    if remaining_amount != 0 || !output_data.is_empty() {
                        return Err(ScriptError::FactoryReserveMismatch);
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn single_output_index_by_lock_hash(expected_lock_hash: &[u8]) -> Result<usize> {
    let mut found = None;
    let mut index = 0;
    loop {
        match load_cell_lock_hash(index, Source::Output) {
            Ok(lock_hash) => {
                if lock_hash.as_slice() == expected_lock_hash {
                    if found.is_some() {
                        return Err(ScriptError::FactoryReserveMismatch);
                    }
                    found = Some(index);
                }
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    found.ok_or(ScriptError::FactoryReserveMismatch)
}

#[cfg(target_arch = "riscv64")]
fn single_group_capacity(source: Source) -> Result<u64> {
    let capacity = load_cell_capacity(0, source).map_err(|_| ScriptError::Encoding)?;
    match load_cell_capacity(1, source) {
        Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => Ok(capacity),
        Err(_) => Err(ScriptError::Encoding),
        Ok(_) => Err(ScriptError::FactoryReserveMismatch),
    }
}

#[cfg(test)]
mod tests {
    use morph_script_common::{FACTORY_STATE_HEADER_LEN, FactoryStateHeader};

    #[test]
    fn factory_state_header_parse_is_borrowed_and_repeatable() {
        for update_number in 0..100u64 {
            let raw = factory_header_bytes(update_number);
            let header = FactoryStateHeader::parse(&raw).unwrap();

            assert_eq!(header.update_number(), update_number);
        }
    }

    fn factory_header_bytes(update_number: u64) -> [u8; FACTORY_STATE_HEADER_LEN] {
        let mut raw = [0u8; FACTORY_STATE_HEADER_LEN];
        raw[0..2].copy_from_slice(&1u16.to_le_bytes());
        raw[2..34].fill(1);
        raw[34..36].copy_from_slice(&1u16.to_le_bytes());
        raw[36..68].fill(2);
        raw[68..76].copy_from_slice(&update_number.to_le_bytes());
        raw[76..108].fill(3);
        raw[108..140].fill(4);
        raw[140..172].fill(5);
        raw[172..204].fill(6);
        raw[204..236].fill(7);
        raw[236..238].copy_from_slice(&1u16.to_le_bytes());
        raw[238..270].fill(8);
        raw
    }
}
