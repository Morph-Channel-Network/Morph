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
    QueryIter, load_cell_capacity, load_cell_data, load_cell_lock, load_cell_lock_hash,
    load_cell_occupied_capacity, load_cell_type_hash, load_input, load_input_out_point,
    load_script, load_script_hash, load_transaction, load_witness_args,
};
#[cfg(target_arch = "riscv64")]
use ckb_std::{default_alloc, entry};
#[cfg(target_arch = "riscv64")]
use morph_script_common::{
    BILATERAL_CKB_DESCRIPTOR_LEN, BILATERAL_CKB_DESCRIPTOR_VERSION,
    BILATERAL_CKB_XUDT_DESCRIPTOR_LEN, BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION, BYTE32_LEN,
    BilateralCkbSettlementDescriptor, BilateralCkbXudtSettlementDescriptor,
    FactoryLocalExitWitness, FactoryMerkleUpdateWitness, FactoryMultiRightUpdateWitness,
    FactoryReducedExitWitness, FactoryReducedRightsWitness, FactoryReducedSpliceWitness,
    FactorySignatureWitness, FactorySpliceWitness, FactoryStateHeader, PHASE_ACTIVE, Result,
    SETTLEMENT_DESCRIPTOR_DOMAIN, STATE_CARRIER_ACTIVATION_FEE, ScriptError, StateHeader,
    UNBOUND_VAULT_OUTPOINT_COMMITMENT, WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT,
    WITNESS_ENVELOPE_KIND_FACTORY_MERKLE_UPDATE, WITNESS_ENVELOPE_KIND_FACTORY_MULTI_RIGHT_UPDATE,
    WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_EXIT, WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_RIGHTS,
    WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_SPLICE, WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE,
    WITNESS_ENVELOPE_KIND_FACTORY_SPLICE, WitnessEnvelope, blake2b256, read_u128,
    vault_cell_commitment, vault_outpoint_commitment, verify_factory_merkle_update,
    verify_factory_multi_right_update, verify_factory_reduced_exit_update,
    verify_factory_reduced_rights_update, verify_factory_reduced_splice_update,
    verify_factory_splice_update, verify_factory_state_signatures,
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
    if args.len() == morph_script_common::factory_multi_asset::FACTORY_MULTI_ASSET_TYPE_ARGS_LEN {
        return morph_script_common::factory_multi_asset_runtime::validate_type();
    }
    if args.len() != BYTE32_LEN {
        return Err(ScriptError::WrongArgsLength);
    }
    let expected_factory_id = &args.as_ref()[..BYTE32_LEN];

    match (
        zero_or_one_group_cell_data(Source::GroupInput)?,
        zero_or_one_group_cell_data(Source::GroupOutput)?,
    ) {
        (None, Some(new_data)) => validate_create(&new_data, expected_factory_id)?,
        (Some(old_data), Some(new_data)) => {
            let old_header = FactoryStateHeader::parse(&old_data)?;
            old_header.validate_profile()?;
            if old_header.factory_id() != expected_factory_id {
                return Err(ScriptError::FactoryIdMismatch);
            }
            validate_update(&old_header, &new_data, expected_factory_id)?;
        }
        _ => return Err(ScriptError::WrongGroupShape),
    }

    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_create(new_data: &[u8], expected_factory_id: &[u8]) -> Result<()> {
    let new_header = FactoryStateHeader::parse(new_data)?;
    new_header.validate_profile()?;
    if new_header.factory_id() != expected_factory_id {
        return Err(ScriptError::FactoryIdMismatch);
    }
    if new_header.update_number() != 0 {
        return Err(ScriptError::NonMonotonicStateNumber);
    }
    if new_header.vault_is_bound() {
        return Err(ScriptError::VaultActivationInvalid);
    }
    validate_factory_id_derivation(expected_factory_id)?;
    validate_initial_participant_authorisation(&new_header)?;
    validate_factory_vault_materialisation(
        Source::Output,
        expected_factory_id,
        new_header.vault_materialisation_root(),
        None,
    )?;
    validate_output_capacity()?;
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_initial_participant_authorisation(header: &FactoryStateHeader) -> Result<()> {
    // As with bilateral funding, the new Factory type group has no GroupInput;
    // input zero is the canonical factory-id anchor and carries the consent.
    let witness_args =
        load_witness_args(0, Source::Input).map_err(|_| ScriptError::ParticipantWitnessMissing)?;
    let input_type = witness_args
        .input_type()
        .to_opt()
        .ok_or(ScriptError::ParticipantWitnessMissing)?;
    let input_type_data = input_type.raw_data();
    let envelope = WitnessEnvelope::parse(input_type_data.as_ref())?;
    if envelope.kind() != WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE {
        return Err(ScriptError::WitnessEnvelopeEncoding);
    }
    let witness = FactorySignatureWitness::parse(envelope.body())?;
    verify_factory_state_signatures(header, &witness)
}

#[cfg(target_arch = "riscv64")]
fn validate_update(
    old_header: &FactoryStateHeader,
    new_data: &[u8],
    expected_factory_id: &[u8],
) -> Result<()> {
    let new_header = FactoryStateHeader::parse(new_data)?;
    new_header.validate_profile()?;
    if new_header.factory_id() != expected_factory_id {
        return Err(ScriptError::FactoryIdMismatch);
    }
    validate_output_lock_preserved()?;
    if !old_header.vault_is_bound() {
        if !old_header.is_vault_activation_to(&new_header) {
            return Err(ScriptError::VaultActivationInvalid);
        }
        validate_factory_activation_cell_dep(
            expected_factory_id,
            new_header.vault_materialisation_root(),
            new_header.vault_outpoint_commitment(),
        )?;
        validate_activation_carrier_capacity()?;
        validate_output_capacity()?;
        return Ok(());
    }
    if new_header.update_number() <= old_header.update_number() {
        return Err(ScriptError::NonMonotonicStateNumber);
    }
    if !old_header.same_context_except_progress(&new_header) {
        return Err(ScriptError::HeaderContextChanged);
    }
    let authorisation_kind = validate_participant_authorisation(old_header, &new_header)?;
    match authorisation_kind {
        WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE
        | WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_RIGHTS
        | WITNESS_ENVELOPE_KIND_FACTORY_MERKLE_UPDATE
        | WITNESS_ENVELOPE_KIND_FACTORY_MULTI_RIGHT_UPDATE => {
            if !new_header.vault_is_bound()
                || old_header.vault_materialisation_root()
                    != new_header.vault_materialisation_root()
                || old_header.vault_outpoint_commitment() != new_header.vault_outpoint_commitment()
            {
                return Err(ScriptError::HeaderContextChanged);
            }
            validate_preserved_carrier_capacity()?;
        }
        WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT
        | WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_EXIT
        | WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_SPLICE
        | WITNESS_ENVELOPE_KIND_FACTORY_SPLICE => {
            if new_header.vault_is_bound() {
                return Err(ScriptError::VaultActivationInvalid);
            }
            validate_factory_vault_materialisation(
                Source::Input,
                expected_factory_id,
                old_header.vault_materialisation_root(),
                Some(old_header.vault_outpoint_commitment()),
            )?;
            validate_factory_vault_materialisation(
                Source::Output,
                expected_factory_id,
                new_header.vault_materialisation_root(),
                None,
            )?;
            validate_unbound_carrier_capacity()?;
        }
        _ => return Err(ScriptError::WitnessEnvelopeEncoding),
    }
    validate_output_capacity()?;
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_participant_authorisation(
    old_header: &FactoryStateHeader,
    header: &FactoryStateHeader,
) -> Result<u16> {
    let witness_args = load_witness_args(0, Source::GroupInput)
        .map_err(|_| ScriptError::ParticipantWitnessMissing)?;
    let input_type = witness_args
        .input_type()
        .to_opt()
        .ok_or(ScriptError::ParticipantWitnessMissing)?;
    let input_type_data = input_type.raw_data();
    let envelope = WitnessEnvelope::parse(input_type_data.as_ref())?;
    let raw = envelope.body();
    match envelope.kind() {
        WITNESS_ENVELOPE_KIND_FACTORY_SIGNATURE => {
            let witness = FactorySignatureWitness::parse(raw)?;
            verify_factory_state_signatures(header, &witness)?;
        }
        WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_RIGHTS => {
            let witness = FactoryReducedRightsWitness::parse(raw)?;
            verify_factory_reduced_rights_update(old_header, header, &witness)?;
        }
        WITNESS_ENVELOPE_KIND_FACTORY_MERKLE_UPDATE => {
            let witness = FactoryMerkleUpdateWitness::parse(raw)?;
            verify_factory_merkle_update(old_header, header, &witness)?;
        }
        WITNESS_ENVELOPE_KIND_FACTORY_MULTI_RIGHT_UPDATE => {
            let witness = FactoryMultiRightUpdateWitness::parse(raw)?;
            verify_factory_multi_right_update(old_header, header, &witness)?;
        }
        WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_EXIT => {
            let witness = FactoryReducedExitWitness::parse(raw)?;
            verify_factory_reduced_exit_update(old_header, header, &witness)?;
            validate_reduced_exit(header, &witness)?;
        }
        WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_SPLICE => {
            let witness = FactoryReducedSpliceWitness::parse(raw)?;
            verify_factory_reduced_splice_update(old_header, header, &witness)?;
        }
        WITNESS_ENVELOPE_KIND_FACTORY_SPLICE => {
            let witness = FactorySpliceWitness::parse(raw)?;
            verify_factory_splice_update(old_header, header, &witness)?;
        }
        WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT => {
            let witness = FactoryLocalExitWitness::parse(raw)?;
            let signatures = witness.factory_signature()?;
            verify_factory_state_signatures(header, &signatures)?;
            validate_local_exit(header, &witness)?;
        }
        _ => return Err(ScriptError::WitnessEnvelopeEncoding),
    }
    Ok(envelope.kind())
}

#[cfg(target_arch = "riscv64")]
fn validate_factory_vault_materialisation(
    source: Source,
    expected_factory_id: &[u8],
    expected_commitment: &[u8],
    expected_outpoint: Option<&[u8]>,
) -> Result<()> {
    if expected_outpoint == Some(UNBOUND_VAULT_OUTPOINT_COMMITMENT.as_slice()) {
        return Err(ScriptError::VaultOutPointUnbound);
    }
    let factory_type_hash = load_script_hash().map_err(|_| ScriptError::Encoding)?;
    let mut candidates = 0usize;
    let mut commitment_matches = false;
    let mut index = 0usize;
    loop {
        match load_cell_lock(index, source) {
            Ok(lock) => {
                let args = lock.args().raw_data();
                if args.len() == 2 * BYTE32_LEN
                    && &args.as_ref()[..BYTE32_LEN] == expected_factory_id
                    && &args.as_ref()[BYTE32_LEN..] == factory_type_hash.as_slice()
                {
                    candidates += 1;
                    if candidates > 1 {
                        return Err(ScriptError::VaultCellAmbiguous);
                    }
                    let lock_hash =
                        load_cell_lock_hash(index, source).map_err(|_| ScriptError::Encoding)?;
                    let capacity =
                        load_cell_capacity(index, source).map_err(|_| ScriptError::Encoding)?;
                    let type_hash =
                        load_cell_type_hash(index, source).map_err(|_| ScriptError::Encoding)?;
                    let data = load_cell_data(index, source).map_err(|_| ScriptError::Encoding)?;
                    let commitment = vault_cell_commitment(
                        lock_hash.as_slice(),
                        capacity,
                        type_hash.as_ref().map(|hash| hash.as_slice()),
                        data.as_slice(),
                    );
                    if commitment.as_slice() == expected_commitment {
                        if let Some(expected_outpoint) = expected_outpoint {
                            let outpoint = load_input_out_point(index, source)
                                .map_err(|_| ScriptError::Encoding)?;
                            let output_index: u32 = outpoint.index().unpack();
                            let locator = vault_outpoint_commitment(
                                outpoint.tx_hash().as_slice(),
                                output_index,
                            );
                            if locator.as_slice() != expected_outpoint {
                                return Err(ScriptError::VaultOutPointMismatch);
                            }
                        }
                        commitment_matches = true;
                    }
                }
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    if candidates == 1 && commitment_matches {
        Ok(())
    } else {
        Err(ScriptError::VaultCellMissing)
    }
}

#[cfg(target_arch = "riscv64")]
fn validate_factory_activation_cell_dep(
    expected_factory_id: &[u8],
    expected_root: &[u8],
    expected_outpoint: &[u8],
) -> Result<()> {
    if expected_outpoint == UNBOUND_VAULT_OUTPOINT_COMMITMENT {
        return Err(ScriptError::VaultOutPointUnbound);
    }
    let state_outpoint =
        load_input_out_point(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let funding_tx_hash = state_outpoint.tx_hash();
    let factory_type_hash = load_script_hash().map_err(|_| ScriptError::Encoding)?;
    let transaction = load_transaction().map_err(|_| ScriptError::Encoding)?;
    let cell_deps = transaction.raw().cell_deps();
    let dep = cell_deps.get(0).ok_or(ScriptError::VaultOutPointMismatch)?;
    if dep.dep_type().as_slice()[0] != 0 {
        return Err(ScriptError::VaultOutPointMismatch);
    }
    let outpoint = dep.out_point();
    let tx_hash = outpoint.tx_hash();
    let output_index: u32 = outpoint.index().unpack();
    if tx_hash != funding_tx_hash
        || vault_outpoint_commitment(tx_hash.as_slice(), output_index).as_slice()
            != expected_outpoint
    {
        return Err(ScriptError::VaultOutPointMismatch);
    }
    for extra_dep in cell_deps.into_iter().skip(1) {
        let extra_outpoint = extra_dep.out_point();
        let extra_index: u32 = extra_outpoint.index().unpack();
        if vault_outpoint_commitment(extra_outpoint.tx_hash().as_slice(), extra_index).as_slice()
            == expected_outpoint
        {
            return Err(ScriptError::VaultOutPointMismatch);
        }
    }
    let lock = load_cell_lock(0, Source::CellDep).map_err(|_| ScriptError::Encoding)?;
    let args = lock.args().raw_data();
    if args.len() != 2 * BYTE32_LEN
        || &args.as_ref()[..BYTE32_LEN] != expected_factory_id
        || &args.as_ref()[BYTE32_LEN..] != factory_type_hash.as_slice()
    {
        return Err(ScriptError::VaultOutPointMismatch);
    }
    let capacity = load_cell_capacity(0, Source::CellDep).map_err(|_| ScriptError::Encoding)?;
    let lock_hash = load_cell_lock_hash(0, Source::CellDep).map_err(|_| ScriptError::Encoding)?;
    let type_hash = load_cell_type_hash(0, Source::CellDep).map_err(|_| ScriptError::Encoding)?;
    let data = load_cell_data(0, Source::CellDep).map_err(|_| ScriptError::Encoding)?;
    let root = vault_cell_commitment(
        lock_hash.as_slice(),
        capacity,
        type_hash.as_ref().map(|hash| hash.as_slice()),
        data.as_slice(),
    );
    if root.as_slice() != expected_root {
        return Err(ScriptError::VaultOutPointMismatch);
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
fn validate_local_exit(
    header: &FactoryStateHeader,
    witness: &FactoryLocalExitWitness,
) -> Result<()> {
    if header.non_interference_digest() != witness.exit_digest().as_slice() {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }
    validate_exit_materialisation(
        witness.state_output_index(),
        witness.vault_output_index(),
        witness.state_type_hash(),
        witness.vault_lock_hash(),
        witness.state_lock_hash(),
        witness.exit_state_header(),
        witness.settlement_descriptor(),
    )
}

#[cfg(target_arch = "riscv64")]
fn validate_reduced_exit(
    _header: &FactoryStateHeader,
    witness: &FactoryReducedExitWitness,
) -> Result<()> {
    validate_exit_materialisation(
        witness.state_output_index(),
        witness.vault_output_index(),
        witness.state_type_hash(),
        witness.vault_lock_hash(),
        witness.state_lock_hash(),
        witness.exit_state_header(),
        witness.settlement_descriptor(),
    )
}

#[cfg(target_arch = "riscv64")]
fn validate_exit_materialisation(
    state_output_index: u32,
    vault_output_index: u32,
    state_type_hash: &[u8],
    vault_lock_hash: &[u8],
    state_lock_hash: &[u8],
    exit_state_header: &[u8],
    descriptor_raw: &[u8],
) -> Result<()> {
    let state_index = state_output_index as usize;
    let vault_index = vault_output_index as usize;
    if state_index == vault_index {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }

    let state_data =
        load_cell_data(state_index, Source::Output).map_err(|_| ScriptError::StateCellMissing)?;
    if state_data.as_slice() != exit_state_header {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }
    let output_state_type_hash = load_cell_type_hash(state_index, Source::Output)
        .map_err(|_| ScriptError::FactoryLocalExitMismatch)?
        .ok_or(ScriptError::FactoryLocalExitMismatch)?;
    if output_state_type_hash.as_slice() != state_type_hash {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }
    let output_state_lock_hash =
        load_cell_lock_hash(state_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    if output_state_lock_hash.as_slice() != state_lock_hash {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }

    let exit_header = StateHeader::parse(exit_state_header)?;
    exit_header.validate_profile()?;
    if exit_header.state_number() != 0 || exit_header.phase() != PHASE_ACTIVE {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }
    if exit_header.settlement_descriptor_commitment()
        != blake2b256(&[SETTLEMENT_DESCRIPTOR_DOMAIN, descriptor_raw]).as_slice()
    {
        return Err(ScriptError::SettlementDescriptorMismatch);
    }

    let input = load_input(0, Source::Input).map_err(|_| ScriptError::Encoding)?;
    let state_index_bytes = (state_index as u64).to_le_bytes();
    let expected_anchor = blake2b256(&[input.as_slice(), &state_index_bytes]);
    if exit_header.funding_anchor() != expected_anchor.as_slice() {
        return Err(ScriptError::FundingAnchorMismatch);
    }

    let output_vault_lock_hash =
        load_cell_lock_hash(vault_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    if output_vault_lock_hash.as_slice() != vault_lock_hash {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }
    validate_child_vault_shape(exit_header, descriptor_raw, vault_index)?;

    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_child_vault_shape(
    exit_header: StateHeader,
    descriptor_raw: &[u8],
    vault_index: usize,
) -> Result<()> {
    match descriptor_raw.len() {
        BILATERAL_CKB_DESCRIPTOR_LEN => {
            if exit_header.descriptor_version() != BILATERAL_CKB_DESCRIPTOR_VERSION {
                return Err(ScriptError::SettlementDescriptorMismatch);
            }
            let descriptor = BilateralCkbSettlementDescriptor::parse(descriptor_raw)?;
            let vault_data =
                load_cell_data(vault_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
            if !vault_data.is_empty() {
                return Err(ScriptError::FactoryLocalExitMismatch);
            }
            let vault_type = load_cell_type_hash(vault_index, Source::Output)
                .map_err(|_| ScriptError::Encoding)?;
            if vault_type.is_some() {
                return Err(ScriptError::XudtTypeMismatch);
            }
            let vault_capacity = load_cell_capacity(vault_index, Source::Output)
                .map_err(|_| ScriptError::Encoding)?;
            if vault_capacity != descriptor.checked_total_capacity()? {
                return Err(ScriptError::SettlementOutputMismatch);
            }
        }
        BILATERAL_CKB_XUDT_DESCRIPTOR_LEN => {
            if exit_header.descriptor_version() != BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION {
                return Err(ScriptError::SettlementDescriptorMismatch);
            }
            let descriptor = BilateralCkbXudtSettlementDescriptor::parse(descriptor_raw)?;
            let vault_type = load_cell_type_hash(vault_index, Source::Output)
                .map_err(|_| ScriptError::Encoding)?
                .ok_or(ScriptError::XudtTypeMismatch)?;
            if vault_type.as_slice() != descriptor.xudt_type_hash() {
                return Err(ScriptError::XudtTypeMismatch);
            }
            let vault_data =
                load_cell_data(vault_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
            if vault_data.len() != 16 {
                return Err(ScriptError::XudtAmountEncoding);
            }
            if read_u128(&vault_data, 0) != descriptor.checked_total_xudt_amount()? {
                return Err(ScriptError::SettlementOutputMismatch);
            }
            let vault_capacity = load_cell_capacity(vault_index, Source::Output)
                .map_err(|_| ScriptError::Encoding)?;
            if vault_capacity != descriptor.checked_total_capacity()? {
                return Err(ScriptError::SettlementOutputMismatch);
            }
        }
        _ => return Err(ScriptError::SettlementDescriptorEncoding),
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_output_capacity() -> Result<()> {
    let cap = load_cell_capacity(0, Source::GroupOutput).map_err(|_| ScriptError::Encoding)?;
    let occupied =
        load_cell_occupied_capacity(0, Source::GroupOutput).map_err(|_| ScriptError::Encoding)?;
    if cap < occupied {
        return Err(ScriptError::OutputBelowOccupiedCapacity);
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
fn validate_activation_carrier_capacity() -> Result<()> {
    let input = load_cell_capacity(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let output = load_cell_capacity(0, Source::GroupOutput).map_err(|_| ScriptError::Encoding)?;
    if input.checked_sub(STATE_CARRIER_ACTIVATION_FEE) != Some(output) {
        return Err(ScriptError::StateCarrierMismatch);
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_unbound_carrier_capacity() -> Result<()> {
    let input = load_cell_capacity(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let output = load_cell_capacity(0, Source::GroupOutput).map_err(|_| ScriptError::Encoding)?;
    if input.checked_add(STATE_CARRIER_ACTIVATION_FEE) != Some(output) {
        return Err(ScriptError::StateCarrierMismatch);
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_factory_id_derivation(expected_factory_id: &[u8]) -> Result<()> {
    let script_hash = load_script_hash().map_err(|_| ScriptError::Encoding)?;
    let output_index = QueryIter::new(load_cell_type_hash, Source::Output)
        .position(|type_hash| type_hash == Some(script_hash))
        .ok_or(ScriptError::FactoryIdMismatch)? as u64;
    let input = load_input(0, Source::Input).map_err(|_| ScriptError::Encoding)?;
    let index = output_index.to_le_bytes();
    let derived = blake2b256(&[input.as_slice(), &index]);
    if derived.as_slice() != expected_factory_id {
        return Err(ScriptError::FactoryIdMismatch);
    }
    let mut input_index = 1;
    loop {
        match load_input(input_index, Source::Input) {
            Ok(input) => {
                if blake2b256(&[input.as_slice(), &index]).as_slice() == expected_factory_id {
                    return Err(ScriptError::FactoryIdMismatch);
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
