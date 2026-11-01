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
    QueryIter, load_cell_capacity, load_cell_data, load_cell_lock, load_cell_lock_hash,
    load_cell_occupied_capacity, load_cell_type, load_cell_type_hash, load_input,
    load_input_out_point, load_script, load_script_hash, load_transaction, load_witness_args,
};
#[cfg(target_arch = "riscv64")]
use ckb_std::{default_alloc, entry};
#[cfg(target_arch = "riscv64")]
use morph_script_common::{
    BILATERAL_SIGNATURE_WITNESS_LEN, BYTE32_LEN, BilateralSignatureWitness,
    FactoryLocalExitWitness, FactoryReducedExitWitness, PHASE_ACTIVE, PHASE_SETTLING, Result,
    STATE_CARRIER_ACTIVATION_FEE, STATE_MODE_BILATERAL_PLAINTEXT, STATE_MODE_FACTORY_PROOF,
    ScriptError, SpliceStateTransitionWitness, StateHeader, UNBOUND_VAULT_OUTPOINT_COMMITMENT,
    WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT, WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_EXIT,
    WitnessEnvelope, blake2b256, read_u64, validate_relative_block_since, vault_cell_commitment,
    vault_outpoint_commitment, verify_bilateral_state_signatures,
    verify_splice_state_transition_bundle,
};

#[cfg(target_arch = "riscv64")]
const MAX_WITNESS_INPUTS_PER_TX: usize = 64;

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
    let (expected_factory_type_hash, finalise_since) = match args.len() {
        len if len == BYTE32_LEN + 8 => (None, read_u64(args.as_ref(), BYTE32_LEN)),
        len if len == 2 * BYTE32_LEN + 8 => (
            Some(&args.as_ref()[BYTE32_LEN..2 * BYTE32_LEN]),
            read_u64(args.as_ref(), 2 * BYTE32_LEN),
        ),
        _ => return Err(ScriptError::WrongArgsLength),
    };
    let expected_funding_anchor = &args.as_ref()[..BYTE32_LEN];

    let old_data = zero_or_one_group_cell_data(Source::GroupInput)?;
    let new_data = zero_or_one_group_cell_data(Source::GroupOutput)?;
    if old_data.as_ref().is_some_and(|data| {
        data.len() == morph_script_common::multi_asset::MULTI_ASSET_STATE_HEADER_LEN
    }) || new_data.as_ref().is_some_and(|data| {
        data.len() == morph_script_common::multi_asset::MULTI_ASSET_STATE_HEADER_LEN
    }) {
        if expected_factory_type_hash.is_some() {
            return Err(ScriptError::UnsupportedProtocolProfile);
        }
        return multi_asset::validate(
            expected_funding_anchor,
            finalise_since,
            old_data.as_deref(),
            new_data.as_deref(),
        );
    }
    match (old_data, new_data) {
        (None, Some(new_data)) => validate_create(
            &script,
            &new_data,
            expected_funding_anchor,
            expected_factory_type_hash,
        )?,
        (Some(old_data), Some(new_data)) => {
            let old_header = StateHeader::parse(&old_data)?;
            old_header.validate_profile()?;
            if old_header.funding_anchor() != expected_funding_anchor {
                return Err(ScriptError::FundingAnchorMismatch);
            }
            validate_supersede(&old_header, &new_data, expected_funding_anchor)?;
        }
        (Some(old_data), None) => {
            let old_header = StateHeader::parse(&old_data)?;
            old_header.validate_profile()?;
            if old_header.funding_anchor() != expected_funding_anchor {
                return Err(ScriptError::FundingAnchorMismatch);
            }
            if old_header.phase() == PHASE_ACTIVE {
                validate_splice_retire(&script, &old_header, expected_funding_anchor)?;
            } else {
                validate_finalise(&old_header, finalise_since)?;
            }
        }
        (None, None) => return Err(ScriptError::WrongGroupShape),
    }

    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_create(
    current_script: &ckb_std::ckb_types::packed::Script,
    new_data: &[u8],
    expected_funding_anchor: &[u8],
    expected_factory_type_hash: Option<&[u8]>,
) -> Result<()> {
    let new_header = StateHeader::parse(new_data)?;
    new_header.validate_profile()?;

    if new_header.funding_anchor() != expected_funding_anchor {
        return Err(ScriptError::FundingAnchorMismatch);
    }
    if new_header.phase() != PHASE_ACTIVE {
        return Err(ScriptError::NewStateNotActive);
    }
    if new_header.vault_is_bound() {
        return Err(ScriptError::VaultActivationInvalid);
    }
    validate_output_lock_args_bind_output_type(0, Source::GroupOutput)?;
    if new_header.state_number() != 0
        || find_splice_witness_raw(expected_funding_anchor, false).is_ok()
    {
        validate_splice_create(current_script, &new_header, expected_funding_anchor)?;
        validate_group_output_capacity()?;
        return Ok(());
    }
    validate_anchor_derivation(expected_funding_anchor)?;
    validate_initial_authorisation(new_data, &new_header, expected_factory_type_hash)?;
    find_unique_output_by_vault_commitment(new_header.vault_materialisation_root())?;
    validate_group_output_capacity()
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
fn validate_splice_create(
    current_script: &ckb_std::ckb_types::packed::Script,
    new_header: &StateHeader,
    expected_funding_anchor: &[u8],
) -> Result<()> {
    let witness_raw = find_splice_witness_raw(expected_funding_anchor, false)?;
    let witness = SpliceStateTransitionWitness::parse(&witness_raw)
        .map_err(|_| ScriptError::SpliceProofEncoding)?;
    let splice_header = witness.header()?;
    let (old_index, old_data) = find_unique_state_cell(
        Source::Input,
        current_script,
        splice_header.old_funding_anchor(),
    )?;
    validate_peer_state_type_script(
        current_script,
        old_index,
        Source::Input,
        splice_header.old_funding_anchor(),
    )?;
    let old_header = StateHeader::parse(&old_data)?;
    old_header.validate_profile()?;
    validate_state_lock_continuity(old_index, Source::Input, 0, Source::GroupOutput)?;
    verify_splice_state_transition_bundle(&old_header, new_header, &witness)?;
    validate_splice_carrier_capacity(old_index)
}

#[cfg(target_arch = "riscv64")]
fn validate_splice_retire(
    current_script: &ckb_std::ckb_types::packed::Script,
    old_header: &StateHeader,
    expected_funding_anchor: &[u8],
) -> Result<()> {
    find_unique_input_by_vault_reference(
        old_header.vault_materialisation_root(),
        old_header.vault_outpoint_commitment(),
    )?;
    let witness_raw = find_splice_witness_raw(expected_funding_anchor, true)?;
    let witness = SpliceStateTransitionWitness::parse(&witness_raw)
        .map_err(|_| ScriptError::SpliceProofEncoding)?;
    let splice_header = witness.header()?;
    let (new_index, new_data) = find_unique_state_cell(
        Source::Output,
        current_script,
        splice_header.new_funding_anchor(),
    )?;
    validate_peer_state_type_script(
        current_script,
        new_index,
        Source::Output,
        splice_header.new_funding_anchor(),
    )?;
    let new_header = StateHeader::parse(&new_data)?;
    new_header.validate_profile()?;
    validate_state_lock_continuity(0, Source::GroupInput, new_index, Source::Output)?;
    verify_splice_state_transition_bundle(old_header, &new_header, &witness)
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
fn validate_supersede(
    old_header: &StateHeader,
    new_data: &[u8],
    expected_funding_anchor: &[u8],
) -> Result<()> {
    let new_header = StateHeader::parse(new_data)?;
    new_header.validate_profile()?;

    if new_header.funding_anchor() != expected_funding_anchor {
        return Err(ScriptError::FundingAnchorMismatch);
    }
    if !old_header.vault_is_bound() {
        return validate_vault_activation(old_header, &new_header);
    }
    if !new_header.vault_is_bound() {
        return Err(ScriptError::VaultOutPointUnbound);
    }
    if new_header.state_number() <= old_header.state_number() {
        return Err(ScriptError::NonMonotonicStateNumber);
    }
    if new_header.phase() != PHASE_SETTLING {
        return Err(ScriptError::NewStateNotSettling);
    }
    if !old_header.same_context_except_progress(&new_header) {
        return Err(ScriptError::HeaderContextChanged);
    }
    validate_participant_authorisation(&new_header)?;
    validate_output_lock_preserved()?;
    validate_preserved_carrier_capacity()?;

    validate_group_output_capacity()
}

#[cfg(target_arch = "riscv64")]
fn validate_vault_activation(old_header: &StateHeader, new_header: &StateHeader) -> Result<()> {
    if !old_header.is_vault_activation_to(new_header) {
        return Err(ScriptError::VaultActivationInvalid);
    }
    validate_output_lock_preserved()?;
    validate_activation_cell_dep(
        new_header.vault_materialisation_root(),
        new_header.vault_outpoint_commitment(),
    )?;
    validate_activation_carrier_capacity()?;
    validate_group_output_capacity()
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
fn validate_splice_carrier_capacity(old_input_index: usize) -> Result<()> {
    let input =
        load_cell_capacity(old_input_index, Source::Input).map_err(|_| ScriptError::Encoding)?;
    let output = load_cell_capacity(0, Source::GroupOutput).map_err(|_| ScriptError::Encoding)?;
    if input.checked_add(STATE_CARRIER_ACTIVATION_FEE) != Some(output) {
        return Err(ScriptError::StateCarrierMismatch);
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_activation_cell_dep(expected_root: &[u8], expected_outpoint: &[u8]) -> Result<()> {
    if expected_outpoint == UNBOUND_VAULT_OUTPOINT_COMMITMENT {
        return Err(ScriptError::VaultOutPointUnbound);
    }
    let state_outpoint =
        load_input_out_point(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let funding_tx_hash = state_outpoint.tx_hash();
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
fn validate_state_lock_continuity(
    old_index: usize,
    old_source: Source,
    new_index: usize,
    new_source: Source,
) -> Result<()> {
    let old_lock = load_cell_lock(old_index, old_source).map_err(|_| ScriptError::Encoding)?;
    let new_lock = load_cell_lock(new_index, new_source).map_err(|_| ScriptError::Encoding)?;
    if old_lock.code_hash() != new_lock.code_hash() || old_lock.hash_type() != new_lock.hash_type()
    {
        return Err(ScriptError::StateTypeMismatch);
    }
    validate_output_lock_args_bind_output_type(old_index, old_source)?;
    validate_output_lock_args_bind_output_type(new_index, new_source)
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
fn validate_participant_authorisation(header: &StateHeader) -> Result<()> {
    let witness_args = load_witness_args(0, Source::GroupInput)
        .map_err(|_| ScriptError::ParticipantWitnessMissing)?;
    let input_type = witness_args
        .input_type()
        .to_opt()
        .ok_or(ScriptError::ParticipantWitnessMissing)?;
    let raw = input_type.raw_data();
    let witness = BilateralSignatureWitness::parse(raw.as_ref())?;
    verify_bilateral_state_signatures(header, &witness)
}

#[cfg(target_arch = "riscv64")]
fn validate_initial_authorisation(
    new_data: &[u8],
    header: &StateHeader,
    expected_factory_type_hash: Option<&[u8]>,
) -> Result<()> {
    // A newly-created type-script group has no GroupInput. Input zero carries
    // either direct bilateral consent or the Factory exit that materialises
    // this exact child State output.
    let witness_args =
        load_witness_args(0, Source::Input).map_err(|_| ScriptError::ParticipantWitnessMissing)?;
    let input_type = witness_args
        .input_type()
        .to_opt()
        .ok_or(ScriptError::ParticipantWitnessMissing)?;
    let raw = input_type.raw_data();
    match header.mode() {
        STATE_MODE_BILATERAL_PLAINTEXT => {
            if expected_factory_type_hash.is_some() {
                return Err(ScriptError::HeaderContextChanged);
            }
            if raw.len() != BILATERAL_SIGNATURE_WITNESS_LEN {
                return Err(ScriptError::ParticipantWitnessEncoding);
            }
            let witness = BilateralSignatureWitness::parse(raw.as_ref())?;
            verify_bilateral_state_signatures(header, &witness)
        }
        STATE_MODE_FACTORY_PROOF => {
            let factory_type_hash =
                expected_factory_type_hash.ok_or(ScriptError::FactoryLocalExitMismatch)?;
            let envelope = WitnessEnvelope::parse(raw.as_ref())?;
            match envelope.kind() {
                WITNESS_ENVELOPE_KIND_FACTORY_LOCAL_EXIT => {
                    let witness = FactoryLocalExitWitness::parse(envelope.body())?;
                    validate_factory_materialised_state(
                        witness.state_output_index(),
                        witness.state_type_hash(),
                        witness.exit_state_header(),
                        new_data,
                        factory_type_hash,
                    )
                }
                WITNESS_ENVELOPE_KIND_FACTORY_REDUCED_EXIT => {
                    let witness = FactoryReducedExitWitness::parse(envelope.body())?;
                    validate_factory_materialised_state(
                        witness.state_output_index(),
                        witness.state_type_hash(),
                        witness.exit_state_header(),
                        new_data,
                        factory_type_hash,
                    )
                }
                _ => Err(ScriptError::WitnessEnvelopeEncoding),
            }
        }
        _ => Err(ScriptError::HeaderContextChanged),
    }
}

#[cfg(target_arch = "riscv64")]
fn validate_factory_materialised_state(
    state_output_index: u32,
    expected_state_type_hash: &[u8],
    committed_header: &[u8],
    new_data: &[u8],
    expected_factory_type_hash: &[u8],
) -> Result<()> {
    let output_index = state_output_index as usize;
    let script_hash = load_script_hash().map_err(|_| ScriptError::Encoding)?;
    if expected_state_type_hash != script_hash.as_slice() || committed_header != new_data {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }
    let input_factory_type_hash = load_cell_type_hash(0, Source::Input)
        .map_err(|_| ScriptError::FactoryLocalExitMismatch)?
        .ok_or(ScriptError::FactoryLocalExitMismatch)?;
    if input_factory_type_hash.as_slice() != expected_factory_type_hash {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }
    let output_type_hash =
        load_cell_type_hash(output_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    let output_data =
        load_cell_data(output_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    if output_type_hash.as_ref().map(|hash| hash.as_slice()) != Some(script_hash.as_slice())
        || output_data.as_slice() != new_data
    {
        return Err(ScriptError::FactoryLocalExitMismatch);
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_finalise(old_header: &StateHeader, finalise_since: u64) -> Result<()> {
    if old_header.phase() != PHASE_SETTLING {
        return Err(ScriptError::NewStateNotSettling);
    }

    let input = load_input(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let since: u64 = input.since().unpack();
    validate_relative_block_since(since, finalise_since)?;
    find_unique_input_by_vault_reference(
        old_header.vault_materialisation_root(),
        old_header.vault_outpoint_commitment(),
    )?;

    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn find_unique_input_by_vault_reference(
    expected_root: &[u8],
    expected_outpoint: &[u8],
) -> Result<usize> {
    if expected_outpoint == UNBOUND_VAULT_OUTPOINT_COMMITMENT {
        return Err(ScriptError::VaultOutPointUnbound);
    }
    let mut found = None;
    let mut index = 0;
    loop {
        if index >= MAX_WITNESS_INPUTS_PER_TX {
            return Err(ScriptError::Encoding);
        }
        match load_cell_capacity(index, Source::Input) {
            Ok(capacity) => {
                let lock_hash =
                    load_cell_lock_hash(index, Source::Input).map_err(|_| ScriptError::Encoding)?;
                let type_hash =
                    load_cell_type_hash(index, Source::Input).map_err(|_| ScriptError::Encoding)?;
                let data =
                    load_cell_data(index, Source::Input).map_err(|_| ScriptError::Encoding)?;
                let commitment = vault_cell_commitment(
                    lock_hash.as_slice(),
                    capacity,
                    type_hash.as_ref().map(|hash| hash.as_slice()),
                    data.as_slice(),
                );
                let outpoint = load_input_out_point(index, Source::Input)
                    .map_err(|_| ScriptError::Encoding)?;
                let output_index: u32 = outpoint.index().unpack();
                let locator =
                    vault_outpoint_commitment(outpoint.tx_hash().as_slice(), output_index);
                if commitment.as_slice() == expected_root && locator.as_slice() == expected_outpoint
                {
                    if found.is_some() {
                        return Err(ScriptError::StateCellAmbiguous);
                    }
                    found = Some(index);
                }
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    found.ok_or(ScriptError::StateCellMissing)
}

#[cfg(target_arch = "riscv64")]
fn find_unique_output_by_vault_commitment(expected: &[u8]) -> Result<usize> {
    let mut found = None;
    let mut index = 0;
    loop {
        if index >= MAX_WITNESS_INPUTS_PER_TX {
            return Err(ScriptError::Encoding);
        }
        match load_cell_capacity(index, Source::Output) {
            Ok(capacity) => {
                let lock_hash = load_cell_lock_hash(index, Source::Output)
                    .map_err(|_| ScriptError::Encoding)?;
                let type_hash = load_cell_type_hash(index, Source::Output)
                    .map_err(|_| ScriptError::Encoding)?;
                let data =
                    load_cell_data(index, Source::Output).map_err(|_| ScriptError::Encoding)?;
                let commitment = vault_cell_commitment(
                    lock_hash.as_slice(),
                    capacity,
                    type_hash.as_ref().map(|hash| hash.as_slice()),
                    data.as_slice(),
                );
                if commitment.as_slice() == expected {
                    if found.is_some() {
                        return Err(ScriptError::VaultCellAmbiguous);
                    }
                    found = Some(index);
                }
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    found.ok_or(ScriptError::VaultCellMissing)
}

#[cfg(target_arch = "riscv64")]
fn find_splice_witness_raw(
    expected_funding_anchor: &[u8],
    match_old_anchor: bool,
) -> Result<alloc::vec::Vec<u8>> {
    let mut found: Option<alloc::vec::Vec<u8>> = None;
    let mut index = 0;
    loop {
        if index >= MAX_WITNESS_INPUTS_PER_TX {
            return Err(ScriptError::SpliceProofEncoding);
        }
        match load_witness_args(index, Source::Input) {
            Ok(witness_args) => {
                if let Some(input_type) = witness_args.input_type().to_opt() {
                    let raw = input_type.raw_data();
                    if let Ok(witness) = SpliceStateTransitionWitness::parse(raw.as_ref()) {
                        let header = witness.header()?;
                        let anchor = if match_old_anchor {
                            header.old_funding_anchor()
                        } else {
                            header.new_funding_anchor()
                        };
                        if anchor == expected_funding_anchor {
                            if found.is_some() {
                                return Err(ScriptError::SpliceProofEncoding);
                            }
                            found = Some(raw.as_ref().to_vec());
                        }
                    }
                }
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    found.ok_or(ScriptError::SpliceProofEncoding)
}

#[cfg(target_arch = "riscv64")]
fn find_unique_state_cell(
    source: Source,
    current_script: &ckb_std::ckb_types::packed::Script,
    expected_funding_anchor: &[u8],
) -> Result<(usize, alloc::vec::Vec<u8>)> {
    let mut found: Option<(usize, alloc::vec::Vec<u8>)> = None;
    let mut index = 0;
    loop {
        match load_cell_data(index, source) {
            Ok(data) => {
                if let Ok(header) = StateHeader::parse(&data)
                    && header.funding_anchor() == expected_funding_anchor
                    && state_type_script_matches_anchor(
                        current_script,
                        index,
                        source,
                        expected_funding_anchor,
                    )?
                {
                    if found.is_some() {
                        return Err(ScriptError::StateCellAmbiguous);
                    }
                    found = Some((index, data));
                }
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    found.ok_or(ScriptError::StateCellMissing)
}

#[cfg(target_arch = "riscv64")]
fn validate_peer_state_type_script(
    current_script: &ckb_std::ckb_types::packed::Script,
    index: usize,
    source: Source,
    expected_funding_anchor: &[u8],
) -> Result<()> {
    if state_type_script_matches_anchor(current_script, index, source, expected_funding_anchor)? {
        Ok(())
    } else {
        Err(ScriptError::StateTypeMismatch)
    }
}

#[cfg(target_arch = "riscv64")]
fn state_type_script_matches_anchor(
    current_script: &ckb_std::ckb_types::packed::Script,
    index: usize,
    source: Source,
    expected_funding_anchor: &[u8],
) -> Result<bool> {
    let Some(candidate) = load_cell_type(index, source).map_err(|_| ScriptError::Encoding)? else {
        return Ok(false);
    };
    if candidate.code_hash() != current_script.code_hash()
        || candidate.hash_type() != current_script.hash_type()
    {
        return Ok(false);
    }
    let current_args = current_script.args().raw_data();
    let candidate_args = candidate.args().raw_data();
    if candidate_args.len() != current_args.len() || candidate_args.len() < BYTE32_LEN {
        return Ok(false);
    }
    if &candidate_args.as_ref()[..BYTE32_LEN] != expected_funding_anchor {
        return Ok(false);
    }
    Ok(candidate_args.as_ref()[BYTE32_LEN..] == current_args.as_ref()[BYTE32_LEN..])
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
