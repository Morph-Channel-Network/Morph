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
    load_cell_capacity, load_cell_data, load_cell_lock, load_cell_lock_hash, load_cell_type,
    load_cell_type_hash, load_input, load_input_out_point, load_script, load_witness_args,
};
#[cfg(target_arch = "riscv64")]
use ckb_std::{default_alloc, entry};
#[cfg(target_arch = "riscv64")]
use morph_script_common::{
    BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_LEN, BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_VERSION,
    BILATERAL_CKB_DESCRIPTOR_LEN, BILATERAL_CKB_XUDT_DESCRIPTOR_LEN, BYTE32_LEN,
    BilateralCkbConditionalDescriptor, BilateralCkbSettlementDescriptor,
    BilateralCkbXudtSettlementDescriptor, PHASE_ACTIVE, PHASE_SETTLING, Result, ScriptError,
    SpliceAssetDelta, SpliceAssetDeltas, SpliceHeader, SpliceStateTransitionWitness,
    SpliceVaultDescriptor, StateHeader, UNBOUND_VAULT_OUTPOINT_COMMITMENT, VAULT_ASSET_KIND_CKB,
    VAULT_ASSET_KIND_XUDT, read_u64, read_u128, validate_relative_block_since,
    vault_cell_commitment, vault_outpoint_commitment, verify_splice_state_transition_bundle,
};

#[cfg(target_arch = "riscv64")]
const BATCH_IDENTITY_OFFSET: usize = BYTE32_LEN + 8 + BYTE32_LEN + 1 + BYTE32_LEN + 1;
#[cfg(target_arch = "riscv64")]
const VAULT_ARGS_LEN: usize = BATCH_IDENTITY_OFFSET + BYTE32_LEN + 1;
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
    if args
        .as_ref()
        .starts_with(morph_script_common::multi_asset::MULTI_ASSET_VAULT_ARGS_MAGIC)
    {
        return multi_asset::validate(args.as_ref());
    }
    if args.len() != VAULT_ARGS_LEN {
        return Err(ScriptError::WrongArgsLength);
    }
    let expected_funding_anchor = &args.as_ref()[..BYTE32_LEN];
    let min_since = read_u64(args.as_ref(), BYTE32_LEN);
    let state_type_code_hash = &args.as_ref()[BYTE32_LEN + 8..BYTE32_LEN + 8 + BYTE32_LEN];
    let state_type_hash_type = args.as_ref()[BYTE32_LEN + 8 + BYTE32_LEN];
    let state_lock_code_hash =
        &args.as_ref()[BYTE32_LEN + 8 + BYTE32_LEN + 1..BYTE32_LEN + 8 + 2 * BYTE32_LEN + 1];
    let state_lock_hash_type = args.as_ref()[BYTE32_LEN + 8 + 2 * BYTE32_LEN + 1];

    let (state_index, state_data) = find_unique_state_input(
        expected_funding_anchor,
        min_since,
        state_type_code_hash,
        state_type_hash_type,
        state_lock_code_hash,
        state_lock_hash_type,
    )?;
    let header = StateHeader::parse(&state_data)?;
    header.validate_profile()?;
    validate_current_vault_commitment(
        header.vault_materialisation_root(),
        header.vault_outpoint_commitment(),
    )?;
    if header.phase() == PHASE_ACTIVE {
        validate_splice_vault_spend(
            &script,
            state_index,
            &header,
            expected_funding_anchor,
            state_lock_code_hash,
            state_lock_hash_type,
        )?;
        return Ok(());
    }
    if header.phase() != PHASE_SETTLING {
        return Err(ScriptError::NewStateNotSettling);
    }

    let input = load_input(state_index, Source::Input).map_err(|_| ScriptError::Encoding)?;
    let since: u64 = input.since().unpack();
    validate_relative_block_since(since, min_since)?;
    let witness_args = load_witness_args(0, Source::GroupInput)
        .map_err(|_| ScriptError::SettlementWitnessMissing)?;
    let input_type = witness_args
        .input_type()
        .to_opt()
        .ok_or(ScriptError::SettlementWitnessMissing)?;
    let descriptor_raw = input_type.raw_data();
    match descriptor_raw.len() {
        BILATERAL_CKB_DESCRIPTOR_LEN => {
            let descriptor = BilateralCkbSettlementDescriptor::parse(descriptor_raw.as_ref())?;
            if header.descriptor_version() != morph_script_common::BILATERAL_CKB_DESCRIPTOR_VERSION
                || header.settlement_descriptor_commitment() != descriptor.commitment().as_slice()
            {
                return Err(ScriptError::SettlementDescriptorMismatch);
            }
            ensure_no_group_xudt(Source::GroupInput)?;
            let vault_capacity = sum_group_capacity(Source::GroupInput)?;
            if descriptor.checked_total_capacity()? != vault_capacity {
                return Err(ScriptError::SettlementOutputMismatch);
            }
            verify_ckb_descriptor_outputs(&descriptor)?;
        }
        BILATERAL_CKB_XUDT_DESCRIPTOR_LEN => {
            let descriptor = BilateralCkbXudtSettlementDescriptor::parse(descriptor_raw.as_ref())?;
            if header.descriptor_version()
                != morph_script_common::BILATERAL_CKB_XUDT_DESCRIPTOR_VERSION
                || header.settlement_descriptor_commitment() != descriptor.commitment().as_slice()
            {
                return Err(ScriptError::SettlementDescriptorMismatch);
            }
            let vault_capacity = sum_group_capacity(Source::GroupInput)?;
            if descriptor.checked_total_capacity()? != vault_capacity {
                return Err(ScriptError::SettlementOutputMismatch);
            }
            verify_ckb_xudt_descriptor_outputs(&descriptor)?;
        }
        BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_LEN => {
            let descriptor = BilateralCkbConditionalDescriptor::parse(descriptor_raw.as_ref())?;
            if header.descriptor_version() != BILATERAL_CKB_CONDITIONAL_DESCRIPTOR_VERSION
                || header.settlement_descriptor_commitment() != descriptor.commitment().as_slice()
            {
                return Err(ScriptError::SettlementDescriptorMismatch);
            }
            ensure_no_group_xudt(Source::GroupInput)?;
            let vault_capacity = sum_group_capacity(Source::GroupInput)?;
            if descriptor.checked_total_capacity()? != vault_capacity {
                return Err(ScriptError::ConditionalValueMismatch);
            }
            if descriptor.transfer_count() == 0 {
                verify_exact_plain_output(descriptor.lock_hash(0), descriptor.settled_capacity(0))?;
                verify_exact_plain_output(descriptor.lock_hash(1), descriptor.settled_capacity(1))?;
            } else {
                verify_conditional_batch_output(
                    &descriptor,
                    &header,
                    &args.as_ref()[BATCH_IDENTITY_OFFSET..VAULT_ARGS_LEN],
                    vault_capacity,
                )?;
            }
        }
        _ => return Err(ScriptError::SettlementDescriptorEncoding),
    }

    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn verify_conditional_batch_output(
    descriptor: &BilateralCkbConditionalDescriptor,
    header: &StateHeader,
    batch_script_identity: &[u8],
    expected_capacity: u64,
) -> Result<()> {
    let expected_code_hash = &batch_script_identity[..BYTE32_LEN];
    let expected_hash_type = batch_script_identity[BYTE32_LEN];
    let mut expected_args = [0u8; BYTE32_LEN + 8 + BYTE32_LEN];
    expected_args[..BYTE32_LEN].copy_from_slice(header.channel_id());
    expected_args[BYTE32_LEN..BYTE32_LEN + 8].copy_from_slice(&header.state_number().to_le_bytes());
    expected_args[BYTE32_LEN + 8..].copy_from_slice(&descriptor.commitment());

    let mut matches = 0u8;
    let mut index = 0;
    loop {
        match load_cell_lock(index, Source::Output) {
            Ok(lock) => {
                let lock_args = lock.args().raw_data();
                if lock.code_hash().as_slice() == expected_code_hash
                    && lock.hash_type().as_slice()[0] == expected_hash_type
                    && lock_args.as_ref() == expected_args
                {
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

#[cfg(target_arch = "riscv64")]
fn sum_group_capacity(source: Source) -> Result<u64> {
    let mut sum = 0u64;
    let mut index = 0;
    loop {
        match load_cell_capacity(index, source) {
            Ok(capacity) => {
                sum = sum
                    .checked_add(capacity)
                    .ok_or(ScriptError::SettlementOutputMismatch)?;
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    Ok(sum)
}

#[cfg(target_arch = "riscv64")]
fn verify_ckb_descriptor_outputs(descriptor: &BilateralCkbSettlementDescriptor) -> Result<()> {
    for entry in 0..2 {
        verify_exact_plain_output(descriptor.lock_hash(entry), descriptor.capacity(entry))?;
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn verify_ckb_xudt_descriptor_outputs(
    descriptor: &BilateralCkbXudtSettlementDescriptor,
) -> Result<()> {
    let input_amount = sum_group_xudt_amount(Source::GroupInput, descriptor.xudt_type_hash())?;
    if input_amount != descriptor.checked_total_xudt_amount()? {
        return Err(ScriptError::SettlementOutputMismatch);
    }
    for entry in 0..2 {
        verify_exact_xudt_or_plain_output(
            descriptor.lock_hash(entry),
            descriptor.xudt_type_hash(),
            descriptor.capacity(entry),
            descriptor.xudt_amount(entry),
        )?;
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn verify_exact_plain_output(expected_lock: &[u8], expected_capacity: u64) -> Result<()> {
    verify_exact_descriptor_output(expected_lock, expected_capacity, None)
}

#[cfg(target_arch = "riscv64")]
fn verify_exact_xudt_or_plain_output(
    expected_lock: &[u8],
    expected_type_hash: &[u8],
    expected_capacity: u64,
    expected_amount: u128,
) -> Result<()> {
    if expected_amount == 0 {
        verify_exact_descriptor_output(expected_lock, expected_capacity, None)
    } else {
        verify_exact_descriptor_output(
            expected_lock,
            expected_capacity,
            Some((expected_type_hash, expected_amount)),
        )
    }
}

#[cfg(target_arch = "riscv64")]
fn verify_exact_descriptor_output(
    expected_lock: &[u8],
    expected_capacity: u64,
    expected_xudt: Option<(&[u8], u128)>,
) -> Result<()> {
    let mut matches = 0u8;
    let mut index = 0;
    loop {
        match load_cell_lock_hash(index, Source::Output) {
            Ok(lock_hash) => {
                if lock_hash.as_slice() == expected_lock {
                    matches = matches
                        .checked_add(1)
                        .ok_or(ScriptError::SettlementOutputMismatch)?;
                    if matches != 1 {
                        return Err(ScriptError::SettlementOutputMismatch);
                    }
                    let capacity = load_cell_capacity(index, Source::Output)
                        .map_err(|_| ScriptError::Encoding)?;
                    if capacity != expected_capacity {
                        return Err(ScriptError::SettlementOutputMismatch);
                    }
                    let type_hash = load_cell_type_hash(index, Source::Output)
                        .map_err(|_| ScriptError::Encoding)?;
                    let data =
                        load_cell_data(index, Source::Output).map_err(|_| ScriptError::Encoding)?;
                    match expected_xudt {
                        None => {
                            if type_hash.is_some() || !data.is_empty() {
                                return Err(ScriptError::SettlementOutputMismatch);
                            }
                        }
                        Some((expected_type_hash, expected_amount)) => {
                            let type_hash = type_hash.ok_or(ScriptError::XudtTypeMismatch)?;
                            if type_hash.as_slice() != expected_type_hash {
                                return Err(ScriptError::XudtTypeMismatch);
                            }
                            if data.len() != 16 {
                                return Err(ScriptError::XudtAmountEncoding);
                            }
                            if read_u128(&data, 0) != expected_amount {
                                return Err(ScriptError::SettlementOutputMismatch);
                            }
                        }
                    }
                }
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    if matches != 1 {
        return Err(ScriptError::SettlementOutputMismatch);
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn sum_group_xudt_amount(source: Source, expected_type_hash: &[u8]) -> Result<u128> {
    let mut sum = 0u128;
    let mut index = 0;
    loop {
        match load_cell_type_hash(index, source) {
            Ok(Some(type_hash)) => {
                if type_hash.as_slice() != expected_type_hash {
                    return Err(ScriptError::XudtTypeMismatch);
                }
                sum = sum
                    .checked_add(load_xudt_amount(index, source)?)
                    .ok_or(ScriptError::SettlementOutputMismatch)?;
                index += 1;
            }
            Ok(None) => return Err(ScriptError::XudtTypeMismatch),
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    Ok(sum)
}

#[cfg(target_arch = "riscv64")]
fn load_xudt_amount(index: usize, source: Source) -> Result<u128> {
    let data = load_cell_data(index, source).map_err(|_| ScriptError::Encoding)?;
    if data.len() != 16 {
        return Err(ScriptError::XudtAmountEncoding);
    }
    Ok(read_u128(&data, 0))
}

#[cfg(target_arch = "riscv64")]
fn validate_current_vault_commitment(expected: &[u8], expected_outpoint: &[u8]) -> Result<()> {
    if expected_outpoint == UNBOUND_VAULT_OUTPOINT_COMMITMENT {
        return Err(ScriptError::VaultOutPointUnbound);
    }
    let capacity = load_cell_capacity(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    match load_cell_capacity(1, Source::GroupInput) {
        Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => {}
        Err(_) => return Err(ScriptError::Encoding),
        Ok(_) => return Err(ScriptError::WrongGroupShape),
    }
    let lock_hash =
        load_cell_lock_hash(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let type_hash =
        load_cell_type_hash(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let data = load_cell_data(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let commitment = vault_cell_commitment(
        lock_hash.as_slice(),
        capacity,
        type_hash.as_ref().map(|hash| hash.as_slice()),
        data.as_slice(),
    );
    if commitment.as_slice() != expected {
        return Err(ScriptError::SettlementDescriptorMismatch);
    }
    let outpoint =
        load_input_out_point(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let output_index: u32 = outpoint.index().unpack();
    let locator = vault_outpoint_commitment(outpoint.tx_hash().as_slice(), output_index);
    if locator.as_slice() != expected_outpoint {
        return Err(ScriptError::VaultOutPointMismatch);
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn find_unique_state_input(
    expected_funding_anchor: &[u8],
    expected_min_since: u64,
    expected_type_code_hash: &[u8],
    expected_type_hash_type: u8,
    expected_lock_code_hash: &[u8],
    expected_lock_hash_type: u8,
) -> Result<(usize, alloc::vec::Vec<u8>)> {
    // The vault-lock group contains vault cells, not the peer State type cell.
    // Scan transaction inputs, then require exact State header anchor plus
    // State type/lock-script binding and reject duplicates.
    let mut found: Option<(usize, alloc::vec::Vec<u8>)> = None;
    let mut index = 0;
    loop {
        match load_cell_data(index, Source::Input) {
            Ok(data) => {
                if let Ok(header) = StateHeader::parse(&data)
                    && header.funding_anchor() == expected_funding_anchor
                    && state_cell_scripts_match(
                        index,
                        Source::Input,
                        expected_funding_anchor,
                        expected_min_since,
                        (expected_type_code_hash, expected_type_hash_type),
                        (expected_lock_code_hash, expected_lock_hash_type),
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
fn validate_splice_vault_spend(
    current_script: &ckb_std::ckb_types::packed::Script,
    state_index: usize,
    old_header: &StateHeader,
    expected_funding_anchor: &[u8],
    expected_lock_code_hash: &[u8],
    expected_lock_hash_type: u8,
) -> Result<()> {
    let witness_raw = find_splice_witness_raw(expected_funding_anchor)?;
    let witness = SpliceStateTransitionWitness::parse(&witness_raw)
        .map_err(|_| ScriptError::SpliceProofEncoding)?;
    let splice_header = witness.header()?;
    let new_data = find_unique_state_output_for_splice(
        state_index,
        splice_header.new_funding_anchor(),
        expected_lock_code_hash,
        expected_lock_hash_type,
    )?;
    let new_header = StateHeader::parse(&new_data)?;
    verify_splice_state_transition_bundle(old_header, &new_header, &witness)?;

    let old_vault = witness.old_vault()?;
    let new_vault = witness.new_vault()?;
    validate_old_vault_inputs(&old_vault)?;
    let new_vault_commitment = validate_new_vault_output(current_script, &new_vault)?;
    if new_header.vault_materialisation_root() != new_vault_commitment.as_slice() {
        return Err(ScriptError::SpliceProofMismatch);
    }
    let deltas = witness.deltas()?;
    validate_splice_withdrawal_outputs(&splice_header, &deltas)?;
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_splice_withdrawal_outputs(
    header: &SpliceHeader,
    deltas: &SpliceAssetDeltas,
) -> Result<()> {
    for index in 0..deltas.delta_count() as usize {
        let delta = deltas.delta(index)?;
        if delta.withdrawal() != 0 {
            validate_splice_withdrawal_output(header.withdrawal_lock_hash(), &delta)?;
        }
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_splice_withdrawal_output(
    expected_lock_hash: &[u8],
    delta: &SpliceAssetDelta,
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
                        _ => return Err(ScriptError::SpliceProofEncoding),
                    };
                    if matches {
                        if found {
                            return Err(ScriptError::SpliceProofMismatch);
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
        return Err(ScriptError::SpliceProofMismatch);
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn find_splice_witness_raw(expected_old_funding_anchor: &[u8]) -> Result<alloc::vec::Vec<u8>> {
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
                        if header.old_funding_anchor() == expected_old_funding_anchor {
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
fn find_unique_state_output_for_splice(
    state_input_index: usize,
    expected_funding_anchor: &[u8],
    expected_lock_code_hash: &[u8],
    expected_lock_hash_type: u8,
) -> Result<alloc::vec::Vec<u8>> {
    let Some(base_type) =
        load_cell_type(state_input_index, Source::Input).map_err(|_| ScriptError::Encoding)?
    else {
        return Err(ScriptError::StateTypeMismatch);
    };

    let mut found: Option<alloc::vec::Vec<u8>> = None;
    let mut index = 0;
    loop {
        match load_cell_data(index, Source::Output) {
            Ok(data) => {
                if let Ok(header) = StateHeader::parse(&data)
                    && header.funding_anchor() == expected_funding_anchor
                    && state_type_script_matches_anchor(
                        &base_type,
                        index,
                        Source::Output,
                        expected_funding_anchor,
                    )?
                    && state_lock_script_matches_type(
                        index,
                        Source::Output,
                        expected_lock_code_hash,
                        expected_lock_hash_type,
                    )?
                {
                    if found.is_some() {
                        return Err(ScriptError::StateCellAmbiguous);
                    }
                    found = Some(data);
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
fn state_cell_scripts_match(
    index: usize,
    source: Source,
    expected_funding_anchor: &[u8],
    expected_min_since: u64,
    expected_type: (&[u8], u8),
    expected_lock: (&[u8], u8),
) -> Result<bool> {
    let (expected_type_code_hash, expected_type_hash_type) = expected_type;
    let (expected_lock_code_hash, expected_lock_hash_type) = expected_lock;
    let Some(state_type) = load_cell_type(index, source).map_err(|_| ScriptError::Encoding)? else {
        return Ok(false);
    };
    if state_type.code_hash().as_slice() != expected_type_code_hash
        || state_type.hash_type().as_slice()[0] != expected_type_hash_type
    {
        return Ok(false);
    }
    let type_args = state_type.args().raw_data();
    if type_args.len() < BYTE32_LEN || &type_args.as_ref()[..BYTE32_LEN] != expected_funding_anchor
    {
        return Ok(false);
    }
    let since_offset = match type_args.len() {
        len if len == BYTE32_LEN + 8 => BYTE32_LEN,
        len if len == 2 * BYTE32_LEN + 8 => 2 * BYTE32_LEN,
        _ => return Ok(false),
    };
    let expected_since = expected_min_since.to_le_bytes();
    if type_args.as_ref()[since_offset..] != expected_since {
        return Ok(false);
    }
    state_lock_script_matches_type(
        index,
        source,
        expected_lock_code_hash,
        expected_lock_hash_type,
    )
}

#[cfg(target_arch = "riscv64")]
fn state_lock_script_matches_type(
    index: usize,
    source: Source,
    expected_lock_code_hash: &[u8],
    expected_lock_hash_type: u8,
) -> Result<bool> {
    let state_type_hash = load_cell_type_hash(index, source).map_err(|_| ScriptError::Encoding)?;
    let Some(state_type_hash) = state_type_hash else {
        return Ok(false);
    };
    let lock = load_cell_lock(index, source).map_err(|_| ScriptError::Encoding)?;
    if lock.code_hash().as_slice() != expected_lock_code_hash
        || lock.hash_type().as_slice()[0] != expected_lock_hash_type
    {
        return Ok(false);
    }
    let lock_args = lock.args().raw_data();
    Ok(lock_args.as_ref() == state_type_hash.as_slice())
}

#[cfg(target_arch = "riscv64")]
fn state_type_script_matches_anchor(
    base_script: &ckb_std::ckb_types::packed::Script,
    index: usize,
    source: Source,
    expected_funding_anchor: &[u8],
) -> Result<bool> {
    let Some(candidate) = load_cell_type(index, source).map_err(|_| ScriptError::Encoding)? else {
        return Ok(false);
    };
    script_matches_anchor(base_script, &candidate, expected_funding_anchor)
}

#[cfg(target_arch = "riscv64")]
fn lock_script_matches_anchor(
    base_script: &ckb_std::ckb_types::packed::Script,
    index: usize,
    source: Source,
    expected_funding_anchor: &[u8],
) -> Result<bool> {
    let candidate = load_cell_lock(index, source).map_err(|_| ScriptError::Encoding)?;
    script_matches_anchor(base_script, &candidate, expected_funding_anchor)
}

#[cfg(target_arch = "riscv64")]
fn script_matches_anchor(
    base_script: &ckb_std::ckb_types::packed::Script,
    candidate: &ckb_std::ckb_types::packed::Script,
    expected_funding_anchor: &[u8],
) -> Result<bool> {
    if candidate.code_hash() != base_script.code_hash()
        || candidate.hash_type() != base_script.hash_type()
    {
        return Ok(false);
    }
    let base_args = base_script.args().raw_data();
    let candidate_args = candidate.args().raw_data();
    if candidate_args.len() != base_args.len() || candidate_args.len() < BYTE32_LEN {
        return Ok(false);
    }
    if &candidate_args.as_ref()[..BYTE32_LEN] != expected_funding_anchor {
        return Ok(false);
    }
    Ok(candidate_args.as_ref()[BYTE32_LEN..] == base_args.as_ref()[BYTE32_LEN..])
}

#[cfg(target_arch = "riscv64")]
fn validate_old_vault_inputs(descriptor: &SpliceVaultDescriptor) -> Result<()> {
    let assets = descriptor_assets(descriptor)?;
    let capacity = sum_group_capacity(Source::GroupInput)? as u128;
    if capacity != assets.ckb_amount {
        return Err(ScriptError::SpliceProofMismatch);
    }

    match assets.xudt {
        Some((type_hash, amount)) => {
            if sum_group_xudt_amount_for_type(Source::GroupInput, type_hash)? != amount {
                return Err(ScriptError::SpliceProofMismatch);
            }
        }
        None => ensure_no_group_xudt(Source::GroupInput)?,
    }

    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_new_vault_output(
    current_script: &ckb_std::ckb_types::packed::Script,
    descriptor: &SpliceVaultDescriptor,
) -> Result<[u8; 32]> {
    let assets = descriptor_assets(descriptor)?;
    let output_index = single_vault_output_index(current_script, descriptor.funding_anchor())?;
    let capacity =
        load_cell_capacity(output_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    if capacity as u128 != assets.ckb_amount {
        return Err(ScriptError::SpliceProofMismatch);
    }

    let output_type_hash =
        load_cell_type_hash(output_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    let data = load_cell_data(output_index, Source::Output).map_err(|_| ScriptError::Encoding)?;
    match assets.xudt {
        Some((expected_type_hash, amount)) => {
            let actual_type_hash =
                type_hash_for_required_xudt(output_type_hash, expected_type_hash)?;
            if data.len() != 16 {
                return Err(ScriptError::XudtAmountEncoding);
            }
            if read_u128(&data, 0) != amount {
                return Err(ScriptError::SpliceProofMismatch);
            }
            let lock_hash = load_cell_lock_hash(output_index, Source::Output)
                .map_err(|_| ScriptError::Encoding)?;
            Ok(vault_cell_commitment(
                lock_hash.as_slice(),
                capacity,
                Some(actual_type_hash.as_slice()),
                data.as_slice(),
            ))
        }
        None => {
            if output_type_hash.is_some() {
                return Err(ScriptError::XudtTypeMismatch);
            }
            if !data.is_empty() {
                return Err(ScriptError::SpliceProofMismatch);
            }
            let lock_hash = load_cell_lock_hash(output_index, Source::Output)
                .map_err(|_| ScriptError::Encoding)?;
            Ok(vault_cell_commitment(
                lock_hash.as_slice(),
                capacity,
                None,
                data.as_slice(),
            ))
        }
    }
}

#[cfg(target_arch = "riscv64")]
fn type_hash_for_required_xudt(actual: Option<[u8; 32]>, expected: &[u8]) -> Result<[u8; 32]> {
    let actual = actual.ok_or(ScriptError::XudtTypeMismatch)?;
    if actual.as_slice() != expected {
        return Err(ScriptError::XudtTypeMismatch);
    }
    Ok(actual)
}

#[cfg(target_arch = "riscv64")]
struct DescriptorAssets<'a> {
    ckb_amount: u128,
    xudt: Option<(&'a [u8], u128)>,
}

#[cfg(target_arch = "riscv64")]
fn descriptor_assets<'a>(descriptor: &SpliceVaultDescriptor<'a>) -> Result<DescriptorAssets<'a>> {
    let mut ckb_amount: Option<u128> = None;
    let mut xudt: Option<(&'a [u8], u128)> = None;

    for index in 0..descriptor.asset_count() as usize {
        let asset = descriptor.asset(index)?;
        match asset.asset_kind() {
            VAULT_ASSET_KIND_CKB => {
                if ckb_amount.is_some() {
                    return Err(ScriptError::SpliceProofMismatch);
                }
                ckb_amount = Some(asset.amount());
            }
            VAULT_ASSET_KIND_XUDT => {
                if xudt.is_some() {
                    return Err(ScriptError::SpliceProofMismatch);
                }
                xudt = Some((asset.asset_type(), asset.amount()));
            }
            _ => return Err(ScriptError::SpliceProofEncoding),
        }
    }

    Ok(DescriptorAssets {
        ckb_amount: ckb_amount.ok_or(ScriptError::SpliceProofMismatch)?,
        xudt,
    })
}

#[cfg(target_arch = "riscv64")]
fn single_vault_output_index(
    current_script: &ckb_std::ckb_types::packed::Script,
    expected_funding_anchor: &[u8],
) -> Result<usize> {
    let mut found = None;
    let mut index = 0;
    loop {
        match load_cell_capacity(index, Source::Output) {
            Ok(_) => {
                if lock_script_matches_anchor(
                    current_script,
                    index,
                    Source::Output,
                    expected_funding_anchor,
                )? {
                    if found.is_some() {
                        return Err(ScriptError::SpliceProofMismatch);
                    }
                    found = Some(index);
                }
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    found.ok_or(ScriptError::SpliceProofMismatch)
}

#[cfg(target_arch = "riscv64")]
fn sum_group_xudt_amount_for_type(source: Source, expected_type_hash: &[u8]) -> Result<u128> {
    let mut sum = 0u128;
    let mut index = 0;
    loop {
        match load_cell_type_hash(index, source) {
            Ok(Some(type_hash)) => {
                if type_hash.as_slice() != expected_type_hash {
                    return Err(ScriptError::XudtTypeMismatch);
                }
                sum = sum
                    .checked_add(load_xudt_amount(index, source)?)
                    .ok_or(ScriptError::SpliceProofMismatch)?;
                index += 1;
            }
            Ok(None) => {
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    Ok(sum)
}

#[cfg(target_arch = "riscv64")]
fn ensure_no_group_xudt(source: Source) -> Result<()> {
    let mut index = 0;
    loop {
        match load_cell_type_hash(index, source) {
            Ok(Some(_)) => return Err(ScriptError::XudtTypeMismatch),
            Ok(None) => index += 1,
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    Ok(())
}
