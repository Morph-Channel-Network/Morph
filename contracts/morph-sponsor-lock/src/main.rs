#![cfg_attr(target_arch = "riscv64", no_std)]
#![cfg_attr(target_arch = "riscv64", no_main)]
#![forbid(unsafe_code)]

#[cfg(target_arch = "riscv64")]
use ckb_std::ckb_constants::Source;
#[cfg(target_arch = "riscv64")]
use ckb_std::error::SysError;
#[cfg(target_arch = "riscv64")]
use ckb_std::high_level::{
    load_cell_capacity, load_cell_data, load_cell_lock_hash, load_cell_type_hash, load_script,
};
#[cfg(target_arch = "riscv64")]
use ckb_std::{default_alloc, entry};
#[cfg(target_arch = "riscv64")]
use morph_script_common::{
    BYTE32_LEN, PHASE_SETTLING, Result, ScriptError, SponsorPolicy, StateHeader,
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
    let policy = SponsorPolicy::parse(args.as_ref())?;
    validate_sponsored_state(&policy)?;

    let sponsor_in = sum_capacity(Source::GroupInput)?;
    let sponsor_out = sum_clean_outputs_by_lock_hash(policy.change_lock())?;
    let sponsor_fee = sponsor_in
        .checked_sub(sponsor_out)
        .ok_or(ScriptError::CapacityUnderflow)?;
    let transaction_fee = sum_capacity(Source::Input)?
        .checked_sub(sum_capacity(Source::Output)?)
        .ok_or(ScriptError::CapacityUnderflow)?;

    if sponsor_fee != transaction_fee {
        return Err(ScriptError::SponsorFeeMismatch);
    }

    if transaction_fee > policy.max_fee_per_tx() {
        return Err(ScriptError::SponsorFeeTooHigh);
    }
    if policy
        .already_spent()
        .checked_add(transaction_fee)
        .ok_or(ScriptError::SponsorBudgetExceeded)?
        > policy.max_total_fee()
    {
        return Err(ScriptError::SponsorBudgetExceeded);
    }
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn validate_sponsored_state(policy: &SponsorPolicy) -> Result<()> {
    let mut sponsored_state: Option<(u64, [u8; BYTE32_LEN])> = None;
    let mut index = 0;
    loop {
        match load_cell_data(index, Source::Output) {
            Ok(data) => {
                if let Ok((channel, anchor, number, phase)) = publication_state_header(&data)
                    && channel == policy.channel_id()
                {
                    if sponsored_state.is_some() {
                        return Err(ScriptError::StateCellAmbiguous);
                    }
                    if phase != PHASE_SETTLING {
                        return Err(ScriptError::NewStateNotSettling);
                    }
                    if number < policy.min_state_number() || number > policy.max_state_number() {
                        return Err(ScriptError::SponsorStateOutOfRange);
                    }
                    let type_hash = load_cell_type_hash(index, Source::Output)
                        .map_err(|_| ScriptError::Encoding)?
                        .ok_or(ScriptError::StateTypeMismatch)?;
                    if type_hash.as_slice() != policy.publication_state_type_hash() {
                        return Err(ScriptError::StateTypeMismatch);
                    }
                    let mut funding_anchor = [0u8; BYTE32_LEN];
                    funding_anchor.copy_from_slice(anchor);
                    sponsored_state = Some((number, funding_anchor));
                }
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    if let Some((_, funding_anchor)) = sponsored_state {
        ensure_publication_backed_by_state_type_input(policy, &funding_anchor)?;
        Ok(())
    } else {
        Err(ScriptError::StateCellMissing)
    }
}

#[cfg(target_arch = "riscv64")]
fn ensure_publication_backed_by_state_type_input(
    policy: &SponsorPolicy,
    output_funding_anchor: &[u8],
) -> Result<()> {
    let mut index = 0;
    loop {
        match load_cell_type_hash(index, Source::Input) {
            Ok(Some(type_hash)) => {
                if type_hash.as_slice() == policy.publication_state_type_hash() {
                    let data =
                        load_cell_data(index, Source::Input).map_err(|_| ScriptError::Encoding)?;
                    let (_, anchor, _, _) = publication_state_header(&data)?;
                    if anchor != output_funding_anchor {
                        return Err(ScriptError::FundingAnchorMismatch);
                    }
                    return Ok(());
                }
                index += 1;
            }
            Ok(None) => index += 1,
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    Err(ScriptError::SponsorStateOutOfRange)
}

#[cfg(target_arch = "riscv64")]
fn publication_state_header(data: &[u8]) -> Result<(&[u8], &[u8], u64, u8)> {
    use morph_script_common::multi_asset::{MULTI_ASSET_STATE_HEADER_LEN, MultiAssetStateHeader};
    if data.len() == MULTI_ASSET_STATE_HEADER_LEN {
        let header = MultiAssetStateHeader::parse(data)?;
        Ok((
            header.channel_id(),
            header.funding_anchor(),
            header.state_number(),
            header.phase(),
        ))
    } else {
        let header = StateHeader::parse(data)?;
        header.validate_profile()?;
        Ok((
            header.channel_id(),
            header.funding_anchor(),
            header.state_number(),
            header.phase(),
        ))
    }
}

#[cfg(target_arch = "riscv64")]
fn sum_capacity(source: Source) -> Result<u64> {
    let mut sum = 0u64;
    let mut index = 0;
    loop {
        match load_cell_capacity(index, source) {
            Ok(capacity) => {
                sum = sum
                    .checked_add(capacity)
                    .ok_or(ScriptError::CapacityUnderflow)?;
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    Ok(sum)
}

#[cfg(target_arch = "riscv64")]
fn sum_clean_outputs_by_lock_hash(expected: &[u8]) -> Result<u64> {
    let mut sum = 0u64;
    let mut index = 0;
    loop {
        match load_cell_lock_hash(index, Source::Output) {
            Ok(lock_hash) => {
                if lock_hash.as_slice() == expected {
                    let type_hash = load_cell_type_hash(index, Source::Output)
                        .map_err(|_| ScriptError::Encoding)?;
                    let data =
                        load_cell_data(index, Source::Output).map_err(|_| ScriptError::Encoding)?;
                    if type_hash.is_some() || !data.is_empty() {
                        return Err(ScriptError::SponsorBudgetExceeded);
                    }
                    let capacity = load_cell_capacity(index, Source::Output)
                        .map_err(|_| ScriptError::Encoding)?;
                    sum = sum
                        .checked_add(capacity)
                        .ok_or(ScriptError::CapacityUnderflow)?;
                }
                index += 1;
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => break,
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    Ok(sum)
}
