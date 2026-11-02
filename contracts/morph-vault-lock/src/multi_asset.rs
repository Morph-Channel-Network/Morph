use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::prelude::*;
use ckb_std::error::SysError;
use ckb_std::high_level::{
    load_cell_data, load_cell_lock_hash, load_cell_type_hash, load_input, load_script_hash,
};
use morph_script_common::multi_asset::{
    MultiAssetStateHeader, MultiAssetVaultArgs, MultiAssetWitness,
};
use morph_script_common::multi_asset_runtime::{
    MULTI_ASSET_MAX_TRANSACTION_CELLS, multi_asset_evidence, verify_multi_asset_settlement_outputs,
    verify_multi_asset_vault_set,
};
use morph_script_common::{PHASE_SETTLING, Result, ScriptError, validate_relative_block_since};

pub fn validate(raw_args: &[u8]) -> Result<()> {
    let args = MultiAssetVaultArgs::parse(raw_args)?;
    let mut state_index = None;
    let mut ended = false;
    for index in 0..MULTI_ASSET_MAX_TRANSACTION_CELLS {
        match load_cell_type_hash(index, Source::Input) {
            Ok(hash) => {
                if hash.as_ref().map(|hash| hash.as_slice()) != Some(args.state_type_hash()) {
                    continue;
                }
                if state_index.is_some() {
                    return Err(ScriptError::StateCellAmbiguous);
                }
                state_index = Some(index);
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => {
                ended = true;
                break;
            }
            Err(_) => return Err(ScriptError::Encoding),
        }
    }
    if !ended {
        return Err(ScriptError::MultiAssetEncoding);
    }
    let state_index = state_index.ok_or(ScriptError::StateCellMissing)?;
    if load_cell_lock_hash(state_index, Source::Input)
        .map_err(|_| ScriptError::Encoding)?
        .as_slice()
        != args.state_lock_hash()
    {
        return Err(ScriptError::StateTypeMismatch);
    }
    let state_data =
        load_cell_data(state_index, Source::Input).map_err(|_| ScriptError::Encoding)?;
    let header = MultiAssetStateHeader::parse(&state_data)?;
    if header.funding_anchor() != args.funding_anchor() {
        return Err(ScriptError::FundingAnchorMismatch);
    }
    if let Some(raw) = morph_script_common::multi_asset_splice_runtime::splice_evidence(
        state_index,
        Source::Input,
    )? {
        if state_index != 0 {
            return Err(ScriptError::MultiAssetSpliceMismatch);
        }
        return morph_script_common::multi_asset_splice_runtime::verify_splice(&raw);
    }
    if header.phase() != PHASE_SETTLING || !header.vaults_are_bound() {
        return Err(ScriptError::NewStateNotSettling);
    }
    let state_input = load_input(state_index, Source::Input).map_err(|_| ScriptError::Encoding)?;
    validate_relative_block_since(state_input.since().unpack(), args.finalise_since())?;
    ended = false;
    for index in 0..MULTI_ASSET_MAX_TRANSACTION_CELLS {
        match load_cell_type_hash(index, Source::Output) {
            Ok(hash) => {
                if hash.as_ref().map(|hash| hash.as_slice()) == Some(args.state_type_hash()) {
                    return Err(ScriptError::WrongGroupShape);
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
        return Err(ScriptError::MultiAssetEncoding);
    }
    let evidence_raw = multi_asset_evidence(state_index, Source::Input)?;
    let evidence = MultiAssetWitness::parse(&evidence_raw)?;
    evidence.validate_header(&header)?;
    if evidence.manifest().entry(0)?.lock_hash
        != load_script_hash().map_err(|_| ScriptError::Encoding)?
    {
        return Err(ScriptError::MultiAssetCommitmentMismatch);
    }
    verify_multi_asset_vault_set(&evidence, Source::Input, true)?;
    verify_multi_asset_settlement_outputs(&evidence, state_index, Source::Input)
}
