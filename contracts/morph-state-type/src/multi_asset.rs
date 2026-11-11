use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::packed::Script;
use ckb_std::ckb_types::prelude::*;
use ckb_std::high_level::{
    load_cell_capacity, load_cell_lock_hash, load_cell_type_hash, load_input, load_input_out_point,
    load_transaction, load_tx_hash, load_witness_args,
};
use morph_script_common::multi_asset::{
    MultiAssetStateHeader, MultiAssetVaultArgs, MultiAssetWitness, multi_asset_occupied_capacity,
};
use morph_script_common::multi_asset_runtime::{
    multi_asset_evidence, verify_multi_asset_settlement_outputs, verify_multi_asset_vault_at,
    verify_multi_asset_vault_set,
};
use morph_script_common::{
    BilateralSignatureWitness, PHASE_ACTIVE, PHASE_SETTLING, Result, ScriptError,
    validate_relative_block_since,
};

fn signatures(header: &MultiAssetStateHeader, source: Source) -> Result<()> {
    let witness =
        load_witness_args(0, source).map_err(|_| ScriptError::ParticipantWitnessMissing)?;
    let signatures = witness
        .input_type()
        .to_opt()
        .ok_or(ScriptError::ParticipantWitnessMissing)?;
    let raw = signatures.raw_data();
    header.verify_signatures(&BilateralSignatureWitness::parse(&raw)?)
}

fn bind_vault_lock(
    evidence: &MultiAssetWitness,
    anchor: &[u8],
    since: u64,
    state_source: Source,
) -> Result<()> {
    let script =
        Script::from_slice(evidence.scripts().script(3)?).map_err(|_| ScriptError::Encoding)?;
    let args_raw = script.args().raw_data();
    let args = MultiAssetVaultArgs::parse(&args_raw)?;
    if args.funding_anchor() != anchor
        || args.finalise_since() != since
        || load_cell_type_hash(0, state_source)
            .map_err(|_| ScriptError::Encoding)?
            .as_ref()
            .map(|hash| hash.as_slice())
            != Some(args.state_type_hash())
        || load_cell_lock_hash(0, state_source)
            .map_err(|_| ScriptError::Encoding)?
            .as_slice()
            != args.state_lock_hash()
    {
        return Err(ScriptError::MultiAssetCommitmentMismatch);
    }
    let carrier = load_cell_capacity(0, state_source).map_err(|_| ScriptError::Encoding)?;
    if multi_asset_occupied_capacity(evidence.scripts().script(2)?, None, 0)? > carrier {
        return Err(ScriptError::MultiAssetCapacityMismatch);
    }
    Ok(())
}

pub fn validate(
    anchor: &[u8],
    since: u64,
    old: Option<&[u8]>,
    new: Option<&[u8]>,
    factory_origin: Option<&[u8]>,
) -> Result<()> {
    match (old, new) {
        (None, Some(raw)) => {
            let header = MultiAssetStateHeader::parse(raw)?;
            let base = header;
            if base.funding_anchor() != anchor
                || base.phase() != PHASE_ACTIVE
                || base.state_number() != 0
                || header.vaults_are_bound()
            {
                return Err(ScriptError::VaultActivationInvalid);
            }
            if let Some(raw) =
                morph_script_common::multi_asset_splice_runtime::splice_evidence(0, Source::Input)?
            {
                morph_script_common::multi_asset_splice_runtime::verify_splice_gate(&raw)?;
                signatures(&header, Source::Input)?;
            } else if let Some(factory_origin) = factory_origin {
                let raw =
                    morph_script_common::factory_multi_asset_runtime::materialisation_evidence()?
                        .ok_or(ScriptError::FactoryMultiAssetPartitionMismatch)?;
                let child =
                    morph_script_common::factory_multi_asset_runtime::verify_child_creation(
                        &raw,
                        &header,
                        &ckb_std::high_level::load_script_hash()
                            .map_err(|_| ScriptError::Encoding)?,
                        factory_origin,
                    )?;
                super::validate_anchor_derivation(anchor)?;
                super::validate_output_lock_args_bind_output_type(0, Source::GroupOutput)?;
                bind_vault_lock(&child.evidence, anchor, since, Source::GroupOutput)?;
                let positions =
                    verify_multi_asset_vault_set(&child.evidence, Source::Output, false)?;
                let tx_hash = load_tx_hash().map_err(|_| ScriptError::Encoding)?;
                for (i, position) in positions
                    .iter()
                    .enumerate()
                    .take(child.evidence.manifest().count())
                {
                    let point = child.evidence.outpoint(i)?;
                    if point[..32] != tx_hash
                        || morph_script_common::read_u32(point, 32) as usize != *position
                    {
                        return Err(ScriptError::VaultOutPointMismatch);
                    }
                }
                return super::validate_group_output_capacity();
            } else {
                let witness = load_witness_args(0, Source::Input)
                    .map_err(|_| ScriptError::ParticipantWitnessMissing)?;
                let raw = witness
                    .input_type()
                    .to_opt()
                    .ok_or(ScriptError::ParticipantWitnessMissing)?
                    .raw_data();
                header.verify_root_funding_signatures(
                    &load_tx_hash().map_err(|_| ScriptError::Encoding)?,
                    &BilateralSignatureWitness::parse(&raw)?,
                )?;
            }
            super::validate_anchor_derivation(anchor)?;
            super::validate_output_lock_args_bind_output_type(0, Source::GroupOutput)?;
            let evidence_raw = multi_asset_evidence(0, Source::Input)?;
            let evidence = MultiAssetWitness::parse(&evidence_raw)?;
            evidence.validate_header(&header)?;
            bind_vault_lock(&evidence, anchor, since, Source::GroupOutput)?;
            verify_multi_asset_vault_set(&evidence, Source::Output, false)?;
            super::validate_group_output_capacity()
        }
        (Some(old_raw), Some(new_raw)) => {
            let old = MultiAssetStateHeader::parse(old_raw)?;
            let new = MultiAssetStateHeader::parse(new_raw)?;
            if old.funding_anchor() != anchor || new.funding_anchor() != anchor {
                return Err(ScriptError::FundingAnchorMismatch);
            }
            super::validate_output_lock_preserved()?;
            super::validate_output_lock_args_bind_output_type(0, Source::GroupInput)?;
            super::validate_preserved_carrier_capacity()?;
            let evidence_raw = multi_asset_evidence(0, Source::GroupInput)?;
            let evidence = MultiAssetWitness::parse(&evidence_raw)?;
            evidence.validate_header(&new)?;
            bind_vault_lock(&evidence, anchor, since, Source::GroupOutput)?;
            if !old.vaults_are_bound() {
                if !old.is_activation_to(&new) {
                    return Err(ScriptError::VaultActivationInvalid);
                }
                activate(&evidence)?;
            } else {
                if !old.same_context_except_progress(&new) {
                    return Err(ScriptError::HeaderContextChanged);
                }
                if new.state_number() <= old.state_number() {
                    return Err(ScriptError::NonMonotonicStateNumber);
                }
                if new.phase() != PHASE_SETTLING {
                    return Err(ScriptError::NewStateNotSettling);
                }
                signatures(&new, Source::GroupInput)?;
            }
            super::validate_group_output_capacity()
        }
        (Some(raw), None) => {
            let header = MultiAssetStateHeader::parse(raw)?;
            if header.funding_anchor() != anchor {
                return Err(ScriptError::FundingAnchorMismatch);
            }
            if let Some(raw) = morph_script_common::multi_asset_close_runtime::close_evidence(
                0,
                Source::GroupInput,
            )? {
                if load_input_out_point(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?
                    != load_input_out_point(0, Source::Input).map_err(|_| ScriptError::Encoding)?
                {
                    return Err(ScriptError::MultiAssetCloseMismatch);
                }
                super::validate_output_lock_args_bind_output_type(0, Source::GroupInput)?;
                return morph_script_common::multi_asset_close_runtime::verify_close(&raw);
            }
            if let Some(raw) = morph_script_common::multi_asset_splice_runtime::splice_evidence(
                0,
                Source::GroupInput,
            )? {
                if load_input_out_point(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?
                    != load_input_out_point(0, Source::Input).map_err(|_| ScriptError::Encoding)?
                {
                    return Err(ScriptError::MultiAssetSpliceMismatch);
                }
                super::validate_output_lock_args_bind_output_type(0, Source::GroupInput)?;
                return morph_script_common::multi_asset_splice_runtime::verify_splice(&raw);
            }
            if header.phase() != PHASE_SETTLING || !header.vaults_are_bound() {
                return Err(ScriptError::NewStateNotSettling);
            }
            super::validate_output_lock_args_bind_output_type(0, Source::GroupInput)?;
            let input = load_input(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
            validate_relative_block_since(input.since().unpack(), since)?;
            let evidence_raw = multi_asset_evidence(0, Source::GroupInput)?;
            let evidence = MultiAssetWitness::parse(&evidence_raw)?;
            evidence.validate_header(&header)?;
            bind_vault_lock(&evidence, anchor, since, Source::GroupInput)?;
            verify_multi_asset_vault_set(&evidence, Source::Input, true)?;
            verify_multi_asset_settlement_outputs(&evidence, 0, Source::GroupInput, &header)
        }
        _ => Err(ScriptError::WrongGroupShape),
    }
}

fn activate(evidence: &MultiAssetWitness) -> Result<()> {
    let state_point =
        load_input_out_point(0, Source::GroupInput).map_err(|_| ScriptError::Encoding)?;
    let transaction = load_transaction().map_err(|_| ScriptError::Encoding)?;
    let deps = transaction.raw().cell_deps();
    for i in 0..evidence.manifest().count() {
        let dep = deps.get(i).ok_or(ScriptError::VaultOutPointMismatch)?;
        if dep.dep_type().as_slice() != [0]
            || dep.out_point().as_slice() != evidence.outpoint(i)?
            || dep.out_point().tx_hash() != state_point.tx_hash()
        {
            return Err(ScriptError::VaultOutPointMismatch);
        }
        verify_multi_asset_vault_at(evidence, i, i, Source::CellDep)?;
    }
    for dep in deps.into_iter().skip(evidence.manifest().count()) {
        for i in 0..evidence.manifest().count() {
            if dep.out_point().as_slice() == evidence.outpoint(i)? {
                return Err(ScriptError::VaultOutPointMismatch);
            }
        }
    }
    Ok(())
}
