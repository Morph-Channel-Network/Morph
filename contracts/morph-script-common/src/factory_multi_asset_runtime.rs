//! Whole-set CKB execution for the multi-Vault Factory profile. Factory Type
//! owns authorisation; the reserve lock gates spending on that authentic Type.
use crate::factory_multi_asset::*;
use crate::multi_asset::MultiAssetVaultManifest;
use crate::multi_asset_runtime::verify_vault_manifest_set;
use crate::{Result, ScriptError, blake2b256};
use alloc::vec::Vec;
use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::prelude::*;
use ckb_std::error::SysError;
use ckb_std::high_level::{
    load_cell_capacity, load_cell_data, load_cell_lock, load_cell_lock_hash,
    load_cell_occupied_capacity, load_cell_type, load_cell_type_hash, load_input,
    load_input_out_point, load_script, load_script_hash, load_transaction, load_tx_hash,
    load_witness_args,
};
fn bad<T>() -> Result<T> {
    Err(ScriptError::FactoryMultiAssetPartitionMismatch)
}
fn encoding<T>(_: T) -> ScriptError {
    ScriptError::Encoding
}
fn group_data(source: Source) -> Result<Option<Vec<u8>>> {
    let value = match load_cell_data(0, source) {
        Ok(data) => Some(data),
        Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => None,
        Err(_) => return bad(),
    };
    match load_cell_data(1, source) {
        Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => Ok(value),
        _ => Err(ScriptError::WrongGroupShape),
    }
}
pub fn materialisation_evidence() -> Result<Option<Vec<u8>>> {
    let witness = load_witness_args(0, Source::Input).map_err(encoding)?;
    Ok(witness
        .output_type()
        .to_opt()
        .map(|data| data.raw_data())
        .filter(|data| data.starts_with(FACTORY_MATERIALISATION_MAGIC))
        .map(|data| data.to_vec()))
}
fn state_evidence() -> Result<Vec<u8>> {
    Ok(load_witness_args(0, Source::Input)
        .map_err(encoding)?
        .input_type()
        .to_opt()
        .ok_or(ScriptError::ParticipantWitnessMissing)?
        .raw_data()
        .to_vec())
}
fn check_state_lock(index: usize, source: Source, type_hash: &[u8]) -> Result<()> {
    let lock = load_cell_lock(index, source).map_err(encoding)?;
    if lock.args().raw_data().as_ref() != type_hash
        || load_cell_capacity(index, source).map_err(encoding)?
            < load_cell_occupied_capacity(index, source).map_err(encoding)?
    {
        return bad();
    }
    Ok(())
}
fn actual_state_index(source: Source, type_hash: &[u8]) -> Result<usize> {
    let mut result = None;
    for index in 0..=64 {
        match load_cell_type_hash(index, source) {
            Ok(hash) => {
                if index == 64 {
                    return bad();
                }
                if hash.as_ref().map(|hash| hash.as_slice()) == Some(type_hash)
                    && result.replace(index).is_some()
                {
                    return bad();
                }
            }
            Err(SysError::IndexOutOfBound) | Err(SysError::ItemMissing) => {
                return result.ok_or(ScriptError::StateCellMissing);
            }
            Err(_) => return bad(),
        }
    }
    bad()
}
fn check_vault_args(
    manifest: &MultiAssetVaultManifest,
    positions: &[usize; 8],
    source: Source,
    factory: &[u8],
    type_hash: &[u8],
) -> Result<()> {
    for position in positions.iter().take(manifest.count()) {
        let lock = load_cell_lock(*position, source).map_err(encoding)?;
        let args = lock.args().raw_data();
        if args.len() != 64 || &args[..32] != factory || &args[32..] != type_hash {
            return bad();
        }
    }
    Ok(())
}
fn no_vault_inputs(manifest: &MultiAssetVaultManifest) -> Result<()> {
    let tx = load_transaction().map_err(encoding)?;
    let lock = manifest.entry(0)?.lock_hash;
    for i in 0..tx.raw().inputs().len() {
        if load_cell_lock_hash(i, Source::Input).map_err(encoding)? == lock {
            return bad();
        }
    }
    Ok(())
}
pub fn validate_type() -> Result<()> {
    let transaction = load_transaction().map_err(encoding)?;
    if u32::from(transaction.raw().version()) != 0
        || transaction.raw().inputs().is_empty()
        || transaction.raw().inputs().len() > 64
        || transaction.raw().outputs().len() > 64
        || transaction.raw().cell_deps().len() > 64
        || transaction.raw().header_deps().len() > 64
        || transaction.witnesses().len() > transaction.raw().inputs().len()
    {
        return bad();
    }
    let script = load_script().map_err(encoding)?;
    let args = script.args().raw_data();
    let factory = parse_factory_multi_asset_type_args(&args)?;
    let type_hash = load_script_hash().map_err(encoding)?;
    let old = group_data(Source::GroupInput)?;
    let new = group_data(Source::GroupOutput)?;
    let witness = load_witness_args(0, Source::Input).map_err(encoding)?;
    if let Some(raw) = materialisation_evidence()? {
        if old.is_none() || witness.input_type().to_opt().is_some() {
            return bad();
        }
        return verify_materialisation(&raw, &type_hash, &transaction);
    }
    if witness.output_type().to_opt().is_some() {
        return bad();
    }
    let raw = state_evidence()?;
    let proof = FactoryMultiAssetStateWitness::parse(&raw)?;
    match (old.as_deref(), new.as_deref()) {
        (None, Some(data)) => {
            let header = FactoryMultiAssetStateHeader::parse(data)?;
            proof.validate_header(&header)?;
            if header.factory_id() != factory
                || header.update_number() != 0
                || header.vaults_are_bound()
                || proof.kind() != FACTORY_STATE_WITNESS_ROOT
            {
                return bad();
            }
            let index = actual_state_index(Source::Output, &type_hash)?;
            check_state_lock(index, Source::Output, &type_hash)?;
            let input = load_input(0, Source::Input).map_err(encoding)?;
            let index = (index as u64).to_le_bytes();
            if blake2b256(&[input.as_slice(), &index]).as_slice() != factory {
                return Err(ScriptError::FactoryIdMismatch);
            }
            header
                .verify_root_signatures(&load_tx_hash().map_err(encoding)?, proof.signatures()?)?;
            let found = verify_vault_manifest_set(proof.manifest(), None, Source::Output)?;
            check_vault_args(
                proof.manifest(),
                &found,
                Source::Output,
                factory,
                &type_hash,
            )?;
        }
        (Some(before), Some(after)) => {
            let old = FactoryMultiAssetStateHeader::parse(before)?;
            let new = FactoryMultiAssetStateHeader::parse(after)?;
            if old.factory_id() != factory || !old.same_identity(&new) {
                return bad();
            }
            proof.validate_header(&new)?;
            let input_index = actual_state_index(Source::Input, &type_hash)?;
            let output_index = actual_state_index(Source::Output, &type_hash)?;
            if input_index != 0
                || load_input(0, Source::Input)
                    .map_err(encoding)?
                    .since()
                    .unpack()
                    != 0u64
                || load_cell_capacity(input_index, Source::Input).map_err(encoding)?
                    != load_cell_capacity(output_index, Source::Output).map_err(encoding)?
                || load_cell_lock_hash(input_index, Source::Input).map_err(encoding)?
                    != load_cell_lock_hash(output_index, Source::Output).map_err(encoding)?
            {
                return bad();
            }
            check_state_lock(output_index, Source::Output, &type_hash)?;
            no_vault_inputs(proof.manifest())?;
            if !old.vaults_are_bound() {
                if !old.is_activation_to(&new) || proof.kind() != FACTORY_STATE_WITNESS_ACTIVATE {
                    return bad();
                }
                let tx = load_transaction().map_err(encoding)?;
                let deps = tx.raw().cell_deps();
                let state = load_input_out_point(input_index, Source::Input).map_err(encoding)?;
                for i in 0..proof.manifest().count() {
                    let dep = deps.get(i).ok_or(ScriptError::VaultOutPointMismatch)?;
                    if dep.dep_type().as_slice() != [0]
                        || dep.out_point().as_slice() != &proof.points()[i * 36..(i + 1) * 36]
                        || dep.out_point().tx_hash() != state.tx_hash()
                    {
                        return Err(ScriptError::VaultOutPointMismatch);
                    }
                }
                for dep in deps.into_iter().skip(proof.manifest().count()) {
                    for point in proof.points().chunks_exact(36) {
                        if dep.out_point().as_slice() == point {
                            return Err(ScriptError::VaultOutPointMismatch);
                        }
                    }
                }
                let positions = verify_vault_manifest_set(proof.manifest(), None, Source::CellDep)?;
                for (i, position) in positions.iter().enumerate().take(proof.manifest().count()) {
                    if *position != i {
                        return bad();
                    }
                }
                check_vault_args(
                    proof.manifest(),
                    &positions,
                    Source::CellDep,
                    factory,
                    &type_hash,
                )?;
            } else {
                if proof.kind() != FACTORY_STATE_WITNESS_UPDATE
                    || !old.same_custody(&new)
                    || new.update_number() <= old.update_number()
                {
                    return bad();
                }
                new.verify_signatures(proof.signatures()?)?;
            }
        }
        _ => return Err(ScriptError::WrongGroupShape),
    }
    Ok(())
}

fn authenticate_source(intent: &FactoryMaterialisationSource, type_hash: &[u8]) -> Result<Vec<u8>> {
    if actual_state_index(Source::Input, type_hash)? != 0
        || load_input_out_point(0, Source::Input)
            .map_err(encoding)?
            .as_slice()
            != intent.old_state_outpoint()
        || load_input(0, Source::Input)
            .map_err(encoding)?
            .since()
            .unpack()
            != 0u64
    {
        return bad();
    }
    let ty = load_cell_type(0, Source::Input)
        .map_err(encoding)?
        .ok_or(ScriptError::StateCellMissing)?;
    let args = ty.args().raw_data();
    if parse_factory_multi_asset_type_args(&args)? != intent.factory_id()
        || blake2b256(&[ty.as_slice()]).as_slice() != type_hash
    {
        return bad();
    }
    let data = load_cell_data(0, Source::Input).map_err(encoding)?;
    let old = FactoryMultiAssetStateHeader::parse(&data)?;
    if !old.vaults_are_bound()
        || old.chain_id() != intent.chain_id()
        || old.factory_id() != intent.factory_id()
        || old.participants_commitment() != intent.participants_commitment()
        || old.content_root() != intent.source().commitment()
        || old.outpoint_root() != intent.source_outpoint_root()?
        || old.vault_count() != intent.source().count()
        || load_cell_capacity(0, Source::Input).map_err(encoding)?
            != intent.factory_carrier_capacity()
    {
        return bad();
    }
    check_state_lock(0, Source::Input, type_hash)?;
    Ok(data)
}
fn verify_materialisation(
    raw: &[u8],
    type_hash: &[u8],
    tx: &ckb_std::ckb_types::packed::Transaction,
) -> Result<()> {
    let proof = FactoryMaterialisationWitness::parse(raw)?;
    let intent = proof.intent();
    if load_tx_hash().map_err(encoding)? != intent.transaction_hash()
        || intent.factory_lock_script()[85..] != *type_hash
    {
        return bad();
    }
    let old_data = authenticate_source(&intent.source_context(), type_hash)?;
    let old = FactoryMultiAssetStateHeader::parse(&old_data)?;
    proof.verify()?;
    let inputs = tx.raw().inputs().len();
    let outputs = tx.raw().outputs().len();
    if inputs > 64
        || outputs > 64
        || inputs < 1 + intent.source().count()
        || outputs == 0
        || tx.raw().cell_deps().len() > 64
        || tx.raw().header_deps().len() > 64
    {
        return bad();
    }
    let positions =
        verify_vault_manifest_set(intent.source(), Some(intent.source_points()), Source::Input)?;
    for (i, position) in positions.iter().enumerate().take(intent.source().count()) {
        if *position != i + 1
            || load_input(*position, Source::Input)
                .map_err(encoding)?
                .since()
                .unpack()
                != 0u64
        {
            return bad();
        }
    }
    let state_lock = load_cell_lock_hash(0, Source::Input).map_err(encoding)?;
    let mut protected = [false; 64];
    protected[0] = true;
    if let Some(retained) = intent.retained() {
        let data = load_cell_data(0, Source::Output).map_err(encoding)?;
        let new = FactoryMultiAssetStateHeader::parse(&data)?;
        if !old.same_identity(&new)
            || new.update_number()
                != old
                    .update_number()
                    .checked_add(1)
                    .ok_or(ScriptError::NonMonotonicStateNumber)?
            || new.vaults_are_bound()
            || new.content_root() != retained.commitment()
            || new.vault_count() != retained.count()
            || load_cell_type_hash(0, Source::Output)
                .map_err(encoding)?
                .as_ref()
                .map(|hash| hash.as_slice())
                != Some(type_hash)
            || load_cell_lock_hash(0, Source::Output).map_err(encoding)? != state_lock
            || load_cell_capacity(0, Source::Output).map_err(encoding)?
                != intent.factory_carrier_capacity()
        {
            return bad();
        }
        check_state_lock(0, Source::Output, type_hash)?;
        let positions = verify_vault_manifest_set(retained, None, Source::Output)?;
        for (i, position) in positions.iter().enumerate().take(retained.count()) {
            if *position != i + 1 {
                return bad();
            }
            protected[*position] = true;
        }
    } else {
        if load_cell_capacity(0, Source::Output).map_err(encoding)?
            != intent.factory_carrier_capacity()
            || load_cell_type_hash(0, Source::Output)
                .map_err(encoding)?
                .is_some()
            || !load_cell_data(0, Source::Output)
                .map_err(encoding)?
                .is_empty()
            || load_cell_lock(0, Source::Output)
                .map_err(encoding)?
                .as_slice()
                != intent.refund_script()
        {
            return bad();
        }
    }
    let mut external_inputs = 0u64;
    let mut external_outputs = 0u64;
    for i in 1 + intent.source().count()..inputs {
        if load_cell_type_hash(i, Source::Input)
            .map_err(encoding)?
            .is_some()
            || !load_cell_data(i, Source::Input)
                .map_err(encoding)?
                .is_empty()
            || intent.is_custody_lock(&load_cell_lock_hash(i, Source::Input).map_err(encoding)?)?
            || load_cell_lock_hash(i, Source::Input).map_err(encoding)? == state_lock
        {
            return bad();
        }
        external_inputs = external_inputs
            .checked_add(load_cell_capacity(i, Source::Input).map_err(encoding)?)
            .ok_or(ScriptError::MultiAssetCapacityMismatch)?;
    }
    for i in 0..intent.child_count() {
        let child = intent.child(i)?;
        let scripts = child.evidence.scripts();
        let state = child.state_output_index;
        if state >= outputs
            || load_cell_data(state, Source::Output)
                .map_err(encoding)?
                .as_slice()
                != child.creation_header()?
            || load_cell_capacity(state, Source::Output).map_err(encoding)?
                != child.carrier_capacity
            || load_cell_lock(state, Source::Output)
                .map_err(encoding)?
                .as_slice()
                != scripts.script(5)?
            || load_cell_type(state, Source::Output)
                .map_err(encoding)?
                .as_ref()
                .map(|script| script.as_slice())
                != Some(scripts.script(4)?)
        {
            return bad();
        }
        protected[state] = true;
        for role in 0..3 {
            if blake2b256(&[scripts.script(role)?]) == state_lock {
                return bad();
            }
        }
        let found = verify_vault_manifest_set(child.evidence.manifest(), None, Source::Output)?;
        for (j, position) in found
            .iter()
            .enumerate()
            .take(child.evidence.manifest().count())
        {
            let point = child.evidence.outpoint(j)?;
            if *position != crate::read_u32(point, 32) as usize {
                return bad();
            }
            protected[*position] = true;
        }
    }
    for (i, is_protected) in protected.iter().enumerate().take(outputs) {
        if load_cell_capacity(i, Source::Output).map_err(encoding)?
            < load_cell_occupied_capacity(i, Source::Output).map_err(encoding)?
        {
            return bad();
        }
        let lock = load_cell_lock_hash(i, Source::Output).map_err(encoding)?;
        let ty = load_cell_type_hash(i, Source::Output).map_err(encoding)?;
        let expected_parent = intent.retained().is_some() && i == 0;
        if (ty.as_ref().map(|hash| hash.as_slice()) == Some(type_hash) || lock == state_lock)
            && !expected_parent
        {
            return bad();
        }
        for child_index in 0..intent.child_count() {
            let child = intent.child(child_index)?;
            let scripts = child.evidence.scripts();
            if (ty == Some(blake2b256(&[scripts.script(4)?]))
                || lock == blake2b256(&[scripts.script(5)?]))
                && i != child.state_output_index
            {
                return bad();
            }
        }
        if !is_protected {
            if ty.is_some()
                || !load_cell_data(i, Source::Output)
                    .map_err(encoding)?
                    .is_empty()
                || intent.is_custody_lock(&lock)?
            {
                return bad();
            }
            external_outputs = external_outputs
                .checked_add(load_cell_capacity(i, Source::Output).map_err(encoding)?)
                .ok_or(ScriptError::MultiAssetCapacityMismatch)?;
        }
    }
    if external_inputs
        < external_outputs
            .checked_add(intent.external_carrier_contribution())
            .ok_or(ScriptError::MultiAssetCapacityMismatch)?
    {
        return Err(ScriptError::SponsorFeeMismatch);
    }
    Ok(())
}

/// Fast reserve gate: the authentic Factory Type runs the complete verifier.
/// Requiring the materialisation frame and exact source roots prevents an
/// ordinary metadata update or activation from authorising reserve spending.
pub fn validate_vault_gate(raw: &[u8], factory: &[u8], type_hash: &[u8]) -> Result<()> {
    let view = FactoryMaterialisationView::parse(raw)?;
    let source = view.source_context()?;
    if source.factory_id() != factory
        || load_script_hash().map_err(encoding)? != source.source().entry(0)?.lock_hash
    {
        return bad();
    }
    authenticate_source(&source, type_hash)?;
    Ok(())
}
pub fn has_multi_asset_factory_source(type_hash: &[u8]) -> Result<bool> {
    Ok(load_cell_type_hash(0, Source::Input)
        .map_err(encoding)?
        .as_ref()
        .map(|hash| hash.as_slice())
        == Some(type_hash)
        && load_cell_data(0, Source::Input).map_err(encoding)?.len()
            == FACTORY_MULTI_ASSET_STATE_HEADER_LEN)
}

pub fn verify_child_creation<'a>(
    raw: &'a [u8],
    header: &crate::multi_asset::MultiAssetStateHeader,
    state_type_hash: &[u8],
    factory_origin: &[u8],
) -> Result<FactoryMaterialisationChild<'a>> {
    if load_cell_type_hash(0, Source::Input)
        .map_err(encoding)?
        .as_ref()
        .map(|hash| hash.as_slice())
        != Some(factory_origin)
    {
        return bad();
    }
    let parent = load_cell_data(0, Source::Input).map_err(encoding)?;
    let parent = FactoryMultiAssetStateHeader::parse(&parent)?;
    let parent_type = load_cell_type(0, Source::Input)
        .map_err(encoding)?
        .ok_or(ScriptError::StateCellMissing)?;
    let parent_args = parent_type.args().raw_data();
    if parse_factory_multi_asset_type_args(&parent_args)? != parent.factory_id()
        || !parent.vaults_are_bound()
    {
        return bad();
    }
    let view = FactoryMaterialisationView::parse(raw)?;
    let source = view.source_context()?;
    if source.old_state_outpoint()
        != load_input_out_point(0, Source::Input)
            .map_err(encoding)?
            .as_slice()
        || source.factory_id() != parent.factory_id()
        || load_tx_hash().map_err(encoding)? != view.transaction_hash()
    {
        return bad();
    }
    let child = view.child_by_anchor(header.funding_anchor())?;
    if child.state_output_index >= 64 {
        return bad();
    }
    let input = load_input(0, Source::Input).map_err(encoding)?;
    if input.since().unpack() != 0u64
        || blake2b256(&[
            input.as_slice(),
            &(child.state_output_index as u64).to_le_bytes(),
        ])
        .as_slice()
            != header.funding_anchor()
    {
        return bad();
    }
    if header.as_bytes() != child.creation_header()?
        || child.evidence.scripts().script(4)?.len() != 125
        || child.evidence.scripts().script(4)?[85..117] != *factory_origin
        || blake2b256(&[child.evidence.scripts().script(4)?]).as_slice() != state_type_hash
    {
        return bad();
    }
    Ok(child)
}
