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
        .filter(|data| {
            data.starts_with(FACTORY_MATERIALISATION_MAGIC)
                || (data.starts_with(FACTORY_REDUCED_RELEASE_MAGIC)
                    && data.len() >= 12
                    && crate::read_u16(data, 10) == FactoryTransitionOperation::ReducedChild as u16)
        })
        .map(|data| data.to_vec()))
}
/// Explicit current reduced release; there is no old-frame fallback.
pub fn reduced_release_evidence() -> Result<Option<Vec<u8>>> {
    let witness = load_witness_args(0, Source::Input).map_err(encoding)?;
    Ok(witness
        .output_type()
        .to_opt()
        .map(|data| data.raw_data())
        .filter(|data| data.starts_with(FACTORY_REDUCED_RELEASE_MAGIC))
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
fn validate_transaction_bounds(
    transaction: &ckb_std::ckb_types::packed::Transaction,
) -> Result<()> {
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
    Ok(())
}
pub fn validate_type() -> Result<()> {
    let transaction = load_transaction().map_err(encoding)?;
    validate_transaction_bounds(&transaction)?;
    let script = load_script().map_err(encoding)?;
    let args = script.args().raw_data();
    let factory = parse_factory_multi_asset_type_args(&args)?;
    let type_hash = load_script_hash().map_err(encoding)?;
    let old = group_data(Source::GroupInput)?;
    let new = group_data(Source::GroupOutput)?;
    let witness = load_witness_args(0, Source::Input).map_err(encoding)?;
    if let Some(raw) = reduced_release_evidence()? {
        if old.is_none() || new.is_none() || witness.input_type().to_opt().is_some() {
            return bad();
        }
        return verify_reduced_release(&raw, &type_hash, &transaction);
    }
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
                new.verify_update_signatures(
                    &load_tx_hash().map_err(encoding)?,
                    proof.signatures()?,
                )?;
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
    verify_materialisation_cells(intent, &old, type_hash, tx)
}

fn verify_materialisation_cells(
    intent: &FactoryMaterialisationIntent,
    old: &FactoryMultiAssetStateHeader,
    type_hash: &[u8],
    tx: &ckb_std::ckb_types::packed::Transaction,
) -> Result<()> {
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
            if (ty == Some(child.state_type_hash()) || lock == child.state_lock_hash())
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

/// Fast reserve gate: the exact Factory Type on input zero must execute the
/// complete verifier. Both scripts consume the same global witness-zero frame;
/// a group witness or another source cell cannot supply delegated authority.
/// Bounds and the actual raw transaction hash are checked here as well, without
/// repeating the Type's signatures, rights proofs or physical conservation.
pub fn validate_vault_gate(raw: &[u8], factory: &[u8], type_hash: &[u8]) -> Result<()> {
    let transaction = load_transaction().map_err(encoding)?;
    validate_transaction_bounds(&transaction)?;
    let witness = load_witness_args(0, Source::Input).map_err(encoding)?;
    if witness.input_type().to_opt().is_some()
        || witness
            .output_type()
            .to_opt()
            .as_ref()
            .map(|frame| frame.raw_data().as_ref() == raw)
            != Some(true)
    {
        return bad();
    }
    let transaction_hash = load_tx_hash().map_err(encoding)?;
    if raw.starts_with(FACTORY_REDUCED_RELEASE_MAGIC) {
        if raw.len() >= 12
            && crate::read_u16(raw, 10) == FactoryTransitionOperation::ReducedChild as u16
        {
            let view = factory_reduced_child_view(raw)?;
            let source = view.source_context()?;
            if transaction_hash.as_slice() != &raw[72..104]
                || transaction_hash != view.transaction_hash()
                || source.factory_id() != factory
                || load_script_hash().map_err(encoding)? != source.source().entry(0)?.lock_hash
            {
                return bad();
            }
            authenticate_source(&source, type_hash)?;
            return Ok(());
        }
        let proof = FactoryReducedReleaseWitness::parse(raw)?;
        if transaction_hash.as_slice() != proof.transaction_hash()
            || proof.before().factory_id() != factory
            || load_script_hash().map_err(encoding)? != proof.source().entry(0)?.lock_hash
        {
            return bad();
        }
        authenticate_reduced_source(&proof, type_hash)?;
        return Ok(());
    }
    let view = FactoryMaterialisationView::parse(raw)?;
    let source = view.source_context()?;
    if transaction_hash != view.transaction_hash()
        || source.factory_id() != factory
        || load_script_hash().map_err(encoding)? != source.source().entry(0)?.lock_hash
    {
        return bad();
    }
    authenticate_source(&source, type_hash)?;
    Ok(())
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
    let view = if raw.starts_with(FACTORY_REDUCED_RELEASE_MAGIC) {
        factory_reduced_child_view(raw)?
    } else {
        FactoryMaterialisationView::parse(raw)?
    };
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
        || child.state_type_hash().as_slice() != state_type_hash
    {
        return bad();
    }
    Ok(child)
}

fn authenticate_reduced_source(
    proof: &FactoryReducedReleaseWitness,
    type_hash: &[u8],
) -> Result<()> {
    if actual_state_index(Source::Input, type_hash)? != 0
        || load_input_out_point(0, Source::Input)
            .map_err(encoding)?
            .as_slice()
            != proof.old_state_outpoint()
        || load_input(0, Source::Input)
            .map_err(encoding)?
            .since()
            .unpack()
            != 0u64
        || load_cell_data(0, Source::Input)
            .map_err(encoding)?
            .as_slice()
            != proof.before().as_bytes()
        || load_cell_capacity(0, Source::Input).map_err(encoding)? != proof.carrier_capacity()
    {
        return bad();
    }
    let ty = load_cell_type(0, Source::Input)
        .map_err(encoding)?
        .ok_or(ScriptError::StateCellMissing)?;
    if parse_factory_multi_asset_type_args(&ty.args().raw_data())? != proof.before().factory_id()
        || blake2b256(&[ty.as_slice()]).as_slice() != type_hash
        || proof.factory_lock_script()[85..117] != *type_hash
    {
        return bad();
    }
    check_state_lock(0, Source::Input, type_hash)
}

fn verify_reduced_release(
    raw: &[u8],
    type_hash: &[u8],
    tx: &ckb_std::ckb_types::packed::Transaction,
) -> Result<()> {
    let proof = FactoryReducedReleaseWitness::parse(raw)?;
    authenticate_reduced_source(&proof, type_hash)?;
    if load_tx_hash().map_err(encoding)?.as_slice() != proof.transaction_hash()
        || actual_state_index(Source::Output, type_hash)? != 0
        || load_cell_data(0, Source::Output)
            .map_err(encoding)?
            .as_slice()
            != proof.after().as_bytes()
        || load_cell_capacity(0, Source::Output).map_err(encoding)? != proof.carrier_capacity()
        || load_cell_lock_hash(0, Source::Input).map_err(encoding)?
            != load_cell_lock_hash(0, Source::Output).map_err(encoding)?
    {
        return bad();
    }
    check_state_lock(0, Source::Output, type_hash)?;
    proof.verify()?;
    if let Some(intent) = proof.child_intent() {
        return verify_materialisation_cells(intent, proof.before(), type_hash, tx);
    }
    if !proof.operation().moves_custody() {
        no_vault_inputs(proof.source())?;
        return verify_factory_external_contributions(&proof, tx, 1, 1);
    }
    let inputs = tx.raw().inputs().len();
    let outputs = tx.raw().outputs().len();
    let input_end = 1 + proof.source().count();
    let protected_end = 1 + proof.retained().count() + proof.payout_count();
    if inputs < input_end || outputs < protected_end {
        return bad();
    }
    let source_positions =
        verify_vault_manifest_set(proof.source(), Some(proof.source_points()), Source::Input)?;
    let retained_positions = verify_vault_manifest_set(proof.retained(), None, Source::Output)?;
    for (i, position) in source_positions
        .iter()
        .enumerate()
        .take(proof.source().count())
    {
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
    for (i, position) in retained_positions
        .iter()
        .enumerate()
        .take(proof.retained().count())
    {
        if *position != i + 1 {
            return bad();
        }
    }
    check_vault_args(
        proof.source(),
        &source_positions,
        Source::Input,
        proof.before().factory_id(),
        type_hash,
    )?;
    check_vault_args(
        proof.retained(),
        &retained_positions,
        Source::Output,
        proof.before().factory_id(),
        type_hash,
    )?;
    for i in 0..proof.payout_count() {
        let payout = proof.payout(i)?;
        let index = payout.output_index;
        let ty = load_cell_type(index, Source::Output).map_err(encoding)?;
        let data = load_cell_data(index, Source::Output).map_err(encoding)?;
        if load_cell_capacity(index, Source::Output).map_err(encoding)?
            != payout.allocation.capacity()?
            || load_cell_lock(index, Source::Output)
                .map_err(encoding)?
                .as_slice()
                != payout.lock_script
            || ty.as_ref().map(|script| script.as_slice()) != proof.type_script(payout.asset)?
            || (payout.asset.kind == 0 && !data.is_empty())
            || (payout.asset.kind == 1 && data.as_slice() != payout.allocation.amount.to_le_bytes())
        {
            return bad();
        }
    }
    verify_factory_external_contributions(&proof, tx, input_end, protected_end)
}

/// External wallets fund only the explicitly derived deposit and fees. Vault
/// value and the State carrier always conserve independently. Every Type has
/// a separate quantity equation; unrelated typed inputs/outputs are rejected.
fn verify_factory_external_contributions(
    proof: &FactoryReducedReleaseWitness,
    tx: &ckb_std::ckb_types::packed::Transaction,
    input_start: usize,
    protected_end: usize,
) -> Result<()> {
    let inputs = tx.raw().inputs().len();
    let outputs = tx.raw().outputs().len();
    let custody_lock = proof.source().entry(0)?.lock_hash;
    let state_lock = load_cell_lock_hash(0, Source::Input).map_err(encoding)?;
    let (assets, count) = proof.assets()?;
    let mut tokens_in = [0u128; 16];
    let mut tokens_out = [0u128; 16];
    let mut capacity_in = 0u64;
    let mut capacity_out = 0u64;
    for (source, start, end, amounts, capacity) in [
        (
            Source::Input,
            input_start,
            inputs,
            &mut tokens_in,
            &mut capacity_in,
        ),
        (
            Source::Output,
            protected_end,
            outputs,
            &mut tokens_out,
            &mut capacity_out,
        ),
    ] {
        for i in start..end {
            let lock = load_cell_lock_hash(i, source).map_err(encoding)?;
            if lock == custody_lock || lock == state_lock {
                return bad();
            }
            let data = load_cell_data(i, source).map_err(encoding)?;
            match load_cell_type_hash(i, source).map_err(encoding)? {
                None => {
                    if !data.is_empty() {
                        return bad();
                    }
                }
                Some(hash) => {
                    let j = assets[..count]
                        .iter()
                        .position(|asset| asset.kind == 1 && asset.type_hash == hash)
                        .ok_or(ScriptError::FactoryMultiAssetPartitionMismatch)?;
                    if data.len() != 16 {
                        return bad();
                    }
                    amounts[j] = amounts[j]
                        .checked_add(crate::read_u128(&data, 0))
                        .ok_or(ScriptError::MultiAssetConservationMismatch)?;
                }
            }
            *capacity = capacity
                .checked_add(load_cell_capacity(i, source).map_err(encoding)?)
                .ok_or(ScriptError::MultiAssetCapacityMismatch)?;
        }
    }
    let deposited_capacity = proof
        .deposited_value(crate::multi_asset::MultiAssetId::CKB)?
        .capacity()?;
    for (j, asset) in assets.iter().enumerate().take(count) {
        let deposit = proof.deposited_value(*asset)?;
        if asset.kind == 1
            && tokens_in[j]
                != tokens_out[j]
                    .checked_add(deposit.amount)
                    .ok_or(ScriptError::MultiAssetConservationMismatch)?
        {
            return Err(ScriptError::MultiAssetConservationMismatch);
        }
    }
    if capacity_in
        < capacity_out
            .checked_add(deposited_capacity)
            .ok_or(ScriptError::MultiAssetCapacityMismatch)?
    {
        return Err(ScriptError::SponsorFeeMismatch);
    }
    for i in 0..outputs {
        if load_cell_capacity(i, Source::Output).map_err(encoding)?
            < load_cell_occupied_capacity(i, Source::Output).map_err(encoding)?
        {
            return bad();
        }
        if i != 0 && load_cell_lock_hash(i, Source::Output).map_err(encoding)? == state_lock {
            return bad();
        }
    }
    Ok(())
}
