//! Reviewed exact-body cooperative-close proposals. Chain freshness and external
//! input ownership must additionally be checked by the signing service resolver.
use crate::{
    Bytes32, MultiAssetError, MultiAssetOutPoint, MultiAssetRecoveryPackage, MultiAssetResult,
    MultiAssetState,
};
use ckb_types::{
    bytes::Bytes,
    packed::{CellOutput, OutPoint, RawTransaction, Script},
    prelude::*,
};
use morph_script_common::{
    PHASE_SETTLING, ScriptError, multi_asset as wire, multi_asset_close as close,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MULTI_ASSET_CLOSE_MAX_TRANSACTION_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiAssetCloseProposal {
    pub source_outpoint: MultiAssetOutPoint,
    pub source_state: MultiAssetState,
    /// Packed canonical RawTransaction, never a signed witness transaction.
    pub transaction: Vec<u8>,
}

fn invalid() -> MultiAssetError {
    ScriptError::MultiAssetCloseMismatch.into()
}
fn point(value: &MultiAssetOutPoint) -> OutPoint {
    OutPoint::new(value.tx_hash.pack(), value.index)
}
fn parse_script(bytes: &[u8]) -> MultiAssetResult<Script> {
    Script::from_slice(bytes).map_err(|_| MultiAssetError::ScriptIdentity)
}

/// Sole host-side output builder used by ordinary finalisation and close review.
pub fn multi_asset_settlement_outputs(
    witness: &wire::MultiAssetWitness<'_>,
    header: &wire::MultiAssetStateHeader<'_>,
    carrier: u64,
) -> MultiAssetResult<Vec<(CellOutput, Bytes)>> {
    witness.validate_header(header)?;
    if !header.vaults_are_bound() || header.phase() != PHASE_SETTLING || header.state_number() == 0
    {
        return Err(invalid());
    }
    let script =
        |index| -> MultiAssetResult<Script> { parse_script(witness.scripts().script(index)?) };
    let mut outputs = Vec::new();
    let mut type_index = 6;
    for index in 0..witness.descriptor().count() {
        let payout = witness.descriptor().entry(index)?;
        if payout.asset.kind == 0
            && let Some(conditional) = witness.descriptor().conditional()?
        {
            let lock = parse_script(&conditional.batch_script(
                header.channel_id(),
                &header.funding_context_id()?,
                header.state_number(),
            )?)?;
            outputs.push((
                CellOutput::new_builder()
                    .capacity(witness.manifest().entry(index)?.allocation.capacity()?)
                    .lock(lock)
                    .build(),
                Bytes::new(),
            ));
            continue;
        }
        let ty = if payout.asset.kind == 1 {
            let value = Some(script(type_index)?);
            type_index += 1;
            value
        } else {
            None
        };
        for participant in 0..2 {
            let value = payout.allocations[participant];
            let capacity = value.capacity()?;
            if capacity == 0 {
                continue;
            }
            let output_type = if value.amount > 0 { ty.clone() } else { None };
            let data = if output_type.is_some() {
                Bytes::from(value.amount.to_le_bytes().to_vec())
            } else {
                Bytes::new()
            };
            outputs.push((
                CellOutput::new_builder()
                    .capacity(capacity)
                    .lock(script(participant)?)
                    .type_(output_type.pack())
                    .build(),
                data,
            ));
        }
    }
    outputs.push((
        CellOutput::new_builder()
            .capacity(carrier)
            .lock(script(2)?)
            .build(),
        Bytes::new(),
    ));
    Ok(outputs)
}

impl MultiAssetCloseProposal {
    pub fn raw_transaction(&self) -> MultiAssetResult<RawTransaction> {
        if self.transaction.len() > MULTI_ASSET_CLOSE_MAX_TRANSACTION_BYTES {
            return Err(invalid());
        }
        let raw = RawTransaction::from_slice(&self.transaction).map_err(|_| invalid())?;
        if u32::from(raw.version()) != 0
            || !(2..64).contains(&raw.inputs().len())
            || !(1..64).contains(&raw.outputs().len())
            || raw.outputs().len() != raw.outputs_data().len()
            || raw.cell_deps().len() > 64
            || raw.header_deps().len() > 64
        {
            return Err(invalid());
        }
        let mut inputs = BTreeSet::new();
        for input in raw.inputs() {
            if !inputs.insert(input.previous_output().as_slice().to_vec()) {
                return Err(invalid());
            }
        }
        for (output, data) in raw.outputs().into_iter().zip(raw.outputs_data()) {
            let ty = output.type_().to_opt();
            let occupied = wire::multi_asset_occupied_capacity(
                output.lock().as_slice(),
                ty.as_ref().map(Entity::as_slice),
                data.raw_data().len() as u64,
            )?;
            if u64::from(output.capacity()) < occupied {
                return Err(invalid());
            }
        }
        Ok(raw)
    }
    pub fn transaction_hash(&self) -> MultiAssetResult<Bytes32> {
        Ok(self.raw_transaction()?.calc_tx_hash().unpack())
    }
    pub fn validate(&self, current: &MultiAssetRecoveryPackage) -> MultiAssetResult<()> {
        current.validate()?;
        let target_raw = current.state.encode()?;
        let target = wire::MultiAssetStateHeader::parse(&target_raw)?;
        let source_raw = self.source_state.encode()?;
        let source = wire::MultiAssetStateHeader::parse(&source_raw)?;
        close::validate_multi_asset_close_source(&source, &target)?;
        let raw = self.raw_transaction()?;
        let count = current.outpoints.len();
        if self.source_outpoint.tx_hash == [0; 32] || raw.inputs().len() < count + 1 {
            return Err(invalid());
        }
        let first = raw.inputs().get(0).ok_or_else(invalid)?;
        if first.previous_output() != point(&self.source_outpoint) || u64::from(first.since()) != 0
        {
            return Err(invalid());
        }
        for (index, expected) in current.outpoints.iter().enumerate() {
            let input = raw.inputs().get(index + 1).ok_or_else(invalid)?;
            if input.previous_output() != point(expected) || u64::from(input.since()) != 0 {
                return Err(invalid());
            }
        }
        let inner = crate::encode_multi_asset_witness(
            &current.manifest,
            &current.settlement,
            &current.outpoints,
            &current.scripts,
        )?;
        let evidence = wire::MultiAssetWitness::parse(&inner)?;
        let expected =
            multi_asset_settlement_outputs(&evidence, &target, current.state_carrier_capacity)?;
        if raw.outputs().len() < expected.len() {
            return Err(invalid());
        }
        for (index, (output, data)) in expected.iter().enumerate() {
            if raw.outputs().get(index).as_ref() != Some(output)
                || raw
                    .outputs_data()
                    .get(index)
                    .ok_or_else(invalid)?
                    .raw_data()
                    != *data
            {
                return Err(invalid());
            }
        }
        // Preserve every custody output. Independent fee change may share a
        // payout address, but may not create another Vault, State or Batch lock.
        let vault_hash = current.manifest.vaults[0].lock_hash;
        let state_lock_hash = crate::blake2b256(&current.scripts.state_lock);
        let batch_hash = if evidence.descriptor().conditional()?.is_some() {
            Some(
                expected
                    .first()
                    .ok_or_else(invalid)?
                    .0
                    .lock()
                    .calc_script_hash(),
            )
        } else {
            None
        };
        for index in expected.len()..raw.outputs().len() {
            let output = raw.outputs().get(index).ok_or_else(invalid)?;
            let lock = output.lock().calc_script_hash();
            if output.type_().to_opt().is_some()
                || !raw
                    .outputs_data()
                    .get(index)
                    .ok_or_else(invalid)?
                    .raw_data()
                    .is_empty()
                || lock.as_slice() == vault_hash
                || lock.as_slice() == state_lock_hash
                || batch_hash.as_ref() == Some(&lock)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub fn signing_digest(&self, current: &MultiAssetRecoveryPackage) -> MultiAssetResult<Bytes32> {
        self.validate(current)?;
        let header = current.state.encode()?;
        Ok(close::multi_asset_close_digest(
            &wire::MultiAssetStateHeader::parse(&header)?,
            &self.transaction_hash()?,
        )?)
    }
}
