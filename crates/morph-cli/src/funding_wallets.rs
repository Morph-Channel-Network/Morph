//! One exact per-wallet funding and owner-change implementation for current custody.
use crate::canonical_fields::{decimal_u64, decimal_u128, hash, public};
use crate::multi_asset_funding::funding_wallet_lock;
use anyhow::{Context, Result, anyhow, ensure};
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, TransactionBuilder},
    packed,
    prelude::*,
};
use morph_core::{Bytes32, MultiAssetTypeScript};
use morph_script_common::multi_asset as wire;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FundingWallet {
    pub pubkey: String,
    pub inputs: Vec<FundingInput>,
    /// Channel custody plus State carrier, excluding this wallet's fee share.
    pub ckb_contribution: String,
    pub fee_contribution: String,
    pub tokens: Vec<TokenContribution>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FundingInput {
    pub tx_hash: String,
    pub index: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenContribution {
    pub type_hash: String,
    pub amount: String,
}
#[derive(Debug, Clone)]
pub struct FundingCell {
    pub point: packed::OutPoint,
    pub output: packed::CellOutput,
    pub data: Bytes,
}

impl FundingInput {
    pub fn point(&self) -> Result<packed::OutPoint> {
        let hash = hash(&self.tx_hash)?;
        ensure!(hash != [0; 32], "zero funding input hash");
        Ok(packed::OutPoint::new_builder()
            .tx_hash(hash.pack())
            .index(self.index)
            .build())
    }
}
pub(crate) fn funding_points(funders: &[FundingWallet]) -> Result<Vec<packed::OutPoint>> {
    ensure!(
        (1..=16).contains(&funders.len()),
        "root requires 1..=16 explicit funders"
    );
    ensure!(
        funders
            .windows(2)
            .all(|pair| pair[0].pubkey < pair[1].pubkey),
        "funders must be distinct and sorted by public key"
    );
    let mut points = Vec::new();
    let mut seen = BTreeSet::new();
    for funder in funders {
        public(&funder.pubkey)?;
        ensure!(
            !funder.inputs.is_empty() && funder.inputs.len() <= 64,
            "funder requires bounded explicit inputs"
        );
        ensure!(
            funder
                .inputs
                .windows(2)
                .all(|pair| (&pair[0].tx_hash, pair[0].index) < (&pair[1].tx_hash, pair[1].index)),
            "funder inputs must be ordered"
        );
        decimal_u64(&funder.ckb_contribution)?;
        decimal_u64(&funder.fee_contribution)?;
        ensure!(
            funder.tokens.len() <= wire::MULTI_ASSET_MAX_VAULTS
                && funder
                    .tokens
                    .windows(2)
                    .all(|pair| pair[0].type_hash < pair[1].type_hash),
            "token contributions must be bounded and ordered"
        );
        for token in &funder.tokens {
            hash(&token.type_hash)?;
            ensure!(decimal_u128(&token.amount)? > 0, "zero token contribution");
        }
        for input in &funder.inputs {
            let point = input.point()?;
            ensure!(
                seen.insert(point.as_slice().to_vec()),
                "duplicate funding input"
            );
            points.push(point);
        }
    }
    ensure!(points.len() <= 64, "too many root funding inputs");
    Ok(points)
}

pub(crate) struct FundingCustody {
    pub state: (packed::CellOutput, Bytes),
    pub vaults: Vec<(packed::CellOutput, Bytes)>,
    pub type_scripts: Vec<MultiAssetTypeScript>,
}

pub(crate) fn build_wallet_funding(
    funders: &[FundingWallet],
    cells: &[FundingCell],
    custody: FundingCustody,
    cell_deps: Vec<packed::CellDep>,
    witness: packed::WitnessArgs,
    max_fee: u64,
) -> Result<(packed::Transaction, u64)> {
    ensure!(
        (1..=wire::MULTI_ASSET_MAX_VAULTS).contains(&custody.vaults.len()),
        "invalid custody Vault count"
    );
    let outputs = std::iter::once(custody.state)
        .chain(custody.vaults)
        .collect();
    build_wallet_transaction(
        funders,
        cells,
        WalletTransaction {
            prefix: vec![],
            outputs,
            state_indices: vec![0],
            type_scripts: custody.type_scripts,
            cell_deps,
            witness,
        },
        max_fee,
    )
}

/// One wallet accounting engine for root creation and current exact Factory
/// spends. Prefix inputs are authenticated protocol custody, never wallet
/// change; their value must remain wholly in declared outputs. Fees come only
/// from each wallet's explicit fee share.
pub(crate) struct WalletTransaction {
    pub prefix: Vec<FundingCell>,
    pub outputs: Vec<(packed::CellOutput, Bytes)>,
    pub state_indices: Vec<usize>,
    pub type_scripts: Vec<MultiAssetTypeScript>,
    pub cell_deps: Vec<packed::CellDep>,
    pub witness: packed::WitnessArgs,
}
pub(crate) fn build_wallet_transaction(
    funders: &[FundingWallet],
    cells: &[FundingCell],
    plan: WalletTransaction,
    max_fee: u64,
) -> Result<(packed::Transaction, u64)> {
    let WalletTransaction {
        prefix,
        outputs: fixed_outputs,
        state_indices,
        type_scripts,
        cell_deps,
        witness,
    } = plan;
    let points = funding_points(funders)?;
    ensure!(
        points.len() == cells.len()
            && points
                .iter()
                .zip(cells)
                .all(|(point, cell)| point == &cell.point),
        "resolved funding inputs differ from exact terms"
    );
    let mut all_points = BTreeSet::new();
    ensure!(
        prefix.len() + points.len() <= 64
            && prefix
                .iter()
                .map(|cell| &cell.point)
                .chain(points.iter())
                .all(|point| all_points.insert(point.as_slice().to_vec())),
        "duplicate or excessive protocol/wallet inputs"
    );
    let registered = type_scripts
        .iter()
        .map(|entry| (entry.type_hash, entry.script.as_slice()))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        registered.len() == type_scripts.len()
            && registered
                .iter()
                .all(|(hash, script)| morph_core::blake2b256(script) == *hash),
        "duplicate or mismatched registered scripts"
    );
    let mut expected_tokens = BTreeMap::<Bytes32, u128>::new();
    for (index, (output, data)) in fixed_outputs.iter().enumerate() {
        if let Some(ty) = output.type_().to_opt() {
            if state_indices.contains(&index) {
                let state_type_hash: Bytes32 = ty.calc_script_hash().unpack();
                ensure!(
                    !registered.contains_key(&state_type_hash),
                    "protocol State Type overlaps a token Type"
                );
                continue;
            }
            let type_hash: Bytes32 = ty.calc_script_hash().unpack();
            ensure!(
                registered
                    .get(&type_hash)
                    .is_some_and(|script| *script == ty.as_slice()),
                "unregistered custody Type Script"
            );
            let amount = u128::from_le_bytes(
                data.as_ref()
                    .try_into()
                    .map_err(|_| anyhow!("custody token data must be 16 bytes"))?,
            );
            let total = expected_tokens.entry(type_hash).or_default();
            *total = total
                .checked_add(amount)
                .context("custody token overflow")?;
        } else {
            ensure!(data.is_empty(), "plain custody carries unexpected data");
        }
    }
    let (mut outputs, mut data): (Vec<_>, Vec<_>) = fixed_outputs.into_iter().unzip();
    let output_capacity =
        outputs
            .iter()
            .zip(&data)
            .try_fold(0u64, |sum, (output, value)| -> Result<_> {
                ensure!(
                    u64::from(output.capacity())
                        >= output
                            .occupied_capacity(Capacity::bytes(value.len())?)?
                            .as_u64(),
                    "custody output below occupied capacity"
                );
                sum.checked_add(u64::from(output.capacity()))
                    .context("custody capacity overflow")
            })?;
    let mut prefix_capacity = 0u64;
    ensure!(
        state_indices.iter().all(|index| *index < outputs.len()),
        "protocol State output index out of bounds"
    );
    for (index, cell) in prefix.iter().enumerate() {
        prefix_capacity = prefix_capacity
            .checked_add(u64::from(cell.output.capacity()))
            .context("protocol input capacity overflow")?;
        if index == 0 {
            continue;
        } // exact State carrier; higher layer validates its Type/header
        if let Some(ty) = cell.output.type_().to_opt() {
            let type_hash: Bytes32 = ty.calc_script_hash().unpack();
            ensure!(
                registered
                    .get(&type_hash)
                    .is_some_and(|script| *script == ty.as_slice()),
                "unregistered protocol input Type"
            );
            let amount = u128::from_le_bytes(
                cell.data
                    .as_ref()
                    .try_into()
                    .map_err(|_| anyhow!("protocol token data must be16bytes"))?,
            );
            let expected = expected_tokens
                .get_mut(&type_hash)
                .ok_or_else(|| anyhow!("protocol token value missing from outputs"))?;
            *expected = expected
                .checked_sub(amount)
                .context("protocol tokens cannot fund fees or disappear")?;
        } else {
            ensure!(cell.data.is_empty(), "plain protocol input carries data");
        }
    }
    expected_tokens.retain(|_, amount| *amount != 0);
    let required_capacity = output_capacity
        .checked_sub(prefix_capacity)
        .context("protocol capacity cannot fund wallet fees or disappear")?;
    let mut contributed_capacity = 0u64;
    let mut fee = 0u64;
    let mut contributed_tokens = BTreeMap::<Bytes32, u128>::new();
    let mut offset = 0;
    for funder in funders {
        let lock = funding_wallet_lock(&public(&funder.pubkey)?)?;
        let group = &cells[offset..offset + funder.inputs.len()];
        offset += group.len();
        let mut remaining = BTreeMap::<Bytes32, u128>::new();
        let mut capacity = 0u64;
        for cell in group {
            ensure!(
                cell.output.lock() == lock,
                "funding input is not owned by its declared funder"
            );
            capacity = capacity
                .checked_add(u64::from(cell.output.capacity()))
                .ok_or_else(|| anyhow!("input capacity overflow"))?;
            ensure!(
                u64::from(cell.output.capacity())
                    >= cell
                        .output
                        .occupied_capacity(Capacity::bytes(cell.data.len())?)?
                        .as_u64(),
                "funding input below occupied capacity"
            );
            if let Some(ty) = cell.output.type_().to_opt() {
                let hash: Bytes32 = ty.calc_script_hash().unpack();
                ensure!(
                    registered.contains_key(&hash),
                    "funding input has an unregistered asset"
                );
                let amount = u128::from_le_bytes(
                    cell.data
                        .as_ref()
                        .try_into()
                        .map_err(|_| anyhow!("funding token data must be 16 bytes"))?,
                );
                let sum = remaining.entry(hash).or_default();
                *sum = sum
                    .checked_add(amount)
                    .ok_or_else(|| anyhow!("input token overflow"))?;
            } else {
                ensure!(
                    cell.data.is_empty(),
                    "plain funding input has unexpected data"
                );
            }
        }
        for token in &funder.tokens {
            let hash = hash(&token.type_hash)?;
            let amount = decimal_u128(&token.amount)?;
            ensure!(
                registered.contains_key(&hash),
                "token contribution is unregistered"
            );
            let available = remaining
                .get_mut(&hash)
                .ok_or_else(|| anyhow!("funder lacks pledged token input"))?;
            *available = available
                .checked_sub(amount)
                .ok_or_else(|| anyhow!("funder lacks pledged token quantity"))?;
            let total = contributed_tokens.entry(hash).or_default();
            *total = total
                .checked_add(amount)
                .ok_or_else(|| anyhow!("token contribution overflow"))?;
        }
        let contribution = decimal_u64(&funder.ckb_contribution)?;
        let fee_share = decimal_u64(&funder.fee_contribution)?;
        contributed_capacity = contributed_capacity
            .checked_add(contribution)
            .ok_or_else(|| anyhow!("CKB contribution overflow"))?;
        fee = fee
            .checked_add(fee_share)
            .ok_or_else(|| anyhow!("fee contribution overflow"))?;
        let mut change = capacity
            .checked_sub(contribution)
            .and_then(|value| value.checked_sub(fee_share))
            .ok_or_else(|| anyhow!("funder lacks pledged CKB capacity"))?;
        let first_change = outputs.len();
        for (hash, amount) in remaining {
            if amount == 0 {
                continue;
            }
            let output = packed::CellOutput::new_builder()
                .lock(lock.clone())
                .type_(Some(packed::Script::from_slice(registered[&hash])?).pack())
                .build();
            let occupied = output.occupied_capacity(Capacity::bytes(16)?)?.as_u64();
            change = change
                .checked_sub(occupied)
                .ok_or_else(|| anyhow!("funder cannot fund occupied token change"))?;
            outputs.push(output.as_builder().capacity(occupied).build());
            data.push(Bytes::from(amount.to_le_bytes().to_vec()));
        }
        if change > 0 {
            let plain = packed::CellOutput::new_builder().lock(lock).build();
            if change >= plain.occupied_capacity(Capacity::bytes(0)?)?.as_u64() {
                outputs.push(plain.as_builder().capacity(change).build());
                data.push(Bytes::new());
            } else if outputs.len() > first_change {
                let capacity = u64::from(outputs[first_change].capacity())
                    .checked_add(change)
                    .ok_or_else(|| anyhow!("change capacity overflow"))?;
                outputs[first_change] = outputs[first_change]
                    .clone()
                    .as_builder()
                    .capacity(capacity)
                    .build();
            } else {
                return Err(anyhow!("funder plain change is below occupied capacity"));
            }
        }
    }
    ensure!(
        contributed_capacity == required_capacity,
        "CKB contributions differ from exact protocol funding delta: required {required_capacity}"
    );
    ensure!(
        contributed_tokens == expected_tokens,
        "per-Type contributions must equal exact root custody"
    );
    ensure!(
        fee > 0 && fee <= max_fee,
        "root fee is zero or exceeds max_fee"
    );
    let input_capacity = prefix.iter().chain(cells).try_fold(0u64, |sum, cell| {
        sum.checked_add(u64::from(cell.output.capacity()))
            .ok_or_else(|| anyhow!("total input capacity overflow"))
    })?;
    let output_capacity = outputs.iter().try_fold(fee, |sum, output| {
        sum.checked_add(u64::from(output.capacity()))
            .ok_or_else(|| anyhow!("total output capacity overflow"))
    })?;
    ensure!(
        input_capacity == output_capacity,
        "root capacity accounting mismatch"
    );
    let mut tx = TransactionBuilder::default().set_cell_deps(cell_deps);
    for point in prefix.iter().map(|cell| cell.point.clone()).chain(points) {
        tx = tx.input(
            packed::CellInput::new_builder()
                .previous_output(point)
                .build(),
        );
    }
    for (output, value) in outputs.into_iter().zip(data) {
        tx = tx.output(output).output_data(value.pack());
    }
    Ok((tx.witness(witness.as_bytes()).build().data(), fee))
}
